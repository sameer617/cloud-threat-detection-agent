"""Train window-level unsupervised anomaly detectors on CloudTrail event features."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import torch
from torch import nn

IAM_MUTATION = {"AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy","AddUserToGroup","CreatePolicyVersion","SetDefaultPolicyVersion","UpdateAssumeRolePolicy"}
CREDENTIAL = {"CreateAccessKey","UpdateAccessKey","CreateLoginProfile","UpdateLoginProfile","GetFederationToken","AssumeRole","GetSecretValue"}
DEFENSE = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"}
RECON = {"ListUsers","ListRoles","ListPolicies","GetAccountAuthorizationDetails","DescribeInstances","ListBuckets","GetCallerIdentity","ListAttachedUserPolicies"}
PRIVILEGE = IAM_MUTATION | {"CreateRole","CreateUser","GetFederationToken"}
NUMERIC = ["total_calls", "unique_api", "unique_services", "unique_ips", "unique_regions", "iam_mutations", "privilege_ops", "credential_ops", "discovery_ops", "defense_ops", "error_count", "root_ops", "mfa_no_ops", "off_hours_ops", "error_rate", "iam_rate", "discovery_rate", "credential_rate", "defense_rate"]

def feature_table(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["eventTime"] = pd.to_datetime(df.eventTime, utc=True)
    df["window_start"] = df.eventTime.dt.floor("6h")
    nm = df.eventName.astype(str)
    flags = {
      "iam_mutations": nm.isin(IAM_MUTATION),
      "privilege_ops": nm.isin(PRIVILEGE),
      "credential_ops": nm.isin(CREDENTIAL),
      "discovery_ops": nm.isin(RECON) | nm.str.startswith(("List", "Describe")),
      "defense_ops": nm.isin(DEFENSE),
      "error_count": df.errorCode.fillna("").astype(str).str.contains("AccessDenied|Unauthorized|InvalidClientTokenId", case=False, regex=True),
      "root_ops": df.identityType.eq("Root"),
      "mfa_no_ops": df.mfaAuthenticated.astype(str).str.lower().eq("false"),
      "off_hours_ops": (df.eventTime.dt.hour < 6) | (df.eventTime.dt.hour >= 22),
    }
    for key,val in flags.items():
        df[key] = val.astype("int8")
    group = df.groupby(["principal","window_start"], dropna=False, sort=False)
    agg = group.agg(total_calls=("eventName","size"), unique_api=("eventName","nunique"),unique_services=("eventSource","nunique"), unique_ips=("sourceIPAddress","nunique"),unique_regions=("awsRegion","nunique"), **{k:(k,"sum") for k in flags}).reset_index()
    for dst, count in [("error_rate","error_count"),("iam_rate","iam_mutations"),("discovery_rate","discovery_ops"),("credential_rate","credential_ops"),("defense_rate","defense_ops")]:
        agg[dst] = agg[count] / agg.total_calls.clip(lower=1)
    # Relevant raw evidence is not part of the fitted model or ground truth.
    interesting = df.loc[df.eventName.isin(PRIVILEGE | CREDENTIAL | RECON | DEFENSE)]
    evidence = interesting.groupby(["principal","window_start"]).eventName.apply(lambda s: ", ".join(s.value_counts().head(8).index)).rename("security_events")
    ips = group.sourceIPAddress.first().rename("example_source_ip")
    agg = agg.join(evidence, on=["principal","window_start"]).join(ips, on=["principal","window_start"])
    agg["security_events"] = agg.security_events.fillna("")
    return agg.sort_values("window_start").reset_index(drop=True)

class Autoencoder(nn.Module):
    def __init__(self, dim: int):
        super().__init__()
        hidden = max(12, dim // 2)
        bottleneck = max(4, dim // 4)
        self.net = nn.Sequential(nn.Linear(dim,hidden),nn.ReLU(),nn.Linear(hidden,bottleneck),nn.ReLU(),nn.Linear(bottleneck,hidden),nn.ReLU(),nn.Linear(hidden,dim))
    def forward(self,x):
        return self.net(x)

def train_and_score(table: pd.DataFrame, epochs=15, seed=42):
    torch.manual_seed(seed)
    np.random.seed(seed)
    n = len(table)
    if n < 40:
        raise ValueError(f"Only {n} behavior windows found. Need at least 40. Provide more event data.")
    cut = max(30, int(n*0.70))
    scaler=StandardScaler()
    X = scaler.fit_transform(table.iloc[:cut][NUMERIC].astype(float)).astype("float32")
    X_all = scaler.transform(table[NUMERIC].astype(float)).astype("float32")
    forest = IsolationForest(n_estimators=200, max_samples="auto", contamination=0.02, random_state=seed, n_jobs=-1)
    forest.fit(X)
    forest_train = -forest.score_samples(X)
    forest_all = -forest.score_samples(X_all)
    model=Autoencoder(len(NUMERIC))
    optim=torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)
    tensor=torch.from_numpy(X)
    batches=torch.utils.data.DataLoader(torch.utils.data.TensorDataset(tensor),batch_size=256,shuffle=True)
    for epoch in range(epochs):
        model.train()
        losses=[]
        for (batch,) in batches:
            pred=model(batch)
            loss=((pred-batch)**2).mean()
            optim.zero_grad(); loss.backward(); optim.step()
            losses.append(loss.item())
        if epoch in {0, epochs-1}:
            print(f"Autoencoder epoch {epoch+1}/{epochs}, loss={np.mean(losses):.4f}")
    model.eval()
    with torch.no_grad():
        ae_train=((model(torch.from_numpy(X))-torch.from_numpy(X))**2).mean(dim=1).numpy()
        ae_all=((model(torch.from_numpy(X_all))-torch.from_numpy(X_all))**2).mean(dim=1).numpy()
    # Empirical training score percentiles: 1 is highest anomaly score.
    def rank_against(values, baseline):
        return np.searchsorted(np.sort(baseline),values,side="right")/len(baseline)
    scored=table.copy()
    scored["if_score"]=forest_all
    scored["ae_reconstruction_error"]=ae_all
    scored["if_percentile"]=rank_against(forest_all,forest_train)
    scored["ae_percentile"]=rank_against(ae_all,ae_train)
    scored["combined_score"]=(scored.if_percentile+scored.ae_percentile)/2
    scored["is_alert"]=(scored.if_percentile>=0.98) | (scored.ae_percentile>=0.98)
    scored["time_split"]=["training"]*cut+["holdout"]*(n-cut)
    return scored.sort_values("combined_score",ascending=False).reset_index(drop=True),scaler,forest,model

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--input", default="outputs/events.csv")
    ap.add_argument("--epochs",type=int,default=15)
    args=ap.parse_args()
    events=pd.read_csv(args.input, low_memory=False)
    table=feature_table(events)
    scored,scaler,forest,model=train_and_score(table,args.epochs)
    Path("outputs").mkdir(exist_ok=True)
    scored.to_csv("outputs/scored_windows.csv",index=False)
    scored.loc[scored.is_alert].to_csv("outputs/alerts.csv",index=False)
    joblib.dump({"scaler":scaler,"forest":forest,"features":NUMERIC},"outputs/iforest.joblib")
    torch.save({"state_dict":model.state_dict(),"dim":len(NUMERIC)},"outputs/autoencoder.pt")
    metrics={"raw_events":int(len(events)),"behavior_windows":int(len(table)),"alert_windows":int(scored.is_alert.sum()),"train_windows":int((scored.time_split=="training").sum()),"holdout_windows":int((scored.time_split=="holdout").sum()),"note":"Unsupervised anomaly flags, not confirmed malicious incidents. No labels available in the main data."}
    Path("outputs/model_stats.json").write_text(json.dumps(metrics,indent=2))
    print(json.dumps(metrics,indent=2))

if __name__ == "__main__":
    main()
