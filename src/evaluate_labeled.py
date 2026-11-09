"""Evaluate frozen unsupervised models on the separate ArielCyber labeled CloudTrail corpus.

Test set is kept separate from training. Cross-dataset domain shift may impact metrics.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
import torch
from sklearn.metrics import precision_score,recall_score,f1_score,confusion_matrix
from .ingest import load_events
from .models import feature_table,Autoencoder,NUMERIC

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--folder",required=True,help="Unzipped ArielCyber TestOn folder (JSON records with attack_name)")
    args=p.parse_args()
    df=load_events(args.folder,100000)
    if df["attack_name"].eq("").all():
        raise ValueError("No attack_name labels found. Did you pass the ArielCyber labeled TestOn JSON data?")
    feats=feature_table(df)
    labels=df.assign(window_start=pd.to_datetime(df.eventTime,utc=True).dt.floor("6h"),is_attack=df.attack_name.ne(""))
    truth=labels.groupby(["principal","window_start"]).is_attack.max().rename("actual_attack_window")
    feats=feats.join(truth,on=["principal","window_start"])
    bundle=joblib.load("outputs/iforest.joblib")
    scaler,forest=bundle["scaler"],bundle["forest"]
    inp=scaler.transform(feats[NUMERIC].astype(float)).astype("float32")
    forest_scores=-forest.score_samples(inp)
    saved=torch.load("outputs/autoencoder.pt",map_location="cpu",weights_only=True)
    model=Autoencoder(saved["dim"])
    model.load_state_dict(saved["state_dict"]); model.eval()
    with torch.no_grad():
        aerrs=((model(torch.from_numpy(inp))-torch.from_numpy(inp))**2).mean(dim=1).numpy()
    ref=pd.read_csv("outputs/scored_windows.csv")
    ref=ref[ref.time_split.eq("training")]
    if_threshold=np.quantile(ref.if_score,.98)
    ae_threshold=np.quantile(ref.ae_reconstruction_error,.98)
    feats["predicted_alert"]=(forest_scores>=if_threshold)|(aerrs>=ae_threshold)
    target=feats.actual_attack_window.astype(int)
    pred=feats.predicted_alert.astype(int)
    metrics={"labeled_windows":int(len(feats)),"attack_windows":int(target.sum()),"precision":float(precision_score(target,pred,zero_division=0)),"recall":float(recall_score(target,pred,zero_division=0)),"f1":float(f1_score(target,pred,zero_division=0)),"confusion_matrix_TN_FP_FN_TP":confusion_matrix(target,pred,labels=[0,1]).ravel().tolist(),"caveat":"Window-level metrics on an independent differently distributed dataset; not event-level accuracy. Labels originate from controlled scenarios."}
    Path("outputs/labeled_eval.json").write_text(__import__("json").dumps(metrics,indent=2))
    feats.to_csv("outputs/labeled_predictions.csv",index=False)
    print(__import__("json").dumps(metrics,indent=2))

if __name__=="__main__":
    main()
