"""Optional smoke-test generator: synthetic events only, NOT the Kaggle dataset."""
from __future__ import annotations
import argparse
from pathlib import Path
import numpy as np
import pandas as pd

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--n",type=int,default=210000)
    args=p.parse_args()
    rng=np.random.default_rng(42)
    n=args.n
    names=["DescribeInstances","ListBuckets","GetCallerIdentity","GetObject","PutObject","GetUser","ListUsers","ListRoles","StartInstances","DescribeVpcs","AssumeRole","AttachUserPolicy","CreateAccessKey","StopLogging"]
    probs=[0.27,0.12,0.18,0.11,0.08,0.08,0.04,0.035,0.04,0.025,0.03,0.009,0.008,0.005]
    probs=np.array(probs,dtype=float); probs/=probs.sum()
    ids=rng.integers(1,65,size=n)
    t=pd.Timestamp("2026-10-01",tz="UTC") + pd.to_timedelta(rng.integers(0,21*24*3600,size=n),unit="s")
    chosen=rng.choice(names,size=n,p=probs)
    events=pd.DataFrame({"eventTime":t,"eventName":chosen,"eventSource":np.where(np.isin(chosen,["StopLogging"]),"cloudtrail.amazonaws.com",np.where(np.isin(chosen,["GetObject","PutObject","ListBuckets"]),"s3.amazonaws.com",np.where(np.isin(chosen,["GetCallerIdentity","AssumeRole"]),"sts.amazonaws.com","iam.amazonaws.com"))),"sourceIPAddress":[f"198.51.100.{x%150+1}" for x in ids],"awsRegion":rng.choice(["us-east-1","us-west-2","eu-west-1"],n,p=[0.7,0.2,0.1]),"principal":[f"arn:aws:iam::123456789012:user/demo-{x}" for x in ids],"identityType":"IAMUser","mfaAuthenticated":rng.choice(["true","false","unknown"],n,p=[.5,.2,.3]),"errorCode":np.where(rng.random(n)<.025,"AccessDenied",""),"userAgent":"aws-cli/2.0","eventID":[f"synthetic-{x:08d}" for x in range(n)],"attack_name":""})
    Path("data/raw").mkdir(parents=True,exist_ok=True)
    events.to_csv("data/raw/synthetic_demo.csv",index=False)
    print(f"Created {n:,} SYNTHETIC records in data/raw/synthetic_demo.csv. Not real CloudTrail events!")

if __name__=="__main__":
    main()
