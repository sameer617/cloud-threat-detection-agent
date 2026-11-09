"""Read anonymized CloudTrail CSV/JSON/JSONL/.gz records into common event fields.

Only public/trusted local files should be passed to this script. No cloud credentials needed.
"""
from __future__ import annotations
import argparse
import ast
import gzip
import json
from pathlib import Path
from typing import Any, Iterable
import pandas as pd

COLUMNS = ["eventTime", "eventName", "eventSource", "sourceIPAddress", "awsRegion", "principal", "identityType", "mfaAuthenticated", "errorCode", "userAgent", "eventID", "attack_name"]

def nested(x: Any, *keys: str):
    for k in keys:
        if not isinstance(x, dict):
            return None
        x = x.get(k)
    return x

def parse_nested(value: Any) -> Any:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.lstrip().startswith("{"):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            try:
                return ast.literal_eval(value)
            except (SyntaxError, ValueError):
                return {}
    return {}

def get(rec: dict, *names: str):
    for n in names:
        if n in rec and rec[n] is not None and not (isinstance(rec[n], float) and pd.isna(rec[n])):
            return rec[n]
    return None

def normalize(rec: dict) -> dict:
    ident = parse_nested(get(rec, "userIdentity", "user_identity"))
    principal = get(rec, "principal", "userIdentity.arn", "userIdentity_arn", "userIdentityArn", "userIdentity.principalId", "userIdentity_userName")
    principal = principal or nested(ident, "arn") or nested(ident, "principalId") or nested(ident, "userName") or "unknown"
    ident_type = get(rec, "identityType", "userIdentity.type", "userIdentity_type") or nested(ident, "type") or "unknown"
    mfa = get(rec, "mfaAuthenticated", "userIdentity.sessionContext.attributes.mfaAuthenticated")
    if mfa is None:
        mfa = nested(ident, "sessionContext", "attributes", "mfaAuthenticated")
    return {
        "eventTime": get(rec, "eventTime", "event_time", "timestamp"),
        "eventName": get(rec, "eventName", "event_name", "eventname"),
        "eventSource": get(rec, "eventSource", "event_source", "eventsource") or "unknown",
        "sourceIPAddress": str(get(rec, "sourceIPAddress", "source_ip", "sourceIP") or "unknown"),
        "awsRegion": get(rec, "awsRegion", "region") or "unknown",
        "principal": str(principal),
        "identityType": str(ident_type),
        "mfaAuthenticated": str(mfa if mfa is not None else "unknown"),
        "errorCode": str(get(rec, "errorCode", "error_code") or ""),
        "userAgent": str(get(rec, "userAgent", "user_agent") or ""),
        "eventID": str(get(rec, "eventID", "eventId", "event_id") or ""),
        "attack_name": str(get(rec, "attack_name") or ""),
    }

def records_for_file(path: Path, max_rows: int) -> Iterable[dict]:
    if path.suffix.lower() == ".csv":
        seen = 0
        for frame in pd.read_csv(path, chunksize=10000, low_memory=False):
            for rec in frame.to_dict("records"):
                if seen >= max_rows:
                    return
                yield rec
                seen += 1
        return
    def openfile():
        return gzip.open(path, "rt", encoding="utf-8") if path.suffix.lower() == ".gz" else path.open("r", encoding="utf-8")
    with openfile() as f:
        # Standard CloudTrail *.json(.gz) files contain {"Records": [...]}.
        if path.name.endswith(".jsonl") or path.name.endswith(".ndjson"):
            for i, line in enumerate(f):
                if i >= max_rows:
                    break
                yield json.loads(line)
        else:
            obj = json.load(f)
            rows = obj.get("Records", []) if isinstance(obj, dict) else obj
            if not isinstance(rows, list):
                raise ValueError(f"Unsupported JSON structure in {path}")
            for rec in rows[:max_rows]:
                yield rec

def load_events(folder: str, max_events: int) -> pd.DataFrame:
    base = Path(folder)
    paths = sorted(p for p in base.rglob("*") if p.is_file() and (p.suffix.lower() in {".csv", ".json", ".gz", ".jsonl", ".ndjson"}))
    if not paths:
        raise FileNotFoundError(f"No CSV, JSON or JSON.GZ files under {base}. Unzip your downloaded dataset here first.")
    rows: list[dict] = []
    for path in paths:
        for record in records_for_file(path, max_events - len(rows)):
            if len(rows) >= max_events:
                break
            rows.append(normalize(record))
        if len(rows) >= max_events:
            break
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce", utc=True)
    df = df.dropna(subset=["eventTime", "eventName"])
    if df.empty:
        raise ValueError("No valid timestamp and eventName columns found. Inspect the source CSV/JSON schema.")
    # Deduplicate only populated event IDs, avoiding accidental collapse of blank IDs.
    df = pd.concat([df.loc[df.eventID.eq("")], df.loc[~df.eventID.eq("")].drop_duplicates("eventID")], ignore_index=True)
    return df.sort_values("eventTime").reset_index(drop=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--folder", default="data/raw")
    p.add_argument("--max-events", type=int, default=250000)
    p.add_argument("--output", default="outputs/events.csv")
    args = p.parse_args()
    df = load_events(args.folder, args.max_events)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.output, index=False)
    print(f"Ingested {len(df):,} CloudTrail records from {args.folder} -> {args.output}")
    if len(df) < 200000:
        print("NOTE: fewer than 200K input records. Your resume's >200K claim would not yet be substantiated.")

if __name__ == "__main__":
    main()
