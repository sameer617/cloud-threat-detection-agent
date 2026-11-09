"""Local-only Streamlit dashboard for ranked anomaly windows and triage reports."""
import json
from pathlib import Path
import pandas as pd
import streamlit as st
from src.triage import make_graph

st.set_page_config(page_title="Cloud Threat Detection & Triage",layout="wide")
st.title("Cloud Threat Detection & Incident Triage")
st.caption("Prototype: anomalies are investigation leads, not confirmed attacks. Real CloudTrail or labeled controlled data is preferred to synthetic samples.")
scored_path=Path("outputs/scored_windows.csv")
if not scored_path.exists():
    st.warning("No model artifacts found. Run: python -m src.ingest and python -m src.models from the project folder.")
    st.stop()
scored=pd.read_csv(scored_path)
c1,c2,c3=st.columns(3)
c1.metric("Behavior windows",f"{len(scored):,}")
c2.metric("Flagged windows",f"{int(scored.is_alert.sum()):,}")
c3.metric("Anomaly percentage",f"{100*scored.is_alert.mean():.1f}%")
st.subheader("Highest-scoring behavior windows")
show=scored.loc[scored.is_alert].copy().head(100)
if show.empty:
    show=scored.head(100)
st.dataframe(show[["principal","window_start","total_calls","iam_mutations","credential_ops","defense_ops","if_percentile","ae_percentile","combined_score","security_events"]],hide_index=True,use_container_width=True)
st.subheader("Inspect a window")
idx=st.selectbox("Ranked window",options=show.index.tolist(),format_func=lambda i:f"{show.loc[i,'principal']} | {show.loc[i,'window_start']} | score={show.loc[i,'combined_score']:.3f}")
selected=show.loc[idx]
st.write("Candidate security activity:", selected.get("security_events") or "No IAM rule-based signal")
use_llm=st.checkbox("Use LLM triage (requires a valid OPENAI_API_KEY in .env)",value=False)
if st.button("Generate incident triage report"):
    events_path=Path("outputs/events.csv")
    if not events_path.exists():
        st.error("Expected outputs/events.csv")
    else:
        events=pd.read_csv(events_path,low_memory=False)
        events["window_start"]=pd.to_datetime(events.eventTime,utc=True).dt.floor("6h")
        start=pd.Timestamp(selected.window_start)
        group=events[(events.principal==selected.principal)&(events.window_start==start)]
        if group.empty:
            st.error("Could not locate matching raw event group")
        else:
            # The agent should see relevant event records only; no labels supplied.
            raw=[{"eventTime":str(r.eventTime),"eventName":r.eventName,"eventSource":r.eventSource,"sourceIPAddress":r.sourceIPAddress,"userIdentity":{"arn":r.principal}} for r in group.head(80).itertuples(index=False)]
            try:
                result=make_graph(use_llm=use_llm).invoke({"events":raw})
                st.write("ATT&CK mapping",result["mapping"])
                st.write("Incident report")
                st.json(result["report"])
            except Exception as e:
                st.error(f"Triage failed: {e}")
bench=Path("outputs/benchmark_metrics.json")
if bench.exists():
    st.subheader("30-pattern triage benchmark")
    st.json(json.loads(bench.read_text()))
labeled=Path("outputs/labeled_eval.json")
if labeled.exists():
    st.subheader("Labeled detection evaluation")
    st.json(json.loads(labeled.read_text()))
