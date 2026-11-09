"""Three-role LangGraph triage: evidence investigator -> ATT&CK analyst -> incident writer.

With --llm, ATT&CK analyst and writer are model-powered; without it, offline
rules are provided for local smoke tests. Never classify an API call as proof
of compromise without surrounding evidence.
"""
from __future__ import annotations
import json
import os
from typing import Any, TypedDict
from dotenv import load_dotenv
from langgraph.graph import StateGraph, START, END
from pydantic import BaseModel
from .models import IAM_MUTATION, CREDENTIAL, DEFENSE

load_dotenv()

TACTICS = {
    "T1098.003": "Privilege Escalation",
    "T1098.001": "Persistence",
    "T1685.002": "Defense Impairment",
    "T1087.004": "Discovery",
    "T1078.004": "Initial Access",
    "T1530": "Collection",
    "unmapped": "Uncertain",
}

class MappingResult(BaseModel):
    technique_id: str
    tactic: str
    rationale: str
    confidence: str

class ReportResult(BaseModel):
    title: str
    summary: str
    evidence: list[str]
    recommended_actions: list[str]
    limitations: str

class TriageState(TypedDict, total=False):
    events: list[dict]
    evidence: dict[str,Any]
    mapping: dict[str,Any]
    report: dict[str,Any]

def event_name(rec):
    return str(rec.get("eventName", ""))

def offline_map(names: list[str]) -> MappingResult:
    names=set(names)
    if names & DEFENSE:
        tid="T1685.002"
    elif names & IAM_MUTATION:
        tid="T1098.003"
    elif names & {"CreateAccessKey","UpdateAccessKey","CreateLoginProfile","UpdateLoginProfile"}:
        tid="T1098.001"
    elif "GetObject" in names:
        tid="T1530"
    elif names & {"AssumeRole","GetFederationToken"}:
        tid="T1078.004"
    elif names & {"ListUsers","ListRoles","GetAccountAuthorizationDetails","ListPolicies"}:
        tid="T1087.004"
    else:
        tid="unmapped"
    return MappingResult(technique_id=tid,tactic=TACTICS[tid],rationale=f"Candidate mapping based on observed API actions: {', '.join(sorted(names)[:10])}. The sequence alone cannot prove malicious intent.",confidence="medium" if tid!="unmapped" else "low")

def make_graph(use_llm: bool = False):
    if use_llm:
        if not os.getenv("OPENAI_API_KEY"):
            raise ValueError("Set OPENAI_API_KEY in .env before using --llm.")
        from langchain_openai import ChatOpenAI
        model_name=os.getenv("OPENAI_MODEL","gpt-4.1-mini")
        llm=ChatOpenAI(model=model_name,temperature=0)
        map_llm=llm.with_structured_output(MappingResult)
        report_llm=llm.with_structured_output(ReportResult)

    # Role 1: evidence investigator (deterministic/tool-based).
    def investigate(s:TriageState):
        events=s["events"]
        names=[event_name(e) for e in events]
        principal=str((events[0].get("userIdentity") or {}).get("arn","unknown")) if events else "unknown"
        ips=sorted({str(e.get("sourceIPAddress","unknown")) for e in events})
        return {"evidence":{"principal":principal,"event_count":len(events),"event_names":names,"source_ips":ips,"timestamps":[e.get("eventTime") for e in events],"rule_note":"API events are indicators, not confirmation of attack. No permission context or business change ticket is available."}}

    # Role 2: ATT&CK classification analyst.
    def map_attack(s:TriageState):
        ev=s["evidence"]
        if use_llm:
            prompt=("You are a cloud security ATT&CK mapping analyst. Use ONLY the evidence supplied. "
                    "Choose ONE best-supported ATT&CK technique from these options and tactic pairs: "
                    f"{json.dumps(TACTICS)}. For ambiguous cases use 'unmapped'. "
                    "Explain the observed actions, don't invent access scope, compromise, identities, or intent. "
                    "Allowed technique_id must be one of the dictionary keys; tactic must match its value. "
                    f"EVIDENCE={json.dumps(ev)}")
            m=map_llm.invoke(prompt)
            if m.technique_id not in TACTICS or m.tactic!=TACTICS.get(m.technique_id):
                m=offline_map(ev["event_names"])
        else:
            m=offline_map(ev["event_names"])
        return {"mapping":m.model_dump()}

    # Role 3: incident report writer.
    def write_report(s:TriageState):
        ev=s["evidence"]
        mapping=s["mapping"]
        if use_llm:
            prompt=("You are a cautious incident-response analyst. Produce a concise actionable incident report using "
                    "ONLY the event evidence and the ATT&CK mapping. Avoid claiming confirmed intrusion, "
                    "malice, exfiltration or successful privilege escalation without evidence. Make clear uncertainties. "
                    "Action items should be defensive investigations, not destructive or automated account changes. "
                    f"EVENTS={json.dumps(ev)} MAPPING={json.dumps(mapping)}")
            report=report_llm.invoke(prompt)
        else:
            report=ReportResult(title=f"Potential {mapping['tactic']} IAM/cloud activity",summary=f"Observed {ev['event_count']} API events for {ev['principal']}. Candidate technique {mapping['technique_id']} ({mapping['tactic']}); investigate the context before escalating.",evidence=[f"Events: {', '.join(ev['event_names'][:12])}",f"Source IPs: {', '.join(ev['source_ips'])}"],recommended_actions=["Validate the principal and action authorization with the resource owner.","Examine surrounding CloudTrail records and affected resources.","Confirm whether a change request or automation explains the activity."],limitations="No resource-specific policy diffs, baseline context or definitive malicious labels provided.")
        return {"report":report.model_dump()}

    graph=StateGraph(TriageState)
    graph.add_node("evidence_investigator",investigate)
    graph.add_node("attack_classifier",map_attack)
    graph.add_node("incident_writer",write_report)
    graph.add_edge(START,"evidence_investigator")
    graph.add_edge("evidence_investigator","attack_classifier")
    graph.add_edge("attack_classifier","incident_writer")
    graph.add_edge("incident_writer",END)
    return graph.compile()

if __name__=="__main__":
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--llm",action="store_true")
    ap.add_argument("--pattern",default="P01")
    args=ap.parse_args()
    from pathlib import Path
    cases=json.loads(Path("benchmarks/attack_patterns.json").read_text())
    case=next(x for x in cases if x["case_id"]==args.pattern)
    result=make_graph(args.llm).invoke({"events":case["events"]})
    print(json.dumps({"case_id":case["case_id"],"mapping":result["mapping"],"report":result["report"]},indent=2))
