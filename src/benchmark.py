"""Run 30 curated scenarios through the LangGraph triage workflow and optional LLM judge."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import pandas as pd
from pydantic import BaseModel
from dotenv import load_dotenv
from .triage import make_graph

load_dotenv()

class JudgeScores(BaseModel):
    mitre_correctness: int
    evidence_grounding: int
    hallucination_avoidance: int
    actionability: int
    clarity: int
    explanation: str

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--llm",action="store_true",help="Enable LLM classifier and incident writer")
    ap.add_argument("--judge",action="store_true",help="Run a separate LLM-as-judge for five criteria")
    ap.add_argument("--limit",type=int,default=30)
    args=ap.parse_args()
    if args.judge and not args.llm:
        ap.error("--judge requires --llm; offline heuristic reports are not presented as LLM judged.")
    cases=json.loads(Path("benchmarks/attack_patterns.json").read_text())[:args.limit]
    graph=make_graph(args.llm)
    if args.judge:
        if not os.getenv("OPENAI_API_KEY"):
            raise ValueError("Set OPENAI_API_KEY in .env")
        from langchain_openai import ChatOpenAI
        judge=ChatOpenAI(model=os.getenv("OPENAI_MODEL","gpt-4.1-mini"),temperature=0).with_structured_output(JudgeScores)
    rows=[]
    Path("outputs").mkdir(exist_ok=True)
    for i, case in enumerate(cases,1):
        state=graph.invoke({"events":case["events"]})
        row={"case_id":case["case_id"],"attack_pattern":case["attack_pattern"],"expected_technique":case["expected_technique"],"predicted_technique":state["mapping"]["technique_id"],"expected_tactic":case["expected_tactic"],"predicted_tactic":state["mapping"]["tactic"],"mapping_match":int(state["mapping"]["technique_id"]==case["expected_technique"]),"summary":state["report"]["summary"],"report_json":json.dumps(state["report"]),"mode":"LLM" if args.llm else "offline-rules"}
        if args.judge:
            prompt=("You are an independent cloud incident report evaluator. Judge ONLY the supplied report "
                "against supplied evidence and a reference MITRE label. Score each criterion integer 1=poor to "
                "5=excellent. Criteria: mitre_correctness (label match and rationale), evidence_grounding "
                "(every key claim traceable to events), hallucination_avoidance (uncertainty and no unsupported "
                "claims), actionability (specific defensive next steps), clarity (concise readable report). "
                "Do not give 5 automatically; use evidence. Return explanation explaining strongest weakness. "
                f"EVENTS={json.dumps(case['events'])} REFERENCE={json.dumps({'technique':case['expected_technique'],'tactic':case['expected_tactic']})} "
                f"MAPPING={json.dumps(state['mapping'])} REPORT={json.dumps(state['report'])}")
            score=judge.invoke(prompt)
            for field in ["mitre_correctness","evidence_grounding","hallucination_avoidance","actionability","clarity"]:
                val=getattr(score,field)
                if not 1<=val<=5:
                    raise ValueError(f"Judge returned invalid {field}={val} for {case['case_id']}")
                row[field]=val
            row["judge_explanation"]=score.explanation
        rows.append(row)
        print(f"[{i}/{len(cases)}] {case['case_id']} mapping={row['predicted_technique']} expected={row['expected_technique']} match={bool(row['mapping_match'])}")
    frame=pd.DataFrame(rows)
    frame.to_csv("outputs/benchmark_results.csv",index=False)
    metrics={"total_patterns":len(frame),"mapping_accuracy":float(frame.mapping_match.mean()),"mode":"LLM" if args.llm else "offline-rules", "benchmark_type":"authored controlled CloudTrail-style attack-pattern scenarios, not verified historical compromises"}
    if args.judge:
        cols=["mitre_correctness","evidence_grounding","hallucination_avoidance","actionability","clarity"]
        metrics["mean_judge_scores"]={col:round(float(frame[col].mean()),3) for col in cols}
        metrics["overall_judge_mean"]=round(float(frame[cols].values.mean()),3)
    Path("outputs/benchmark_metrics.json").write_text(json.dumps(metrics,indent=2))
    print(json.dumps(metrics,indent=2))

if __name__=="__main__":
    main()
