# Cloud Threat Detection & Incident Triage Agent

Portfolio prototype analyzing **200K+ public AWS CloudTrail records** with Isolation Forest and a PyTorch autoencoder, followed by a 3-role **LangGraph** incident triage workflow. A separately authored **30-pattern CloudTrail-style benchmark** measures MITRE ATT&CK classification; an optional LLM-as-judge provides five distinct quality scores. Streamlit offers a local investigation UI.

**Important:** Anomalies are *not* confirmed attacks. The 30 controlled patterns are **not** labeled real-world incidents. `ArielCyber` supplies independent, labeled logs. Do not represent the synthetic generator as real AWS activity. No AWS account or actual attack emulation is required.

## Quickstart (Windows PowerShell, Python 3.11)

```powershell
# Open VS Code terminal in this project folder
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PyTorch CPU installation is difficult on Windows, install it separately using the official selector at https://pytorch.org/get-started/locally/ then `pip install -r requirements.txt`.

## 1. Download real CloudTrail data (>200K events)

Get the **AWS Cloudtrails Dataset from flaws.cloud** at:
https://www.kaggle.com/datasets/nobukim/aws-cloudtrails-dataset-from-flaws-cloud

Extract it to `data/raw/`, including nested folders if needed. The dataset is described as containing roughly 1.94 million events, but file formats can vary by Kaggle release. Ingest handles CSV and CloudTrail `{"Records": [...]}` JSON/JSON.GZ, plus JSONL, with standard fields. **If ingest fails with schema-related errors, inspect the CSV header and adjust `src/ingest.py` aliases.**

```powershell
python -m src.ingest --folder data/raw --max-events 250000
python -m src.models --epochs 15
```

These create `outputs/events.csv`, `outputs/scored_windows.csv`, `outputs/alerts.csv`, and saved model artifacts. Source logs are never automatically uploaded to GitHub. **Check the printed input count before saying 200K+.**

### Offline smoke test if dataset download is delayed

```powershell
python -m src.generate_demo --n 210000
python -m src.ingest --folder data/raw --max-events 250000
python -m src.models --epochs 8
```

This is **synthetic test data**, not real CloudTrail. Remove `data/raw/synthetic_demo.csv` before processing the genuine Kaggle dataset to avoid mixing them.

## 2. LangGraph triage

Three graph roles: evidence investigator (deterministic tool), MITRE ATT&CK mapping analyst (LLM if enabled), and incident writer (LLM if enabled). All state passes through explicit graph nodes.

```powershell
# Test local graph wiring with rule-based offline mode
python -m src.triage --pattern P01
# Enable model-powered agent behavior:
Copy-Item .env.example .env
# Edit .env to insert your own OPENAI_API_KEY; never commit it.
python -m src.triage --pattern P01 --llm
```

The API key is **only** for LLM classification/report generation and LLM judging; the large dataset and both ML models run locally. The model in `.env` must be enabled on your API account; API usage may incur charges.

## 3. Thirty-pattern evaluation

`benchmarks/attack_patterns.json` contains 30 manually authored CloudTrail-style API sequences covering six technique families (five variations each). ATT&CK IDs and tactic labels are reference mappings, not proof of actual compromise. DO NOT pass expected labels into classifier inputs; the judge alone may see the reference answer.

```powershell
# Offline unit/smoke check (no LLM quality measurement)
python -m src.benchmark --limit 30
# Actual LLM classification + 5-criterion independent model judging
python -m src.benchmark --llm --judge --limit 30
```

Five rubric scores (1-5): `mitre_correctness`, `evidence_grounding`, `hallucination_avoidance`, `actionability`, `clarity`. Outputs: `outputs/benchmark_results.csv`, `outputs/benchmark_metrics.json`.

**Separate objective result:** `mapping_accuracy` equals fraction of the 30 cases with exactly correct technique IDs. Subjective LLM judge scores should be presented individually and as a mean, not as detection precision/recall.

## 4. Ground-truth validation (optional but recommended)

Download https://github.com/ArielCyber/cloud_log_sampling . Extract its **TestOn/labeled_cloudtrail_a.zip** to a new location such as `data/ariel_test/`, retaining the JSON file (do not mix with `data/raw/`). `attack_name` supplies the adversarial label. Run:

```powershell
python -m src.evaluate_labeled --folder data/ariel_test
```

Result: `outputs/labeled_eval.json` contains attack-window precision/recall/F1 and confusion matrix using **frozen models** trained on Dataset A. Due to different datasets and 6-hour aggregation, this is an out-of-domain, session-level detection test, *not* an event-level test or guaranteed high metric.

## 5. Streamlit demo

```powershell
streamlit run app.py
```

Dashboard: total behavioral windows, top anomaly windows, supporting IAM/STS actions, corresponding MITRE mapping, generated report, evaluation tables.

## File guide

```
app.py                        # demo dashboard
src/ingest.py                 # raw-to-CSV processing
src/models.py                 # per-principal 6-hour feature profiles, IF + autoencoder
src/triage.py                 # LangGraph three-role workflow
src/benchmark.py              # 30 attack-pattern cases + five-criterion judge
src/evaluate_labeled.py       # separate ground-truth eval
src/generate_demo.py          # optional SYNTHETIC smoke data
benchmarks/attack_patterns.json
outputs/                      # generated locally, not committed
```

## Scientific caveats

1. Original `flaws.cloud` CloudTrail records do not have reliable event-level malicious labels. Model outliers are leads, not confirmed attacks.
2. Labels in our 30-pattern benchmark are *author-assigned controlled reference labels*. The benchmark stresses LLM classification, not end-to-end anomaly detection recall.
3. An AWS `AssumeRole` or `GetObject` event alone does not prove malicious activity. Agent language reflects uncertainty.
4. No rolling historical baseline, IAM policy diff, resource graph, IP reputation feed, or live AWS integration is implemented.
5. The train/holdout split is chronological by behavior window but may reuse principals; a production evaluation needs broader temporal and environment holdouts.
6. The demo uses 6-hour aggregated behavior windows, and alert cutoffs are fixed by train-score percentiles, not optimized on labels.

## Sources

- CloudTrail record format: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- Main dataset: https://www.kaggle.com/datasets/nobukim/aws-cloudtrails-dataset-from-flaws-cloud
- Labeled validation: https://github.com/ArielCyber/cloud_log_sampling
- LangGraph Graph API quickstart: https://docs.langchain.com/oss/python/langgraph/quickstart
- Official MITRE techniques: https://attack.mitre.org/techniques/T1098/003/ and https://attack.mitre.org/wiki/Technique/T1562/008/

