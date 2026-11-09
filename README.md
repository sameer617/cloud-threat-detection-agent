# Cloud Threat Detection & Incident Triage Agent

Portfolio prototype analyzing **200K+ public AWS CloudTrail records** with Isolation Forest and a PyTorch autoencoder, followed by a 3-role **LangGraph** incident triage workflow. A separately authored **30-pattern CloudTrail-style benchmark** measures MITRE ATT&CK classification; an optional LLM-as-judge provides five distinct quality scores. Streamlit offers a local investigation UI.


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

