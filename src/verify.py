"""End-of-project audit: makes missing portfolio evidence explicit."""
import json
from pathlib import Path
import pandas as pd

def result(ok, message):
    print(("PASS " if ok else "TODO ")+message)

def main():
    events=Path('outputs/events.csv')
    if events.exists():
        n=sum(1 for _ in events.open(encoding='utf-8'))-1
        result(n>=200000, f'{n:,} ingested event records (target 200K+)')
    else:
        result(False,'Ingested data missing; run python -m src.ingest')
    result(not Path('data/raw/synthetic_demo.csv').exists(),'No synthetic demo data mixed with project sources')
    model=Path('outputs/model_stats.json')
    result(model.exists(),'Model run metrics saved')
    if model.exists():
        stats=json.loads(model.read_text()); print('    ',stats)
    for f in ['outputs/iforest.joblib','outputs/autoencoder.pt','outputs/alerts.csv']:
        result(Path(f).exists(), f'{f} created')
    cases=json.loads(Path('benchmarks/attack_patterns.json').read_text())
    result(len(cases)==30, f'{len(cases)} authored benchmark attack patterns')
    b=Path('outputs/benchmark_results.csv')
    if b.exists():
        df=pd.read_csv(b)
        result(len(df)==30,f'{len(df)} triaged benchmark patterns')
        result(('mitre_correctness' in df and df['mode'].eq('LLM').all()),'LLM classifier + five-criterion judge results saved')
    else:
        result(False,'Benchmark output missing; run python -m src.benchmark --llm --judge')
    result(Path('outputs/labeled_eval.json').exists(),'Independent labeled evaluation saved (recommended)')
    print('VERIFY actual cloud data and model performance before publishing any resume claims.')
if __name__ == '__main__':
    main()
