#!/usr/bin/env bash
# Runs every Linux step in order, after the LLM policies exist in policies/llm/.
#   bash scripts/run_pipeline.sh              trace + baseline + enforcement + containment + analysis
#   bash scripts/run_pipeline.sh --no-trace   keep the existing data/ (do not re-record traces)
# LLM generation is a separate step: python3 harness/generate_policies.py (see README, step 4).
set -euo pipefail
cd "$(dirname "$0")/.."
make
if [[ "${1:-}" != "--no-trace" ]]; then
  python3 tracing/record_traces.py          # data/<program>/traces/{training,heldout}.strace + summaries
fi
python3 tracing/make_baseline.py            # policies/baseline/<program>/baseline.json
python3 enforce/run_enforcement.py          # results/enforcement.csv
python3 enforce/run_containment.py          # results/containment.csv
python3 analysis/evaluate_policies.py       # results/policy_metrics.csv
python3 analysis/make_figures.py            # results/figures/*.png, results/summary.md
echo "Done: see results/summary.md and results/figures/"
