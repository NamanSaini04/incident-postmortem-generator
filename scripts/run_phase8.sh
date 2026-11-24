#!/usr/bin/env bash
# Phase 8: one run per incident (with RAG), then the root cause / impact / response review table.
# Usage (from the project folder, key loaded):  bash scripts/run_phase8.sh
set -euo pipefail
out=reports/phase8
mkdir -p "$out"
for i in 1 2 3 4 5 6; do
  echo "=== INC-2026-00$i ==="; python -m pmgen.postmortem "data/incidents/INC-2026-00$i" --out "$out"
done 2>&1 | tee "$out/run_log.txt"
python -m pmgen.abtest "$out" --impact
python -m pmgen.abtest "$out" --attack > /dev/null
