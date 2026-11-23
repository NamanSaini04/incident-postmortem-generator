#!/usr/bin/env bash
# Phase 7: one run per incident (with RAG), then the ATT&CK review table.
# Usage (from the project folder, key loaded):  bash scripts/run_phase7.sh
set -euo pipefail
out=reports/phase7
mkdir -p "$out"
for i in 1 2 3 4 5 6; do
  echo "=== INC-2026-00$i ==="; python -m pmgen.postmortem "data/incidents/INC-2026-00$i" --out "$out"
done 2>&1 | tee "$out/run_log.txt"
python -m pmgen.abtest "$out" --attack
