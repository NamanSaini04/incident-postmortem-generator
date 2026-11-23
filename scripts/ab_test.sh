#!/usr/bin/env bash
# Phase 6 A/B test: every incident with and without the knowledge base, same prompt.
# Usage (from the project folder, key loaded):  bash scripts/ab_test.sh
set -euo pipefail
mkdir -p reports
for i in 1 2 3 4 5 6; do
  inc="data/incidents/INC-2026-00$i"
  echo "=== INC-2026-00$i without RAG ==="; python -m pmgen.postmortem "$inc" --no-rag
  echo "=== INC-2026-00$i with RAG ===";    python -m pmgen.postmortem "$inc"
done 2>&1 | tee reports/ab_log.txt
python -m pmgen.abtest reports
