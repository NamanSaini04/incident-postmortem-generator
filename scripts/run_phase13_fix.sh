#!/usr/bin/env bash
# Phase 13 fix test: regenerate the two incidents with the most certainty flags (INC-002, INC-004)
# with the new certainty rule, then review them the same way as the baseline (with planted errors).
# Cost: about $0.30. Usage (from the project folder, key loaded): bash scripts/run_phase13_fix.sh
set -euo pipefail
out=reports/phase13fix
mkdir -p "$out"
for i in 2 4; do
  echo "=== INC-2026-00$i ==="; python -m pmgen.postmortem "data/incidents/INC-2026-00$i" --out "$out"
done 2>&1 | tee "$out/run_log.txt"
python -m pmgen.verify "$out"
python -m pmgen.agents review "$out" --plant
cp reports/review/review_summary.md "$out/review_summary.md"
echo "wrote $out/review_summary.md"
