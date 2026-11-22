# Cybersecurity Incident Postmortem Generator

Turns incident evidence (logs, alerts, analyst notes) into a structured
postmortem where every claim cites its source. **Defensive use only.**
Synthetic data only.

**Status:** Phase 4 of 15. Evidence ingestion (TXT/CSV/JSON), deterministic
extraction, timeline reconstruction, and timeline evaluation on 3 synthetic
incidents plus 15 messy variants (shuffled, noisy, mixed timezones,
duplicate alerts).
No LLM yet. Evaluated on synthetic data only; not validated on production data.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install ".[dev]"   # re-run after pulling new code (see note below)
pytest -q          # expect: 115 passed
python -m pmgen.ingest data/incidents/INC-2026-001   # ingestion summary
python -m pmgen.extract data/incidents/INC-2026-001  # extracted observables
python -m pmgen.timeline data/incidents/INC-2026-001 # reconstructed timeline
python -m pmgen.evaluate                             # timeline scores, 18 cases (run from this folder)
```

**macOS note:** if `pip install -e` succeeds but `import pmgen` fails, macOS
may have marked the install's `.pth` file as hidden, and newer Python skips
hidden `.pth` files. A normal install (`pip install ".[dev]"`) avoids this.

## Layout

```
src/pmgen/schemas.py      Pydantic models + safety validators
src/pmgen/ingest.py       Read evidence files into citable records
src/pmgen/extract.py      Pull IPs, domains, users, timestamps etc. from records
src/pmgen/timeline.py     Order events, fill dates, merge duplicates
src/pmgen/evaluate.py     Score timelines against ground truth
src/pmgen/variants.py     Messy versions of each incident
src/pmgen/provenance.py   Resolve "file / row N" back to the source record
src/pmgen/samples.py      Load bundled incidents
data/incidents/INC-*/     Evidence files + ground_truth.json
docs/architecture.md      Design, pipeline diagram, roadmap
tests/                    Schema rules + ground-truth consistency
```

See `docs/architecture.md` for the design.
