# Cybersecurity Incident Postmortem Generator

Turns incident evidence (logs, alerts, analyst notes) into a structured
postmortem where every claim cites its source. **Defensive use only.**
Synthetic data only.

**Status:** Phase 3 of 15. Data contract, three synthetic incidents with
ground truth, evidence ingestion (TXT/CSV/JSON), deterministic observable
extraction and a citation resolver.
No LLM yet. Evaluated on synthetic data only; not validated on production data.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q          # expect: 81 passed
python -m pmgen.ingest data/incidents/INC-2026-001   # ingestion summary
python -m pmgen.extract data/incidents/INC-2026-001  # extracted observables
```

## Layout

```
src/pmgen/schemas.py      Pydantic models + safety validators
src/pmgen/ingest.py       Read evidence files into citable records
src/pmgen/extract.py      Pull IPs, domains, users, timestamps etc. from records
src/pmgen/provenance.py   Resolve "file / row N" back to the source record
src/pmgen/samples.py      Load bundled incidents
data/incidents/INC-*/     Evidence files + ground_truth.json
docs/architecture.md      Design, pipeline diagram, roadmap
tests/                    Schema rules + ground-truth consistency
```

See `docs/architecture.md` for the design.
