# Cybersecurity Incident Postmortem Generator

Turns incident evidence (logs, alerts, analyst notes) into a structured
postmortem where every claim cites its source. **Defensive use only.**
Synthetic data only.

**Status:** Phase 7 of 15. Validated LLM postmortem with policy retrieval (RAG) and MITRE ATT&CK mapping checked against the official catalogue; 6 synthetic incidents.
Previous: Evidence ingestion (TXT/CSV/JSON), deterministic
extraction, timeline reconstruction, and timeline evaluation on 3 synthetic
incidents plus 15 messy variants (shuffled, noisy, mixed timezones,
duplicate alerts).
No LLM yet. Evaluated on synthetic data only; not validated on production data.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install ".[dev,llm]"   # re-run after pulling new code (see note below)
pytest -q          # expect: 253 passed
python -m pmgen.ingest data/incidents/INC-2026-001   # ingestion summary
python -m pmgen.extract data/incidents/INC-2026-001  # extracted observables
python -m pmgen.timeline data/incidents/INC-2026-001 # reconstructed timeline
python -m pmgen.evaluate                             # timeline scores, 18 cases (run from this folder)
python -m pmgen.postmortem data/incidents/INC-2026-001 --dry-run   # LLM prompt, no API call
python -m pmgen.kb --eval                            # knowledge-base retrieval recall, no API call
bash scripts/ab_test.sh                              # with vs without RAG, 12 API runs (~$1-1.50)
python -m pmgen.attack T1059.001                     # look up an ATT&CK ID in the official catalogue
bash scripts/run_phase7.sh                           # 6 runs + ATT&CK review table (~$0.60-0.80)
```

## Running the LLM step

Needs an Anthropic API key. Never put the key in a file inside this repo.

```bash
read -s ANTHROPIC_API_KEY && export ANTHROPIC_API_KEY   # paste key, press Enter (not saved to shell history)
python -m pmgen.postmortem data/incidents/INC-2026-001  # writes reports/INC-2026-001_postmortem.md
```

Default model: `claude-sonnet-5-5`. Override with `--model` or `PMGEN_MODEL`.
JSON is requested in the prompt by default; `--mode structured` uses the API's
constrained output instead (fails on this schema with current models, see docs).
If ground truth exists, a score is printed, plus a list of statements to
check by hand (the hallucination traps).

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
src/pmgen/evidence_pack.py  What the LLM sees: numbered records, timeline, observables
src/pmgen/llm.py            Anthropic client (+ fake client for tests)
src/pmgen/validate.py       Check every LLM claim; drop or redact what fails
src/pmgen/postmortem.py     Generate + render the Markdown postmortem
src/pmgen/kb.py            Knowledge base: section chunking + BM25 retrieval
src/pmgen/abtest.py        Summarise with/without-RAG runs
src/pmgen/attack.py        MITRE ATT&CK catalogue lookups and ID checks
src/pmgen/provenance.py   Resolve "file / row N" back to the source record
src/pmgen/samples.py      Load bundled incidents
data/incidents/INC-*/     Evidence files + ground_truth.json
docs/architecture.md      Design, pipeline diagram, roadmap
tests/                    Schema rules + ground-truth consistency
```

See `docs/architecture.md` for the design and `docs/results.md` for real-model results.
