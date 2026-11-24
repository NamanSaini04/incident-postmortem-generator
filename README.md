# Cybersecurity Incident Postmortem Generator

[![tests](https://github.com/NamanSaini04/incident-postmortem-generator/actions/workflows/tests.yml/badge.svg)](https://github.com/NamanSaini04/incident-postmortem-generator/actions/workflows/tests.yml)

Turns incident evidence (logs, alerts, analyst notes) into a structured
postmortem where every claim cites its source. **Defensive use only.**
Synthetic data only.

**Live demo:** [incident-postmortem-generator-fpcsgufbx6gwrke2fyxqpm.streamlit.app](https://incident-postmortem-generator-fpcsgufbx6gwrke2fyxqpm.streamlit.app/)
(no sign-up, no API calls; it shows 6 saved reports with their evidence and an
independent verification of every citation)

**Technical report:** [`docs/technical_report.md`](docs/technical_report.md)
([PDF](docs/Cybersecurity_Incident_Postmortem_Generator_Technical_Report.pdf)) ·
**Every run, prediction and correction:** [`docs/results.md`](docs/results.md)

### Results at a glance (6 synthetic incidents; details and limits in the report)

| | |
|---|---|
| Indicators extracted / timeline accuracy | 138/138 / 100% over 36 messy cases |
| Category and severity correct | 18/18 reports, identical across 3 runs |
| MITRE ATT&CK | 94% recall, 0 forbidden techniques used |
| Citations confirmed by the independent verifier | 1401/1401 |
| Hallucination traps avoided (checked by hand) | 120/120 |
| Reviewer agent: planted errors caught | 28/29 |

## Status: all 15 phases complete

| Phase | What | State |
|---|---|---|
| 1-4 | Evidence ingestion (TXT/CSV/JSON), extraction, timeline reconstruction | Done. Timeline 100% on 36 cases (6 incidents x 6 messy variants) |
| 5 | LLM postmortem with claim validation (Anthropic API) | Done. Held-out incidents: category, severity, root cause 3/3 |
| 6 | Policy/playbook retrieval (RAG, BM25) | Done. More specific actions; no accuracy gain (A/B tested) |
| 7 | MITRE ATT&CK mapping, checked against the official catalogue | Done. Recall 92%, 0 forbidden techniques |
| 8 | Root cause vs immediate cause, impact scope, response timing | Done. Milestones 24/24, 0 forbidden systems/accounts |
| 9 | Independent verifier for saved reports | Done. 6/6 reports pass, 718 items, 0 failures |
| 10 | Streamlit dashboard (demo mode: saved reports, no API calls) | Done. Live on Streamlit Community Cloud |
| 11 | Incident PDF export (title page, timeline chart, tables, page numbers) | Done. Also a button in the dashboard |
| 12 | Evaluation suite: the 10 measures in one command, no API calls | Done. See `docs/evaluation.md` |
| 13 | Reviewer agent: checks each claim against its cited records; pipeline trace | Done. 28/29 planted errors caught; found and helped fix certainty inflation |
| 14 | Technical report | Done. [`docs/technical_report.md`](docs/technical_report.md) and PDF |
| 15 | Final testing and documentation | Done. Fresh-install test, CI on Python 3.11 and 3.12 |

Across all runs: 116/116 hallucination traps avoided (checked by hand).

**Limits:** synthetic data only, written by the same author as the answer keys;
one run per incident; the generator and the reviewer are the same model family;
durations in the prose are written by the model and not verified by code.
Details in `docs/results.md`.

## Quick start

Run every command from the repository folder: the sample incidents and the knowledge base are read from
`data/`, not installed with the package. Only commands marked with a cost call the API.

```bash
git clone https://github.com/NamanSaini04/incident-postmortem-generator.git
cd incident-postmortem-generator
python -m venv .venv && source .venv/bin/activate
pip install ".[dev,llm,app]"   # re-run after pulling new code (see note below)
pytest -q          # expect: 352 passed (dashboard and PDF tests skip if their libraries are missing)
python -m pmgen.ingest data/incidents/INC-2026-001   # ingestion summary
python -m pmgen.extract data/incidents/INC-2026-001  # extracted observables
python -m pmgen.timeline data/incidents/INC-2026-001 # reconstructed timeline
python -m pmgen.evaluate                             # timeline scores, 36 cases (run from this folder)
python -m pmgen.postmortem data/incidents/INC-2026-001 --dry-run   # LLM prompt, no API call
python -m pmgen.kb --eval                            # knowledge-base retrieval recall, no API call
bash scripts/ab_test.sh                              # with vs without RAG, 12 API runs (~$1-1.50)
python -m pmgen.attack T1059.001                     # look up an ATT&CK ID in the official catalogue
bash scripts/run_phase7.sh                           # 6 runs + ATT&CK review table (~$0.60-0.80)
bash scripts/run_phase8.sh                           # 6 runs + root cause/impact/timing table (~$0.75)
python -m pmgen.verify docs/sample_reports/phase8/   # re-check the saved reports, no API call
python -m pmgen.pdf docs/sample_reports/phase8/ --out reports/pdf   # Cybersecurity_Incident_Postmortem_<ID>.pdf
python -m pmgen.evalsuite docs/sample_reports/phase8 --out reports/evaluation.md   # all 10 measures, no API calls
python -m pmgen.agents review docs/sample_reports/phase8 --plant --dry-run   # reviewer prompt, no API call
python -m pmgen.agents review docs/sample_reports/phase8 --plant   # reviewer + planted-error benchmark (~$0.15-0.30)
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

## Dashboard

```bash
pip install ".[app]"
streamlit run streamlit_app.py
```

Demo mode by default: shows the saved reports in `docs/sample_reports/phase8/`
(JSON) with their evidence, timeline, ATT&CK mapping, impact, response timing,
actions, the full report, and the verifier result. No API key, no cost.
Live generation appears only when you set `PMGEN_LIVE=1` and `ANTHROPIC_API_KEY`
on your own machine, so a public deployment can never spend API credit.
Other report folders: `PMGEN_REPORTS_DIR=path streamlit run streamlit_app.py`.
Uploading new evidence files through the app is not supported yet.

## Verifying a saved report (no API key needed)

```bash
python -m pmgen.verify docs/sample_reports/phase8/   # every *_postmortem*.json in the folder
```

Re-reads the original evidence files and re-checks the finished report from
scratch: file hashes, every citation and quote, policy quotes, IOCs, ATT&CK IDs,
recomputed durations, impact names, and that confirmed/probable findings have
evidence. Exit code 1 if anything fails. It checks that claims are *grounded*,
not that they are *true*: a real quote can still be misread. That stays with a
human reviewer.

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
src/pmgen/verify.py        Independent re-check of a saved report against the evidence
src/pmgen/dashboard_data.py  Data for the dashboard (tested without Streamlit)
streamlit_app.py           The dashboard
src/pmgen/pdf.py           PDF export (ReportLab, no browser needed)
src/pmgen/evalsuite.py     Evaluation: the 10 measures across saved runs
src/pmgen/agents.py        Reviewer agent, planted-error benchmark, pipeline trace
src/pmgen/report_pdf.py    Builds the technical report PDF from docs/technical_report.md
src/pmgen/provenance.py   Resolve "file / row N" back to the source record
src/pmgen/samples.py      Load bundled incidents
data/incidents/INC-*/     Evidence files + ground_truth.json
docs/architecture.md      Design, pipeline diagram, roadmap
docs/sample_reports/      Real generated reports, one folder per phase
tests/                    352 tests: schema rules, validator, verifier, scoring, dashboard, PDF, evaluation, agents, report
```

See `docs/architecture.md` for the design and `docs/results.md` for real-model results.
