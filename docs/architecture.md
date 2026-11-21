# Architecture (Phase 1)

## Core design rule

**Code extracts facts. The LLM only writes about facts it is given.**

Timestamps, IPs, hashes, domains and users are pulled out by parsers and
regex (Phases 2–4). They can be tested, they can't make things up, and you
get exact citations. The LLM gets a structured evidence pack, writes the
narrative parts (summary, root cause wording, lessons), and every claim it
makes is checked against the evidence before it reaches the report.

If the LLM is allowed to extract IOCs from raw logs, it will sometimes invent
or change them. In a security report that's the worst possible failure.

## Pipeline

```mermaid
flowchart TD
    A[Evidence files<br/>TXT / CSV / JSON / PDF / DOCX] --> B[Ingestion<br/>hash + store raw text]
    B --> C[Deterministic extraction<br/>parsers + regex, every fact keeps EvidenceRef]
    C --> D[Timeline builder<br/>normalise to UTC, sort, de-duplicate]
    D --> E[Evidence pack<br/>Pydantic JSON]
    E --> F[LLM analysis<br/>classification, root cause, lessons, actions<br/>structured output only]
    F --> G[Validator<br/>citations resolve? excerpt matches?<br/>confirmed claims have evidence?]
    G -->|fails| F
    G --> H[Report model]
    H --> I[Markdown / PDF / Streamlit]
    J[(V2: RAG knowledge base<br/>playbooks, ATT&CK, policies)] -.-> F
    K[Ground truth<br/>synthetic incidents] -.-> L[Evaluation harness]
    H -.-> L
```

## Module map

| Module | Phase | Status |
|---|---|---|
| `schemas.py` — data contract plus safety rules | 1 | Done |
| `provenance.py` — resolve a citation to its source record | 1 | Done |
| `samples.py` — load synthetic incidents and ground truth | 1 | Done |
| `ingest.py` — read TXT/CSV/JSON, hash, split into citable records | 2 | Done (PDF/DOCX deferred) |
| `extract.py` — regex, field mapping, cross-source user/host linking | 3 | Done |
| `timeline.py` | 4 | Next |
| `llm/` — provider wrapper, prompts, structured output | 5 | |
| `validate.py` — claim vs evidence checks | 5 (basic), 9 (full) | |
| `report/` — Markdown, then PDF | 5, 11 | |
| `eval/` | 12 (basic version from Phase 4) | |

## Extraction (Phase 3): observables, not IOCs

Extraction finds every observable: IPs, domains, URLs, emails, hashes, users,
hosts, processes, file paths, cloud resources and timestamps. It does **not**
decide what is malicious. The company's own domain and its VPN IP are
extracted too. Labelling something an IOC is analysis, done later with context.

Three methods, each recorded on the entity:

| Method | Finds | Example |
|---|---|---|
| `regex` | IPs, URLs, domains, emails, hashes, timestamps in text | `203.0.113.45` in an auth log row |
| `field` | known CSV/JSON keys (`user`, `src_host`, `userIdentity.userName`) | `d.reyes` from cloud audit log |
| `known_entity` | users/hosts from structured data, re-found in notes | `j.patel` in "Revoked all active sessions for j.patel" |

Precision guards:
- A bare `word.word` counts as a domain only if it ends in a known TLD. Without
  this, `j.patel`, `upd.dll` and `powershell.exe` all become domains.
- IPs are validated (`999.1.1.1` is rejected) and tagged with a scope:
  public, private, documentation, loopback or link_local.
- URLs stop at quotes, commas and trailing punctuation.
- Timestamps with a timezone are converted to UTC. Timestamps without one are
  **flagged, not assumed to be UTC**. Time-only values (`09:52`) are flagged
  for Phase 4 to resolve.

Known limits:
- Defanged indicators (`hxxp://`, `evil[.]com`) are not handled.
- The TLD list is short; swap in the public suffix list for real data.
- Relative times ("Next day 09:30") are not extracted.
- Users who appear only as email recipients (`a.khan`) aren't linked as users.

## Safety rules enforced in code (not just in prompts)

- A `confirmed` timeline event must cite evidence and have a timestamp.
- An `inferred` event must give a rationale.
- An `unknown` event can't have confidence above 0.5.
- `confirmed` or `probable` findings must cite evidence.
- An ATT&CK mapping must cite evidence and use a valid ID format.
- Every corrective action must cite supporting evidence.
- Timestamps without a timezone are rejected.

## Locator format (citations)

| File type | Locator | Example |
|---|---|---|
| CSV | `row N` (1-based, header excluded) | `auth_logs.csv / row 2` |
| TXT | `line N` (1-based; blank lines not citable) | `analyst_notes.txt / line 8` |
| JSON | `key[i]`, `[i]` (top-level list), `meta` (top-level fields) | `siem_alerts.json / alerts[1]` |
| PDF/DOCX | `page N para M` | deferred (after Phase 5) |

## Synthetic incidents

| ID | Scenario | What it tests |
|---|---|---|
| INC-2026-001 | Phishing, then mailbox takeover and forwarding rule | Joining events across 5 sources; trap: SharePoint access is suspected but not checked |
| INC-2026-002 | Macro document, then PowerShell, DLL and C2 beacon | No email log is included, so T1566 must **not** be mapped; trap: lateral movement |
| INC-2026-003 | Public storage bucket exposing customer data | Detection by an outside party; trap: who owns the downloading IP |

All IPs are in reserved documentation ranges (RFC 5737). All domains end in
`.test` or `.example`. The hashes are SHA-256 of placeholder strings.
None of them are real indicators.
