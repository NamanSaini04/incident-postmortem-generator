# Cybersecurity Incident Postmortem Generator: Technical Report

Naman Saini · 24 November 2026 · Code: github.com/NamanSaini04/incident-postmortem-generator · Live demo: incident-postmortem-generator-fpcsgufbx6gwrke2fyxqpm.streamlit.app

## 1. Executive Summary

This project turns raw incident evidence (logs, alerts, analyst notes) into a structured, evidence-grounded postmortem draft. Its central design rule is that **code extracts the facts and the LLM only writes about facts it is given**. Every claim in a report cites a specific record, and every citation is checked by code twice: once while the report is generated, and again afterwards by an independent verifier that re-reads the original files.

It was evaluated on 6 synthetic incidents (phishing, macro malware, cloud data exposure, ransomware, insider data theft, cloud key misuse), with answer keys and "trap" statements written before each run and predictions pre-registered.

Main results:

- Deterministic stages: 138/138 answer-key indicators extracted and 100% timeline accuracy over 36 cases, including messy variants (shuffled rows, mixed timezones, duplicates, noise).
- LLM stages: category and severity correct in 18/18 reports across 3 runs; root cause cites the correct record in 18/18; MITRE ATT&CK lenient recall 94% with 0 of 17 forbidden techniques used; 120/120 hand-checked hallucination traps avoided.
- Citations: 1401/1401 confirmed by the independent verifier.
- A reviewer agent added in Phase 13 found what none of the code checks could: about 1 in 11 claims stated an inference as "confirmed". One prompt rule cut this from 7 to 1 on the two incidents re-tested, with a small and partly measured cost.

The main limits: all data is synthetic and written by the same author as the answer keys; the generator and the reviewer are the same model family; most measurements are one run per incident. The results show the pipeline behaves as designed on these cases. They do not show accuracy on real incidents.

## 2. Problem Statement

After a security incident, teams write a postmortem: what happened, when, why, what it affected, how the response went, and what will prevent a repeat. It is slow, manual work spread across many log sources, and the quality depends on who writes it.

An LLM can draft a postmortem quickly, but in security a fluent draft is dangerous when it is wrong. The specific failures that matter are:

- **Invented indicators of compromise.** An IP or domain that is not in the evidence gets blocked, or worse, a real one is missed.
- **Overstated certainty.** "The attacker stole 200 GB" when only the ransom note claims it. Notification duties and legal decisions follow from such statements.
- **Wrong timeline.** A timestamp without a timezone silently treated as UTC; a next-day event read as same-day.
- **Unverifiable claims.** A reader cannot check a statement that cites nothing.

The goal was therefore not "an LLM that writes postmortems" but **a system whose every claim can be traced to evidence, whose uncertainty is explicit, and whose failure modes are measured**.

## 3. Incident Response Background

A postmortem (or post-incident review) is the final stage of the incident response life cycle described in NIST SP 800-61: preparation; detection and analysis; containment, eradication and recovery; and post-incident activity. Its value comes from being blameless and evidence-based: the aim is to find which controls failed and why, not who to blame.

The concepts this project models directly:

- **Immediate cause vs root cause.** The immediate cause is what directly triggered the incident (a password typed into a fake page). The root cause is the underlying weakness that let it succeed (MFA not enforced for that account).
- **Contributing factors and detection gaps.** Conditions that made the incident worse or slower to find, such as an alert routed to a queue instead of paging.
- **Response metrics.** Time to detect, respond and contain, and dwell time, computed from timeline milestones.
- **MITRE ATT&CK.** A public catalogue of attacker tactics and techniques (for example T1078 Valid Accounts) that gives a shared vocabulary for observed behaviour.
- **Certainty.** Every finding is labelled confirmed (stated in the evidence), probable (a strong inference), possible, or unknown.

## 4. LLM Architecture

```
Evidence files (TXT / CSV / JSON)
  -> ingest: hash each file, split into citable records         code
  -> extract: IPs, domains, users, hosts, hashes, timestamps    code
  -> timeline: UTC, ordering, date inference, de-duplication    code
  -> retrieve: relevant policy and playbook sections (BM25)     code
  -> evidence pack: records R###, KB sections K##, timeline EV###
  -> draft: the LLM writes JSON that cites R/K/EV IDs           LLM (Anthropic API)
  -> validate: citations, quotes, certainty, IOCs, ATT&CK IDs   code, one retry with the problems
  -> review: does each cited record support its claim?          LLM (Phase 13)
  -> verify: independent re-check of the saved report           code
  -> report: Markdown, PDF, Streamlit dashboard                 code
```

Key decisions:

- **The model never sees raw logs as free text to "find" indicators in.** It receives numbered records and may only cite them. An indicator it names is kept only if extraction found it in the evidence; otherwise it is dropped and logged.
- **Output format.** The Anthropic API is called in "prompt-JSON" mode: the schema is given in the prompt and JSON is parsed from tags. Two other designs failed in practice: a forced tool call was rejected by the model (HTTP 400), and constrained decoding was rejected for this schema ("compiled grammar too large"). Both are recorded in the architecture notes.
- **Pydantic schemas are the contract.** A confirmed finding must have evidence; timestamps must carry a timezone; ATT&CK IDs must match the ID format. Invalid drafts are rejected before any report is built.
- **One retry.** The validator returns specific problems ("quote not found in auth_logs.csv row 2") to the model once. Whatever still fails is dropped or redacted, and logged in the report.
- **Model:** claude-sonnet-5-5, about $0.10-0.13 per report.

## 5. RAG Architecture

The knowledge base holds 13 synthetic company documents: 5 incident playbooks, 4 policies, 1 hardening standard, 1 severity matrix and 2 past incident reviews, split into 53 sections.

- **Retrieval is BM25 keyword search, top 8 sections.** The spec suggested embeddings and a vector database; at 53 sections that adds a dependency without a measured benefit, so it was not built. Retrieval recall against sections listed in the answer keys before running: 84.7% (chosen on the same 6 incidents, so slightly optimistic). A per-document cap that was expected to help made recall worse (72%) and was dropped.
- **Knowledge-base citations are allowed only on lessons and corrective actions**, never on findings: a policy says what should happen, not what did happen. An action that cites only policy and no evidence is dropped.
- **Leak guard:** a test fails if incident facts appear in the knowledge base.

A/B test, 6 incidents with and without retrieval: core accuracy (category, severity, root cause, contributing factors) was 100% in both arms and traps were avoided in both. With retrieval, 95% of corrective actions cited a policy and policy recall was 85%. By my reading, 31 of 33 policy citations applied (2 were weak). Retrieval made recommendations specific and checkable (for example "DLP audit mode at most 30 days, POL-12 §5"), and surfaced two insights absent without it: a past review had already agreed the fix for a recurring failure, and an insider was interviewed before the laptop was collected, against the playbook. **It did not make the analysis more correct**; the core scores were already at ceiling.

## 6. Evidence Processing

Ingestion reads TXT, CSV and JSON, stores a SHA-256 hash of each file, and splits it into citable records with stable locators: `row N` for CSV, `line N` for text, `key[i]` for JSON. The same readers are used later to resolve citations, so a locator always points at the same text.

Extraction finds observables, not indicators of compromise: the company's own VPN IP is extracted too, because deciding what is malicious is analysis that needs context. Three methods are used: regex for IPs, URLs, domains, emails and hashes; known fields such as `user` or `userIdentity.userName`; and re-finding known users and hosts in free-text notes. Precision guards include a known-TLD list (so `j.patel` and `powershell.exe` are not domains), IP validation with a scope tag (public, private, documentation), and URLs ending at quotes and punctuation.

Result: **138/138 answer-key indicators found** across the 6 incidents and their 5 messy variants each.

Not supported: PDF and DOCX evidence (listed in the spec), defanged indicators such as `evil[.]com`, and relative times ("next day 09:30").

## 7. Timeline Reconstruction

- Timestamps with a timezone are converted to UTC. **Timestamps without one are never silently assumed to be UTC**: each event records a time basis of exact, timezone_assumed, or date_inferred.
- Time-only analyst notes ("09:52 Revoked sessions") take their date from a date heading in the notes, rolling to the next day past midnight.
- Duplicate events across logs (an EDR and a proxy record of the same connection) are merged within 2 seconds when they share a strong observable and do not conflict on user or host.

Result: **100% event recall, timestamp accuracy and order accuracy over 36 cases** (6 incidents × original + 5 variants: shuffled rows, noise rows, offset timezones, duplicate alerts, and all of these combined).

The PDF timeline chart exposed one presentation bug that the tests had missed: for an incident spanning midnight, the axis showed only hours, so an event the next morning read as the same night. The axis now shows dates whenever events span two days, with a test.

## 8. MITRE ATT&CK Mapping

The model maps behaviour to techniques **from its own knowledge**. It is given no technique list, because a list would leak the answer key; a test fails if any answer-key technique ID appears anywhere in the prompt or schema. This test caught a real leak while building: the schema's example ID, T1059.001, was one of INC-002's answers.

Code then checks every ID against the official MITRE enterprise ATT&CK catalogue (matrix modified 2026-07-31), rejects invented, revoked or deprecated IDs, and fills in the official names and tactics. Mapped techniques must be confirmed or probable and cite evidence.

Each answer key lists required, acceptable and **forbidden** techniques. Forbidden ones are plausible-sounding but unsupported, such as exfiltration techniques for a ransom note's unverified theft claim, or phishing where no email evidence exists.

Results: lenient recall 94% and precision 97% over 12 reports, and **0 of 17 forbidden techniques used**. The main recurring miss is instructive: in INC-004 the model mapped an internet-facing RDP logon as T1021.001 (Remote Desktop, lateral movement) instead of T1133 (External Remote Services, initial access). Because T1021.001 was on the acceptable list for internal RDP, the scorer counted it correct. **An acceptable list cannot check why a technique was chosen**; that error was found only by reading the report.

## 9. Root Cause Analysis

The report separates the immediate cause, the root cause, contributing factors and detection gaps. Each is a finding with a certainty label and citations.

- Root cause cites the answer key's record in **18/18 reports** across 3 runs, and contributing-factor recall is 100%.
- Across runs, the cited root-cause *record* matched exactly in only 1 of 6 incidents: the model picks different supporting lines for the same cause.
- **Certainty was the weak point.** The independent reviewer (Section 10) found that the drafts systematically labelled cause-and-effect inferences as confirmed: "routed to a queue instead of paging, *which delayed response*", where the record states only the routing. A prompt rule now says a finding is only as certain as its least certain part.
- I corrected two of my own earlier diagnoses here. A "certainty drift" I had called the most consistent weakness turned out to be the model making different claims across runs, each labelled correctly; my answer key had bundled a stated fact with an inference. And a claim I had called under-claimed, the reviewer showed to be over-claimed, and it was right.

Impact and response timing (Phase 8): the model chooses four timeline events (attack start, first detection, response start, containment); **code computes the durations** and marks them approximate if a time was inferred. Milestones were right in 24/24 cases, but the evidence notes name these moments plainly, so this is an easy test. The model does still write durations itself in prose ("about 45 minutes later"); those were correct in every case I spot-checked but are not verified by code.

## 10. Postmortem Generation and Validation

Validation happens in three layers, each catching what the previous one cannot:

| Layer | When | Checks | Cannot check |
|---|---|---|---|
| Validator (code) | while generating | record IDs exist; quotes are found in the cited record; confirmed and probable findings have evidence; indicators were extracted; ATT&CK IDs are real; summary points that rest on unconfirmed findings are hedged | whether the record means what the claim says |
| Verifier (code) | after saving | file hashes unchanged; every citation, quote, policy quote and IOC re-found in the original files; durations recompute | the same |
| Reviewer agent (LLM) | after saving | whether the cited records support each claim at its stated certainty | its own mistakes (same model family) |

Two further code checks for meaning were tested offline and rejected. Requiring named accounts in the cited records flagged 4 of 294 claims, with only 1 true problem. Requiring numbers in the cited records flagged 56 of 419 claims, none of them real problems: they were reformatted dates, units, and correct arithmetic.

**Reviewer agent.** Of the 8 specialist agents the spec suggested, only one was built, because only one gap needed it; the other stages are tested deterministic code. The reviewer sees each claim with the full text of its cited records, never the draft's reasoning, and returns supported, overstated, understated or unsupported. It only flags; a human decides. To measure it, known errors that keep real citations (so every code check passes) were planted among the real claims: certainty raised from probable to confirmed, a statement moved onto unrelated citations, and an account, host or IP swapped for another from the same evidence (for example, the company's own VPN IP as "the attacker").

The reports are delivered as Markdown, a PDF with a timeline chart, and a Streamlit dashboard in demo mode (saved reports, no API calls, so a public link cannot spend credit).

## 11. Evaluation

All 10 measures in the spec are computed by one command from saved reports, without API calls (`python -m pmgen.evalsuite`). A stage a report's version did not have (for example ATT&CK before Phase 7) counts as not applicable rather than 0%. The first version of the evaluation got this wrong and showed ATT&CK recall of 63% instead of 94%.

| # | Measure | Method |
|---|---|---|
| 1 | Evidence extraction | answer-key indicators found, 36 cases, code only |
| 2 | Timeline | event recall, timestamp and order accuracy, 36 cases |
| 3 | Classification | category and severity vs answer key |
| 4 | ATT&CK | lenient recall, precision, forbidden techniques |
| 5 | Root cause grounding | root cause cites the key's record; contributing-factor recall |
| 6 | Citation correctness | share confirmed by the independent verifier |
| 7 | Unsupported claims | claims removed / all claims; first drafts with problems |
| 8 | Severity consistency | same answer (value, not correctness) across runs |
| 9 | Recommendation relevance | proxy: action cites a record behind a finding; policy recall |
| 10 | Completeness | 13-item section checklist |

Hallucination traps ("must not claim" statements such as "the attacker stole 200 GB" or "198.51.100.77 belongs to a known threat actor") are checked by hand, because a statement can cite a real record and still misread it.

Method rules: answer keys and trap lists were written before runs; predictions were pre-registered in `docs/results.md`; three incidents were held out from all prompt tuning; ground-truth corrections are listed with reasons, never applied silently.

## 12. Results

Evaluation over 18 reports (3 runs of 6 incidents) unless stated:

| Measure | Result |
|---|---|
| Extraction | 138/138 indicators |
| Timeline | 100% recall, timestamps, order (36 cases) |
| Classification | category 18/18, severity 18/18 |
| Severity consistency | 6/6 incidents identical across 3 runs |
| ATT&CK (12 reports) | lenient recall 94%, precision 97%, forbidden 0 (17 in the answer keys) |
| Root cause | 18/18 cite the key's record |
| Citation correctness | 1401/1401 |
| Claims removed | 0/602; first drafts with problems 3/18, all fixed on retry |
| Recommendation relevance (proxy) | 80%; policy recall 85% |
| Completeness | 100%, except INC-003 listing no indicator (a defensible choice, below) |
| Traps (by hand, all runs) | 120/120 avoided |

Held-out test (3 incidents never used for tuning, rules frozen first): category, severity and root cause 3/3, traps 12/12. The 3 tuned incidents had scored category 2/3 and severity 2/3 before the prompt fixes.

Reviewer agent (Phase 8 reports): **28/29 planted errors caught** (entity swaps 6/6, statement swaps 12/12, certainty 10/11). Of 132 unmodified claims, 30 were flagged. My reading of those 30: 12 genuine certainty inflation, 9 true claims with incomplete citations, 6 nitpicks or false alarms, 3 unclear. The pre-registered prediction of at most 15% flagged failed, because the drafts were worse than the earlier checks could detect, not because the reviewer was noisy.

Fix and re-test (INC-002 and INC-004, one run each): flags on unmodified claims fell from 13 to 6 and certainty inflation from 7 to 1, while category, severity, root cause and citations held. Costs: 2 claims were now under-claimed (one rightly flagged by the reviewer, one I judge defensible); INC-004 again missed T1133, which the pre-fix Phase 7 run had also missed, so it is likely run-to-run variation; and the stricter rule appears to drop some findings rather than downgrade them.

Pre-registered predictions that failed are kept in `docs/results.md`: recommendation relevance above 80% (it was 80%), reviewer flags at most 15% (23%), and certainty plants caught 50-70% (91%).

A note on the answer keys: INC-003's key lists an IP as an indicator while also forbidding the claim that it is malicious. The model withheld it, because the notes say it may belong to the researcher who reported the exposure. That tension is in my key, not in the model's output.

## 13. Safety

- **Defensive only.** The system reads evidence and writes reports. It runs no scans, makes no network calls to evidence-derived addresses, and generates no exploit code.
- **No invented indicators.** An indicator survives only if extraction found it in the evidence; indicators the model names that are not in the evidence are defanged (`198[.]51[.]100[.]99`) in any logged text.
- **Uncertainty is explicit** and enforced: confirmed and probable need evidence, summary points must hedge when based on unconfirmed findings, and every report is marked "DRAFT: requires human review".
- **Untrusted output is escaped** in the PDF, so model text cannot inject formatting.
- **Synthetic data only**, including the company knowledge base.
- **Secrets.** The public demo cannot spend API credit: live generation needs both an environment flag and a key on the owner's machine. During development an API key was exposed twice in screenshots. Each time it was revoked and replaced, and the key is now loaded only from the macOS Keychain.

## 14. Limitations

- **Synthetic, self-authored data.** The incidents, the notes and the answer keys were written by the same author. The notes state key facts plainly, which makes several tests easy (for example milestone selection).
- **Same model family** for the generator, the reviewer, and the assistant used during development: shared blind spots are possible.
- **Small samples.** 6 incidents; most measurements are one run per incident; the fix was re-tested on 2 incidents once each.
- **Proxy measures.** Recommendation relevance checks that an action is tied to evidence, not that it is a good fix.
- **Not measured by code:** whether claims are true (traps and reviewer flags were judged by hand, by me), and durations written in prose.
- **Deviations from the spec:** no FastAPI backend (Streamlit only); BM25 instead of embeddings and a vector database; no SQLite or PostgreSQL storage (reports are JSON files); PDF and DOCX evidence not supported; mean time to resolve not computed (recovery is rarely dated in the evidence); one reviewer agent instead of eight; no MCP or threat-intelligence integrations; no evidence upload in the dashboard.

## 15. Future Improvements

1. **Real or independently written incidents,** for example adapted from public post-incident reports, with answer keys written by someone else.
2. **Repeated runs:** 3 or more per incident, to separate the certainty fix's effect from run-to-run variation.
3. **A reviewer from a different model family,** to reduce shared blind spots, and reviewer-assisted retries with the drafter.
4. **Check prose durations in code,** or forbid them in prose and point to the computed table.
5. **Evidence upload in the dashboard** with ingestion of PDF and DOCX files.
6. **An ATT&CK "why" check:** compare the chosen tactic with where the event sits in the timeline (initial access vs lateral movement).
7. **Embeddings only if the knowledge base grows** to the point where BM25 recall measurably drops.

## 16. Conclusion

The project shows a workable pattern for using an LLM where wrong answers are costly. Code owns the facts, the model writes only about cited records, and each layer of checking is measured by the failures it can and cannot catch. Code checks proved that every citation is real (1401/1401) and kept every invented indicator out. They could not see the subtler failure: correct quotes supporting overconfident claims. An independent reviewer agent found it, and a measured fix reduced it.

The most useful practices were not model choices but method: answer keys and traps written before runs, predictions written down and kept when they failed, held-out incidents, and reading the outputs rather than trusting the scores. Several of the most important findings came from my own mistakes in answer keys and scoring, and they are documented as such.

## 17. References

- NIST Special Publication 800-61 Revision 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management (2025).
- MITRE ATT&CK, Enterprise matrix, STIX bundle `enterprise-attack.json` (matrix modified 2026-07-31, spec 3.3.0). attack.mitre.org.
- Beyer, B. et al. (eds.), Site Reliability Engineering, O'Reilly (2016), chapter "Postmortem Culture: Learning from Failure".
- Robertson, S. and Zaragoza, H., The Probabilistic Relevance Framework: BM25 and Beyond, Foundations and Trends in Information Retrieval (2009).
- Anthropic API documentation, docs.claude.com.
- Project records: `docs/results.md` (every run, prediction and correction), `docs/architecture.md`, `docs/evaluation.md`.
- Libraries: Pydantic, Streamlit, Plotly, ReportLab, pytest.
