# Results

## Run 1: first real-model run (2026-11-23)

- Model: `claude-sonnet-5-5`. Mode: prompt-JSON (after two failed API designs, see architecture.md).
- 3 synthetic incidents, one run each. Reports in `docs/sample_reports/run1/`.
- All 3 drafts passed validation on the first attempt (0 problems, 0 claims removed).
- Tokens per run: about 5.2k–6.1k input, 7.3k–8.4k output.

Scores below use the **corrected** ground truth and scorer (fixes listed underneath).

| | INC-001 phishing / account takeover | INC-002 macro malware | INC-003 public bucket |
|---|---|---|---|
| Category correct | yes | **no** (said phishing; truth malware) | yes |
| Severity correct | yes | yes | **no** (SEV2; truth SEV1, off by 1) |
| Root cause cites the right record | yes | yes | yes |
| Contributing-factor recall | 100% | 100% | 100% |
| Indicator recall / precision | 9/9, 100% | 6/6, 100% | 0/1, n/a (listed none) |
| Hallucination traps avoided (manual check) | 3/3 | 4/4 | 4/4 |

**Totals:** category 2/3, severity 2/3, root cause 3/3, traps avoided **11/11**.

### Model errors found by reading the reports

1. **INC-002 category.** The model wrote that email delivery "is not directly
   confirmed" and asked how the file was delivered, yet classified the incident
   as phishing. The classification contradicts its own findings. (This incident
   deliberately has no email evidence.)
2. **INC-002 executive summary overclaim.** The summary says the host "kept
   contacting the same external server until it was isolated"; the cited
   findings say continuity "is not established". The summary has no citations,
   so the validator does not check it. **This is a validator gap**, not just a
   prompt problem.
3. **INC-003 severity.** 41,200 customer records were downloaded by an
   unattributed external party; the model chose SEV2, partly because the bucket
   was closed 25 minutes after the report (the exposure lasted 4 days). Partly
   a design gap: no severity scale was given to the model.

### Errors that were ours, not the model's

1. INC-001 ground truth missed a malicious URL (`...reset?u=akhan`); the model
   listed it and was wrongly penalised (precision showed 89%).
2. INC-003 ground truth listed the victim's storage bucket as an "indicator of
   compromise", which the system can't (and shouldn't) list. Recall was capped
   at 50%.
3. Precision was shown as 0% when no indicators were listed; it is undefined.
4. Titles repeated the incident ID; free-text record IDs (`R012`) were neither
   readable nor validated.

### Changes made after run 1

- Ground truth and scorer fixed (above). Severity distance added (`severity_off_by`).
- Prompt: explicit SEV1–SEV4 scale; category must come from confirmed events;
  summary must not say more than the findings.
- Record IDs in free text are validated and converted to `file locator`.

### Caveat for any later run

The prompt changes were written **after seeing these three incidents fail**. A
better score on the same three incidents would partly reflect tuning to them,
not general improvement. A fair re-test needs incidents the prompt was not
tuned on (planned for the evaluation phase).

## Phase 5b: held-out test (rules fixed before running)

Three new incidents were written **after** the run-1 prompt fixes and have never
been shown to the model:

| ID | Scenario | Hardest traps |
|---|---|---|
| INC-2026-004 | Internet-exposed RDP brute force, then ransomware | Ransom note *claims* 200 GB stolen; no network evidence |
| INC-2026-005 | Departing employee uploads pipeline/pricing to personal cloud | Motive, competitor, deletion of copies all unknown |
| INC-2026-006 | Leaked contractor cloud key, self-granted admin, GPU instances | "No data was accessed" is unprovable (S3 read logging off) |

**Rules for this test:**
1. The prompt and validator are frozen at the commit that adds this section.
2. Each held-out incident is run once. Results are recorded as they come,
   including failures.
3. Ground truth may only be corrected if it is factually wrong about the
   evidence, and every correction is listed here with the reason.
4. No prompt changes are made because of these results until they are written
   down. Any later re-run is labelled as tuned.

Also new in 5b, applied to all incidents:
- The executive summary is a list of points; each names the findings it
  restates, and must hedge if any of them is not confirmed (checked in code).
- Ground truth can list acceptable alternative categories (INC-002 stays
  strict, so the run-1 miss is unchanged).
- Notes with a date heading ("Log date 2026-11-10") date their HH:MM lines from
  it, rolling to the next day past midnight.

## Run 2: held-out results (2026-11-23, recorded before any changes)

Model `claude-sonnet-5-5`, prompt-JSON mode, prompt frozen at commit `ea869bd`.
One run per incident. Reports in `docs/sample_reports/run2/`.

| | INC-004 ransomware | INC-005 insider | INC-006 cloud privilege escalation |
|---|---|---|---|
| Category | correct (ransomware) | correct (insider_threat) | correct via declared alternative (credential_compromise) |
| Severity | correct (SEV1) | correct (SEV2) | correct (SEV2) |
| Root cause cites the right record | yes | yes | yes |
| Contributing-factor recall | 100% | 100% | 100% |
| Indicator recall / precision | 4/4, 100% | 2/2, 100% | 1/1, 100% |
| Traps avoided (manual check) | 4/4 | 4/4 | 4/4 |
| Validation attempts | 1 | 2 (1 problem on attempt 1) | 2 (1 problem on attempt 1) |

**Held-out totals:** category 3/3, severity 3/3, root cause 3/3, traps **12/12**.
**Both runs:** traps avoided **23/23**.

Trap handling worth noting:
- INC-004: the ransom note's "200 GB stolen" claim was reported as `[unknown]`,
  citing the egress review and naming the unreviewed hosts.
- INC-006: the model did not claim exfiltration **and** did not claim "no data
  was accessed"; it said object reads "cannot be determined".

**Ground-truth corrections (rule 3):** INC-006 ground truth marked the root
cause and the `iam:*` factor as confirmed. The model marked both probable,
correctly: the evidence never states that the leaked key was the one used, or
that c.ng is in the contractors group. Both changed to probable. Scores are
unaffected (certainty is not scored).

**Gaps found in run 2:**
- The problems behind the two retries were not logged (only their count). Fixed
  after this run: every attempt's problems are now kept in the validation log.
- Timeline descriptions dropped alert names and event details (e.g. INC-006 EV004
  showed only `severity=high`). Fixed after this run.

**Limits of these results:**
- **Same-model-family bias.** The incidents and answer keys were written with
  Claude, and the reports are generated by Claude. High agreement may partly
  reflect shared assumptions. Incidents written independently (by another
  person, or adapted from public case studies) are needed.
- **One run each.** Run-to-run variation is not yet measured.
- **Six incidents, all synthetic.** These results show the pipeline behaves as
  designed on these cases, not that it is accurate on real incidents.

## Phase 6: knowledge base (RAG)

### Retrieval (no LLM, free to run: `python -m pmgen.kb --eval`)

Expected knowledge-base sections per incident were written into the ground
truth **before** retrieval was run. Measured mean recall over 6 incidents:

| Setting | Mean recall |
|---|---|
| BM25, top 6 sections | 76% |
| BM25, top 6, max 2 sections per document | 72% |
| BM25, top 8, max 2 per document | 81% |
| **BM25, top 8 (chosen)** | **84.7%** |

The per-document cap was expected to help (one playbook filled 4 of 6 slots for
INC-001) and made things worse, so it was dropped. Top-8 was chosen on these
same 6 incidents, so 84.7% is slightly optimistic. Still missed at top 8:
INC-001 `POL-12#3`, INC-003 `PB-05#2`, INC-006 `POL-12#2`.

### A/B test plan (written before running)

- Same prompt, same model, each of the 6 incidents run once **without** the
  knowledge base (`--no-rag`) and once **with** it: `bash scripts/ab_test.sh`.
- Compared: category, severity, root cause, contributing factors, indicators,
  claims removed, **policy recall** (expected sections cited in actions or
  lessons) and **actions with a policy citation**. Traps checked by hand in all
  12 reports.
- What counts as RAG helping: higher policy recall and policy-backed actions
  **without** any drop in the other scores or any new trap failure.
- Not held out: INC-004–006 were already run once. Both arms are equally
  affected, so the comparison is fair, but absolute scores are not a fresh test.
- Expected cost at $2 / $10 per million tokens: about $1–1.50 for all 12 runs.

### A/B results (2026-11-23, one run per incident per arm)

Reports: `docs/sample_reports/ab/`. Summary table: `docs/sample_reports/ab/ab_summary.md`.

| Mean over 6 incidents | Without RAG | With RAG |
|---|---|---|
| Category / severity / root cause / contributing factors | 100% | 100% |
| Indicator recall | 67% | 100% |
| Claims removed by validator | 0 | 0 |
| Traps avoided (manual) | 23/23 | 23/23 |
| Policy recall | 0% (by construction) | 85% |
| Corrective actions citing a policy | 0% (by construction) | 95% |

**Reading the numbers honestly**
- The two policy metrics are 0% without RAG by design (there is nothing to
  cite). They show the citations happen, not that the content is better.
- INC-002 category and INC-003 severity, both missed in run 1, are now correct
  in both arms. That is the effect of the post-run-1 prompt rules, not RAG.
- The indicator difference (INC-003 and INC-005 listed no indicators without
  RAG) is a single run per arm and may be run-to-run noise.

**What RAG changed in the content (manual review)**
- INC-004: noticed a past review (PIR-2025-031) had already agreed the
  exception-expiry fix and the same failure recurred; added "restore only after
  the entry point is closed" (PB-02 §5).
- INC-005: flagged that the laptop was collected after the interview, against
  the insider playbook (PB-05 §3). Absent without RAG.
- INC-006: "treat data as potentially exposed" when reads cannot be ruled out
  (PB-04 §4), where the no-RAG report only said "unknown".
- Recommendations cite concrete rules ("audit mode at most 30 days",
  POL-12 §5) instead of generic advice, so they can be checked against policy.

**Where RAG was weak**
- Policy-citation fit (my judgement): 31 of 33 citations apply; 2 are weak
  (INC-002 cites PIR-2025-014's alert-delay lesson for an EDR backlog; INC-001
  cites PB-01 §1 "triggers" for a triage-correlation lesson).
- Retrieval misses show in the output: INC-006's paging action has no policy
  citation because POL-12 §2 was not retrieved.

**Problems seen in both arms: certainty drift between runs**
- INC-006 (RAG): `iam:*` factor marked confirmed; run 2 correctly said probable.
- INC-005 (no RAG): uploaded files stated as confirmed to be the exports; only
  file names match.
- INC-004 (RAG): summary says locker.exe "encrypted files", an inference inside
  findings the model labelled confirmed, which the hedge check cannot see.
- One run per arm cannot separate RAG effects from this variation. Repeated
  runs per incident are needed before claiming any accuracy difference.

**Validator in action:** the no-RAG INC-006 draft first stated a probable and an
unknown finding as fact in the summary; both were caught, logged with details,
and fixed on retry.

**Conclusion:** RAG made recommendations more specific, auditable and
occasionally more insightful, with no loss of accuracy or trap safety. It did
not make the analysis more correct; the core scores were already at ceiling.

## Phase 7: MITRE ATT&CK mapping

### Answer key (written before any mapping run)

Each ground truth lists **required** techniques (the original lists from Phase 1),
**acceptable** extras (defensible, not required, not penalised) and **forbidden**
techniques (plausible-sounding but unsupported by the evidence; a forbidden
parent also forbids its sub-techniques). All IDs were checked against the
official catalogue.

| Incident | Forbidden (traps) | Why |
|---|---|---|
| INC-001 | T1213, T1110 | SharePoint access never checked; no brute force |
| INC-002 | T1566, T1021, T1041, T1567, T1486 | no email evidence; no lateral movement, exfiltration or encryption seen |
| INC-003 | T1078, T1537 | downloads were anonymous; no transfer to another cloud account |
| INC-004 | T1041, T1048, T1567, T1003 | 200 GB theft is only the ransom note's claim; no credential dumping seen |
| INC-005 | T1078.004, T1566 | insider on a managed laptop, not an account takeover |
| INC-006 | T1530, T1537 | S3 object reads cannot be confirmed |

### Rules for the run
- The model gets **no technique list** (it would leak the answer key). It maps
  from its own knowledge; code rejects IDs that are invented, revoked or
  deprecated in the official catalogue and fills in names and tactics.
- A test fails if any required, acceptable or forbidden ID appears anywhere in
  the prompt or schema. (This caught a real leak while building: the schema's
  example ID was T1059.001, one of INC-002's answers. Replaced with T1012.)
- Metrics: strict recall (exact ID), lenient recall (parent or sub-technique
  accepted), precision (required or acceptable, lenient), forbidden hits,
  mappings removed by the validator. Every extra technique is reviewed by hand
  before it is counted as an error.
- Not held out: the incidents have been run before (not for ATT&CK). The
  answer key for ATT&CK was fixed before this run.

### Phase 7 results (2026-11-23, one run per incident, with RAG)

Reports: `docs/sample_reports/phase7/`.

| Incident | Strict recall | Lenient recall | Precision (scored) | Forbidden hits | Missed |
|---|---|---|---|---|---|
| INC-001 | 3/3 | 3/3 | 100% | 0 | - |
| INC-002 | 5/5 | 5/5 | 100% | 0 | - |
| INC-003 | 1/1 | 1/1 | 100% | 0 | - |
| INC-004 | 4/5 | 4/5 | 100% | 0 | T1133 |
| INC-005 | 1/1 | 1/1 | 100% | 0 | - |
| INC-006 | 3/4 | 3/4 | 100% | 0 | T1496 |
| **Mean** | **92%** | **92%** | **100% (scored)** | **0** | |

No mapping was removed by the validator (every ID was a current ATT&CK
technique). All 26 forbidden (trap) techniques were avoided, including T1566
for INC-002 (no email evidence) and T1041/T1567 for the ransom note's
unverified theft claim. Text traps: 23/23 again (92/92 across all runs).

**Manual review of the misses and of "precision 100%"**
- **INC-004, T1133 missed: a real model error that the answer key partly hid.**
  The model mapped the attacker's internet RDP logon as T1021.001 Remote Desktop
  Protocol (lateral movement), while its own rationale says "from the internet",
  which is T1133 External Remote Services (initial access). T1021.001 was in the
  acceptable list (intended for internal RDP), so it scored as correct.
  **True precision is below 100%.** Lesson: an "acceptable" list cannot check
  *why* a technique was chosen.
- **INC-006, T1496 missed: arguable.** Four GPU instances launched with a stolen
  key is the usual resource-hijacking pattern, but the evidence does not show
  what they were used for, and the model listed that as an open question. Kept
  as a miss (the answer key was fixed before the run).

**Other findings**
- **Validator bug (fixed):** INC-003's quote `"Principal":"*"` was wrongly
  rejected because nested JSON stores its quotes escaped (`\"`). It cost one retry
  and could have dropped a correct claim. Fixed and covered by a regression test.
- **Certainty drift, third time:** INC-006 again labels the `iam:*` factor
  "confirmed" (the evidence never states c.ng is in that group) and states it as
  fact in the summary. Because the model's own label says confirmed, the hedge
  check cannot see it. This is now the most consistent weakness.
- Cost: 6 runs at about $0.10 each.

## Phase 8 pre-registration (written before any API run)

Answer key added to every `ground_truth.json` before running the model:

- `response_milestones`: acceptable source records for each of the 4 milestones.
  All 6 x 4 map to real timeline events (enforced by a test).
- `impact`: required, acceptable and forbidden systems/accounts. Forbidden traps:
  INC-001 `a.khan` (targeted, not compromised) and `SharePoint` (only suspected).

Metrics: milestone accuracy (share of the 4 that match), systems/accounts recall
and precision, scope forbidden hits, immediate cause present.

Predictions (to be checked, not tuned against):

- Most likely milestone error: `response_start`. INC-002, INC-004 and INC-006
  notes show an alert sat untriaged; the model may pick the alert, or the
  containment action, instead of the pickup.
- INC-005: the DLP alert and the upload are merged into one event (EV004), so
  attack start may equal first detection; time to detect 0s is then correct by
  construction, not a finding.
- INC-003: durations will be marked approximate (researcher email has no timezone).
- Scope: expect at least one extra system (e.g. a responder tool or the attacker
  domain) to lower precision; expect 0 forbidden hits.

Pass bar: mean milestone accuracy >= 75%, 0 scope forbidden hits, traps still all
avoided. Cost: 6 runs, about $0.60.

## Phase 8 results (run 2026-11-24, 6 incidents, 1 run each, with RAG)

| Incident | Milestones | Detect | Respond | Contain | Systems R/P | Accounts R/P | Forbidden |
|---|---|---|---|---|---|---|---|
| INC-001 | 4/4 | 9m 58s | 28m~ | 34m~ | 100/100 | 100/100 | 0 |
| INC-002 | 4/4 | 22s | 2h 27m~ | 2h 34m~ | 100/100 | 100/100 | 0 |
| INC-003 | 4/4 | 3d 18h 27m~ | 25m~ | 25m~ | 100/100 | n/a/100 | 0 |
| INC-004 | 4/4 | 51m 58s | 18m 55s~ | 24m 55s~ | 100/100 | 100/100 | 0 |
| INC-005 | 4/4 | 19m 22s | 16h 53m~ | 22h 18m~ | n/a/**50** | 100/100 | 0 |
| INC-006 | 4/4 | 50s | 44m 30s~ | 49m 30s~ | n/a | 100/100 | 0 |

`~` = approximate (inferred date or assumed timezone). Durations computed by code.

- **Pass bar met:** milestone accuracy 100% (bar 75%), 0 scope forbidden hits.
- **Traps:** 24/24 avoided, checked by hand against each report (116/116 across all runs).
- **Validation:** 5 of 6 passed first try. INC-005 needed one retry: a summary
  point stated a probable finding as fact; the hedge check caught it and the retry fixed it.

**Why 100% milestone accuracy is weak evidence**
- I wrote the data and the answer key. The notes say "picked up" / "isolated" in
  plain words, so choosing the events is easy. Real notes are messier.
- Several milestones accept 2-3 events.
- One run each: no evidence about stability yet.

**Prediction check**
- Wrong: I predicted `response_start` would be the main error. It was 6/6 right.
- Wrong: I predicted INC-005 time to detect could be 0s. The model chose the CRM
  export (16:02) as attack start, which is the better choice (19m 22s).
- Right: INC-003 durations marked approximate; 0 forbidden hits.
- Partly right: one extra system lowered precision (INC-005), but it was my error (below).
- Judgement call: INC-003 attack start = the misconfiguration (14 Sep), not the
  first outside read (17 Sep). So "3d 18h to detect" means time from exposure, not
  from attacker activity. Both are accepted by the key.

**Answer-key correction (made after the run, disclosed)**
- INC-005: the model listed `upload.personal-cloud.test` as a system involved. My
  prompt defines systems as anything "the insider used" or "that held affected
  data", which this site meets. The key left it out. It is now in
  `systems_acceptable`. Pre-registered score: precision 50%; corrected: 100%.

**Pattern the numbers show (by design of the synthetic data, not a discovery)**
- Detection is fast; pickup is slow. INC-002: alert in 22s, picked up after 2h 27m.
  INC-005: 19m to the DLP alert, 16h 53m to review. This shows the tool measures the
  delay correctly, not that real SOCs behave this way.

**Quality notes from reading the reports**
- INC-004 now maps T1133 (External Remote Services), the Phase 7 miss, but still
  also maps internet RDP as T1021.001 (lateral movement): tactic confusion remains.
- INC-006 "certainty drift": see the correction below; it was my misdiagnosis.
- INC-006 under-claims once: "leaked key found only during the response" is
  labelled probable, but the notes state it.
- INC-005 adds a useful, grounded lesson: the interview came before device
  collection, against the insider playbook.
- Cost: about $0.12-0.13 per run (longer output; INC-006 ~10.6k output tokens).

## Correction: the INC-006 "certainty drift" was my misdiagnosis (2026-11-24)

Checked all 5 saved INC-006 reports side by side (Phase 6-8, with and without RAG).

- Every report that labels the `iam:*` claim **confirmed** states only what
  ir_notes.txt line 7 says: the contractors-group policy grants `iam:*`, so any
  member could attach AdministratorAccess. That is a correct label.
- Every report that adds the link "c.ng is in that group" labels it **probable**
  and says the membership is not stated. Also correct.
- So the runs differ in *which claim they make*, not in certainty for the same
  claim. Earlier write-ups (Phase 6/7) called this the most consistent weakness;
  that was wrong. The answer key's single "probable" root cause bundles the leaked
  key (inferred) with the `iam:*` policy (stated), so it penalised a correct split.
- Remaining, smaller issue: the reports leave the c.ng-to-group link implicit
  instead of listing it as an open question (one report did).

**Proposed fix tested offline and rejected.** A code check that a confirmed claim
naming an account/host/IP must cite a record mentioning it was run over 30 saved
reports (294 confirmed claims). It fired 4 times: 3 false positives (the host name
is in the EDR file header, not in each event) and 1 minor citation gap (INC-001
cited a.khan's email row for a claim about j.patel). It would not have caught the
INC-006 pattern at all. Not worth adding.

## Phase 9: validation (2026-11-24)

**Two claim-level checks tested offline on 30 saved reports, both rejected:**

| Check | Claims checked | Flagged | True problems found |
|---|---|---|---|
| Confirmed claim names an account/host/IP not in its cited records | 294 | 4 | 1 minor citation gap |
| Number in a claim not in its cited records | 419 | 56 | 0 in a manual spot check |

- The number check flags correct text: dates reformatted ("14 Sep" vs
  2026-09-14), units ("24 hours" vs "24h") and gaps the model computed itself
  ("about 45 minutes later").
- That exposed a gap in an earlier claim: "the LLM never does time arithmetic" is
  true only for the Response analysis table. Every prose duration spot-checked was
  correct (e.g. 01:13 to 01:58 = 45 min; 23:34:10 to 23:36:40 = 2.5 min), but none
  are verified by code.

**Built instead:** `pmgen.verify`, an independent re-check of saved reports
(8 checks, 16 tests, each check mutation-tested: disabling it fails a test).

**Pre-registered prediction for the 6 Phase 8 JSON reports:** all pass with 0
failures. Any failure means a bug in the validator or the verifier, not the model,
because these checks repeat what the validator already enforced.

**Phase 9 result (run 2026-11-24):** prediction held. 6/6 Phase 8 reports pass,
718 items checked, 0 failures, 0 claims removed during generation. This confirms
the saved reports are consistent with their evidence; it is not new evidence of
report quality (that is the Phase 8 scoring and trap checks).
