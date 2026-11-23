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
