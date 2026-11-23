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
