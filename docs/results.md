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
