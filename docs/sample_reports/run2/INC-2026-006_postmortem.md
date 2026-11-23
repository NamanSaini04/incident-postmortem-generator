# Incident Postmortem: INC-2026-006: Leaked contractor access key used for self-granted admin rights and GPU instance launch

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-006 |
| Category | credential_compromise |
| Severity | SEV2 |
| Classification confidence | 80% |
| Generated | 2026-11-23 19:49 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

The c.ng account was used from an IP never seen before for it to attach AdministratorAccess to itself, create an access key for svc.reporting, list buckets and launch four GPU instances. The root cause was probably c.ng's long-lived access key, which secret scanning found in a public repository commit dated 2026-10-30. The link between the leaked key and the malicious use is not confirmed. A CI deploy policy on the contractors group granting iam:* probably allowed the self-escalation. c.ng's group membership is not explicitly confirmed. Contractor users were allowed long-lived keys, and c.ng's key was 400 days old. The admin-policy alert went to email only, and on-call was paged only after the later GPU launch alert. cloud.secops deactivated the keys, detached the admin policy and terminated the four instances. S3 data-event logging was not enabled, so S3 object reads cannot be ruled out. It is not confirmed whether any objects were read, and this remains an open question.

**Severity rationale:** Confirmed compromise of the c.ng cloud account with attacker-style activity: self-attached AdministratorAccess (cloudtrail.json Records[2]), a new access key for svc.reporting (cloudtrail.json Records[3]) and four p4d.24xlarge instances (cloudtrail.json Records[5]). It was contained by cloud.secops (cloudtrail.json Records[6], cloudtrail.json Records[7], cloudtrail.json Records[8]). Management events show only ListBuckets (ir_notes.txt line 10), and no exposure of sensitive data is confirmed. S3 data-event logging was off, so object reads cannot be ruled out (ir_notes.txt line 10). SEV1 would apply if such reads were later confirmed.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| EV001 | 2026-11-01 15:40:00 | eventName=DescribeInstances; userName=c.ng | exact | [E1] |
| **EV002** | **2026-11-02 01:12:40** | **eventName=GetCallerIdentity; userName=c.ng** | exact | [E2] |
| **EV003** | **2026-11-02 01:13:05** | **eventName=AttachUserPolicy; userName=c.ng** | exact | [E3] |
| **EV004** | **2026-11-02 01:13:30** | **severity=high** | exact | [E4] |
| **EV005** | **2026-11-02 01:14:20** | **eventName=CreateAccessKey; userName=c.ng** | exact | [E5] |
| **EV006** | **2026-11-02 01:16:02** | **eventName=ListBuckets; userName=c.ng** | exact | [E6] |
| **EV007** | **2026-11-02 01:21:47** | **eventName=RunInstances; userName=c.ng** | exact | [E7] |
| **EV008** | **2026-11-02 01:50:12** | **severity=high** | exact | [E8] |
| **EV009** | **2026-11-02 01:58:00** | **01:58 On-call paged by the GPU launch alert. The admin-policy alert at 01:13 went to email only.** | date inferred | [E9] |
| **EV010** | **2026-11-02 02:03:00** | **02:03 Deactivated both access keys for c.ng and the new key created for svc.reporting.** | date inferred | [E10] |
| EV011 | 2026-11-02 02:03:10 | eventName=UpdateAccessKey; userName=cloud.secops | exact | [E11] |
| **EV012** | **2026-11-02 02:04:00** | **eventName=DetachUserPolicy; userName=cloud.secops** | exact | [E12] |
| EV013 | 2026-11-02 02:06:00 | 02:06 Terminated the 4 GPU instances. | date inferred | [E13] |
| **EV014** | **2026-11-02 02:06:30** | **eventName=TerminateInstances; userName=cloud.secops** | exact | [E14] |
| **EV015** | **2026-11-02 03:10:00** | **03:10 Secret scanning found c.ng's access key in a public code repository commit dated 2026-10-30.** | date inferred | [E15] |

## 3. What happened

- **[confirmed]** c.ng normally works from 192.0.2.80. The IP 198.51.100.77 had not been seen before for this account. [E16]
- **[confirmed]** From 198.51.100.77, using python-boto3, c.ng ran GetCallerIdentity and then attached the AdministratorAccess policy to its own user (EV002, EV003). [E2][E3]
- **[confirmed]** Using c.ng, the actor created a new access key for the svc.reporting user (EV005). [E5]
- **[confirmed]** The same session ran ListBuckets and then RunInstances for 4 p4d.24xlarge GPU instances (EV006, EV007). [E6][E7]
- **[confirmed]** A high-severity admin-policy alert fired at EV004 but went to email only. On-call was paged only after the GPU launch alert (EV008, EV009). [E4][E8][E9]
- **[confirmed]** Responders deactivated the access keys (c.ng and the new svc.reporting key), detached AdministratorAccess from c.ng and terminated the four GPU instances (EV010-EV014). [E10][E12][E14]
- **[confirmed]** Secret scanning found c.ng's access key in a public code repository commit dated 2026-10-30, before the malicious activity (EV015). [E15]
- **[probable]** The activity was probably unauthorized use of c.ng's credential, likely the key exposed in the public repository. The evidence does not record which key was used or directly link the leaked key to the session. [E15][E16]
- **[unknown]** Whether any S3 object data was read cannot be determined. Management events show only ListBuckets, and data-event logging was off. [E17]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `198.51.100.77` | ip | [E4] |

## 5. Root cause

**[probable]** A long-lived c.ng access key was probably exposed in a public code repository commit and then used from an unfamiliar IP. The leaked key was probably the entry point, but the evidence does not confirm which key was used or that the repository exposure was the source. [E15][E16]

### Contributing factors

- **[probable]** The CI deploy policy attached to the contractors group granted iam:*, so a member could attach AdministratorAccess to itself. c.ng did exactly that. c.ng's membership in that group is not explicitly stated, hence probable. [E3][E18]
- **[confirmed]** Long-lived access keys were allowed for contractor users, and c.ng's key was 400 days old. [E19]

## 6. Detection gaps

- **[confirmed]** The admin-policy alert was routed to email rather than paging. On-call was engaged only by the later GPU launch alert. [E9][E20]
- **[confirmed]** S3 data-event logging was not enabled, so object reads cannot be ruled out. [E17]
- **[probable]** The exposed key was found in the public commit only during incident response, after the 2026-10-30 commit. No earlier detection of the leak is recorded. [E15]

## 7. Lessons learned

**Process**
- Long-lived keys that are never rotated stay valid long after being committed to code. [E15][E19]

**Technology**
- A high-impact IAM change such as attaching AdministratorAccess must page on-call. Email-only routing delayed engagement until a secondary alert fired. [E20]
- Without S3 data-event logging, responders cannot say whether data was accessed. [E17]

**Governance**
- Broad permissions such as iam:* on a CI deploy policy shared by a contractor group allow trivial self-escalation. [E18]

## 8. Corrective actions

| Priority | Action | Why | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|
| critical | Remove iam:* from the CI deploy policy on the contractors group and scope it to the specific actions the pipeline needs. Consider permission boundaries that block self-attachment of administrative policies. | A group member could attach AdministratorAccess to itself, and c.ng did so. [E18] | Cloud security / IAM | Immediately (days) | Blocks self-escalation by a single compromised contractor credential. |
| high | Route admin-policy attachment alerts to paging, not email only. | The admin-policy alert went to email, and on-call was engaged only by the later GPU launch alert. [E9][E20] | Security operations | 1 week | Earlier response to privilege escalation. |
| high | Disallow or time-limit long-lived access keys for contractor users. Enforce rotation and prefer short-lived credentials. | Contractor users may hold long-lived keys, and the c.ng key was 400 days old. [E19] | Cloud security / IAM | 30 days | Limits the usable lifetime of any leaked key. |
| high | Enable S3 data-event logging, at least for sensitive buckets. | Object reads cannot be ruled out without data-event logs. [E17] | Cloud platform | 2 weeks | Allows data-access scoping in future incidents. |
| high | Remove the exposed key from the public repository history and rotate any other credentials in it. Add push-time secret scanning and alerting so leaked keys are caught when committed. | The key sat in a public commit from 2026-10-30 until it was found during response. [E15] | Application security / Engineering | 1-2 weeks | Shortens exposure time for committed secrets. |
| medium | Audit svc.reporting and the keys and policies for any other principals touched in this window. Confirm the newly created svc.reporting key remains inactive or is deleted. | A new key was created for svc.reporting using the compromised account. [E5][E10] | Cloud security / IAM | Immediately | Closes a possible persistence path. |

## 9. Open questions and remaining risks

- **Open:** Who committed the key to the public repository, and how? (ir_notes.txt line 11: unknown who committed the key.)
- **Open:** Which of c.ng's two access keys was exposed and used from 198.51.100.77? Is it the same key found in the repository?
- **Open:** Is c.ng a member of the contractors group that carries the iam:* policy?
- **Open:** Was the new svc.reporting key used before it was deactivated?
- **Open:** Were any S3 objects read? The logs cannot answer this.
- **Open:** Did the actor take any other actions not visible in the exported management events?
- **Risk:** Possible undetected S3 object reads, because data events were not logged.
- **Risk:** Other secrets may remain in the public repository history.
- **Risk:** Other contractor accounts may hold long-lived keys and the same iam:* path until remediated.

## 10. Validation log

- attempt 1: 1 validation problem(s)
- attempt 2: 0 validation problem(s)

## Evidence index

| Ref | File | Location | Quote |
|---|---|---|---|
| E1 | cloudtrail.json | Records[0] | 2026-11-01T15:40:00Z |
| E2 | cloudtrail.json | Records[1] | 2026-11-02T01:12:40Z |
| E3 | cloudtrail.json | Records[2] | 2026-11-02T01:13:05Z |
| E4 | cloud_alerts.csv | row 1 | 2026-11-02T01:13:30Z |
| E5 | cloudtrail.json | Records[3] | 2026-11-02T01:14:20Z |
| E6 | cloudtrail.json | Records[4] | 2026-11-02T01:16:02Z |
| E7 | cloudtrail.json | Records[5] | 2026-11-02T01:21:47Z |
| E8 | cloud_alerts.csv | row 2 | 2026-11-02T01:50:12Z |
| E9 | ir_notes.txt | line 3 | 01:58 |
| E10 | ir_notes.txt | line 4 | 02:03 |
| E11 | cloudtrail.json | Records[6] | 2026-11-02T02:03:10Z |
| E12 | cloudtrail.json | Records[7] | 2026-11-02T02:04:00Z |
| E13 | ir_notes.txt | line 5 | 02:06 |
| E14 | cloudtrail.json | Records[8] | 2026-11-02T02:06:30Z |
| E15 | ir_notes.txt | line 6 | 03:10 |
| E16 | ir_notes.txt | line 12 | c.ng normally works from 192.0.2.80; 198.51.100.77 has not been seen before for this account. |
| E17 | ir_notes.txt | line 10 | S3 data-event logging is not enabled, so object reads cannot be ruled out. |
| E18 | ir_notes.txt | line 7 | grants iam:* so any member could attach AdministratorAccess to themselves |
| E19 | ir_notes.txt | line 9 | c.ng's key was 400 days old |
| E20 | ir_notes.txt | line 8 | the admin-policy alert is routed to email, not paging |

**Evidence file hashes (SHA-256)**

- `cloud_alerts.csv`: `31f9d2354e94899f667d461a8b620734b193cd5d7ec840703351c3036b2ca4be`
- `cloudtrail.json`: `127fe8b88d48016fb651c9a36102901b5f69f6d12907b3134b35dd9a99de3740`
- `ir_notes.txt`: `e981b3f3916a1158dd66157678ec5ee25f120976efde81cdd115b6efc229e3e9`
