# Incident Postmortem: INC-2026-006: Contractor access key exposed in a public repository, used for admin self-escalation and GPU instance launch

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-006 |
| Category | credential_compromise |
| Severity | SEV2 |
| Classification confidence | 80% |
| Generated | 2026-11-23 20:18 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

c.ng's access key was used from an IP not previously seen for the account. The activity included attaching AdministratorAccess to c.ng, creating a key for svc.reporting, and launching 4 p4d.24xlarge GPU instances. c.ng's access key was found in a public repository commit dated 2026-10-30. The key was probably the way the actor obtained access, but the link is not confirmed and who committed it is unknown. The contractors-group CI deploy policy granted iam:*, which probably let a member such as c.ng attach AdministratorAccess to themselves. That c.ng is a contractor user is inferred, not confirmed. The key was also a 400-day-old long-lived key. The admin-policy alert went to email only. On-call was paged only for the GPU alert, about 45 minutes after the admin-policy alert. Keys were deactivated, the admin policy was detached and the GPU instances were terminated by about 02:06. It is not confirmed whether any S3 objects were read. Data-event logging was not enabled, so reads may have occurred and cannot be ruled out.

**Severity rationale:** The c.ng account was used from a never-before-seen IP to attach AdministratorAccess, create a new access key for svc.reporting and launch 4 GPU instances. Responders deactivated the keys, detached the policy and terminated the instances within about 50 minutes of the first alert. Large-scale sensitive data exposure is not confirmed. Object reads cannot be ruled out because S3 data-event logging was off, but only ListBuckets is recorded.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| EV001 | 2026-11-01 15:40:00 | eventName=DescribeInstances; userName=c.ng | exact | [E1] |
| **EV002** | **2026-11-02 01:12:40** | **eventName=GetCallerIdentity; userName=c.ng** | exact | [E2] |
| **EV003** | **2026-11-02 01:13:05** | **eventName=AttachUserPolicy; userName=c.ng** | exact | [E3] |
| **EV004** | **2026-11-02 01:13:30** | **alert=Admin policy attached to user; severity=high** | exact | [E4] |
| **EV005** | **2026-11-02 01:14:20** | **eventName=CreateAccessKey; userName=c.ng** | exact | [E5] |
| EV006 | 2026-11-02 01:16:02 | eventName=ListBuckets; userName=c.ng | exact | [E6] |
| **EV007** | **2026-11-02 01:21:47** | **eventName=RunInstances; userName=c.ng** | exact | [E7] |
| **EV008** | **2026-11-02 01:50:12** | **alert=Anomalous GPU instance launch; severity=high** | exact | [E8] |
| **EV009** | **2026-11-02 01:58:00** | **01:58 On-call paged by the GPU launch alert. The admin-policy alert at 01:13 went to email only.** | date inferred | [E9] |
| **EV010** | **2026-11-02 02:03:00** | **02:03 Deactivated both access keys for c.ng and the new key created for svc.reporting.** | date inferred | [E10] |
| EV011 | 2026-11-02 02:03:10 | eventName=UpdateAccessKey; userName=cloud.secops | exact | [E11] |
| EV012 | 2026-11-02 02:04:00 | eventName=DetachUserPolicy; userName=cloud.secops | exact | [E12] |
| EV013 | 2026-11-02 02:06:00 | 02:06 Terminated the 4 GPU instances. | date inferred | [E13] |
| **EV014** | **2026-11-02 02:06:30** | **eventName=TerminateInstances; userName=cloud.secops** | exact | [E14] |
| **EV015** | **2026-11-02 03:10:00** | **03:10 Secret scanning found c.ng's access key in a public code repository commit dated 2026-10-30.** | date inferred | [E15] |

## 3. What happened

- **[confirmed]** Earlier activity for c.ng came from 192.0.2.80, the account's normal location. This is the baseline against which the later activity was anomalous. [E1][E16]
- **[confirmed]** At EV002, c.ng's credentials were used from 198.51.100.77 via python-boto3, starting with GetCallerIdentity. This IP had not been seen before for this account. [E2][E16]
- **[confirmed]** The c.ng session attached the AdministratorAccess policy to c.ng itself (EV003). [E3]
- **[confirmed]** The c.ng session then created an access key for the svc.reporting user (EV005) and listed buckets (EV006). [E5][E6]
- **[confirmed]** The c.ng session launched 4 p4d.24xlarge instances (EV007). [E7]
- **[confirmed]** A high-severity admin-policy alert fired at EV004 but went to email only. A GPU launch alert fired at EV008, and on-call was paged for that alert at EV009. [E4][E8][E9]
- **[confirmed]** Containment: the secops user deactivated c.ng's key (EV011), detached AdministratorAccess (EV012) and terminated the 4 instances (EV014). The notes say the new svc.reporting key was also deactivated. [E10][E11][E12][E14]
- **[confirmed]** Secret scanning found c.ng's access key in a public code repository commit dated 2026-10-30, before the 2026-11-02 activity. [E15]
- **[unknown]** Whether any S3 data was read cannot be determined. Management events show only ListBuckets, but data-event logging was off. [E17]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `198.51.100.77` | ip | [E4] |

## 5. Root cause

**[probable]** Probably the actor used c.ng's long-lived access key, which had been committed to a public repository, and then used overly broad IAM permissions to escalate to admin. The key's exposure in the repository is confirmed. That the actor obtained the key from there is inferred from timing and not confirmed. [E2][E15][E18]

### Contributing factors

- **[probable]** The CI deploy policy attached to the contractors group granted iam:*, so any member could attach AdministratorAccess to themselves. c.ng appears to be a contractor user, which is inferred from the key finding. [E18][E19]
- **[confirmed]** Long-lived access keys were allowed for contractor users, and c.ng's key was 400 days old. [E19]

## 6. Detection gaps

- **[confirmed]** The admin-policy alert was routed to email, not paging. On-call was paged only at 01:58 by the later GPU alert, about 45 minutes after the admin-policy alert at 01:13. [E9][E20]
- **[confirmed]** S3 data-event logging is not enabled, so object access cannot be assessed. [E17]
- **[confirmed]** The key was exposed in a public repository on 2026-10-30. Secret scanning found it only at 03:10 on 2026-11-02, after the incident was under way. [E15]

## 7. Lessons learned

**Process**
- Long-lived keys that are never rotated extend the window in which a leaked credential stays usable. Here the key was 400 days old and a commit exposed it publicly. [E15][E19]

**Technology**
- Creating a new access key for another user and attaching an admin policy are high-risk IAM events. Alerts for them must page, because the admin-policy alert sat in email while the actor continued. [E5][E20]
- Without S3 data-event logging, responders cannot say whether data was read, which leaves scoping uncertain. [E17]

**Governance**
- Broad IAM permissions such as iam:* in a CI policy shared by a contractors group let a single leaked key become full admin. [E18]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Route IAM privilege-change alerts (admin policy attached, access key created for another user) to the paging system with a short response SLA. | The admin-policy alert went to email only, and paging happened about 45 minutes later from a different alert. [E9][E20] | - | Cloud security / SecOps | 1 week | Faster response to privilege escalation, before resources are launched or other keys are created. |
| critical | Remove iam:* from the contractors-group CI deploy policy and replace it with least-privilege permissions. Consider permission boundaries that block self-attachment of admin policies. | Any group member could attach AdministratorAccess to themselves. [E18] | - | Cloud platform / IAM | 1 week | A leaked contractor key can no longer escalate itself to admin. |
| high | Disallow long-lived access keys for contractor users in favour of short-lived credentials, and rotate or remove all existing long-lived keys. Rotate any key committed to a repository. | c.ng's 400-day-old key was found in a public commit and used from an unseen IP. [E15][E19] | - | Cloud platform / IAM | 30 days | Shorter usable lifetime of any leaked credential. |
| high | Enable S3 data-event logging for sensitive buckets. | Object reads could not be ruled out for this incident. [E17] | - | Cloud security | 30 days | Ability to scope data exposure in future incidents. |
| high | Add pre-commit and push-time secret scanning for repositories, and continuous scanning of public repositories, with automatic key revocation on detection. Audit the activity of the svc.reporting key created during the incident. | The key sat in a public commit from 2026-10-30 and was found only after the incident began. [E5][E15] | - | AppSec / Developer tooling | 30 days | Leaked keys are caught and revoked before they are used. |

## 9. Open questions and remaining risks

- **Open:** Who committed the key to the public repository? The notes list this as unknown.
- **Open:** Did the actor obtain the key from the public repository? Timing suggests so, but it is not confirmed.
- **Open:** Were any S3 objects read? Data-event logging was off, so this cannot be determined.
- **Open:** Was the svc.reporting key created at 01:14 ever used before it was deactivated? No usage records are in the evidence.
- **Open:** Was there other activity by c.ng or the actor between the 2026-10-30 commit and 2026-11-02 01:12? The evidence contains no records for that period beyond one DescribeInstances event on 2026-11-01.
- **Open:** Has the key been removed from the repository history and fully revoked? The evidence shows deactivation but not repository cleanup.
- **Open:** Is c.ng a member of the contractors group? This is inferred from the contractor key finding and not stated directly.
- **Risk:** Possible undetected S3 object reads.
- **Risk:** Other credentials may exist in public repositories that have not been scanned.
- **Risk:** The contractors-group iam:* policy remains until it is corrected.

## 10. Validation log

- attempt 1: 2 validation problem(s)
- attempt 1 problem: summary_points[2]: summary point states a probable finding as fact; hedge it (e.g. 'probably', 'may', 'not confirmed'): 'The contractors-group CI deploy policy granted iam:*, which let a member attach '
- attempt 1 problem: summary_points[5]: summary point states a unknown finding as fact; hedge it (e.g. 'probably', 'may', 'not confirmed'): 'Whether any S3 objects were read is not determinable, because data-event logging'
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
| E16 | ir_notes.txt | line 12 | c.ng normally works from 192.0.2.80 |
| E17 | ir_notes.txt | line 10 | S3 data-event logging is not enabled, so object reads cannot be ruled out. |
| E18 | ir_notes.txt | line 7 | so any member could attach AdministratorAccess to themselves |
| E19 | ir_notes.txt | line 9 | long-lived access keys are allowed for contractor users |
| E20 | ir_notes.txt | line 8 | the admin-policy alert is routed to email, not paging |

**Evidence file hashes (SHA-256)**

- `cloud_alerts.csv`: `31f9d2354e94899f667d461a8b620734b193cd5d7ec840703351c3036b2ca4be`
- `cloudtrail.json`: `127fe8b88d48016fb651c9a36102901b5f69f6d12907b3134b35dd9a99de3740`
- `ir_notes.txt`: `e981b3f3916a1158dd66157678ec5ee25f120976efde81cdd115b6efc229e3e9`
