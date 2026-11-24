# Incident Postmortem: INC-2026-006: Contractor access key c.ng used from an unfamiliar IP to self-grant AdministratorAccess and launch GPU instances

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-006 |
| Category | credential_compromise |
| Severity | SEV2 |
| Classification confidence | 80% |
| Generated | 2026-11-24 09:06 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

c.ng was used from an IP not previously seen for the account and attached AdministratorAccess to itself. The same session created an access key for svc.reporting and launched 4 large GPU instances. c.ng's access key was found in a public repository commit. The misuse was probably done with that leaked key, but this is not confirmed. The contractors group's CI deploy policy granted iam:*, so any member could self-escalate. Long-lived contractor keys were also permitted. The admin-policy alert went to email only. On-call was paged only by the later GPU launch alert. Keys were deactivated, the admin policy detached and the instances terminated. Data reads cannot be ruled out because S3 data-event logging was off.

**Severity rationale:** The c.ng account was compromised and the actor attached AdministratorAccess, created a key for svc.reporting and launched 4 GPU instances. Responders contained this by deactivating keys, detaching the policy and terminating the instances. No large-scale sensitive data exposure is confirmed. Management events show ListBuckets only, but object reads cannot be ruled out because S3 data-event logging was off.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| EV001 | 2026-11-01 15:40:00 | eventName=DescribeInstances; userName=c.ng | exact | [E1] |
| **EV002** | **2026-11-02 01:12:40** | **eventName=GetCallerIdentity; userName=c.ng** | exact | [E2] |
| **EV003** | **2026-11-02 01:13:05** | **eventName=AttachUserPolicy; userName=c.ng** | exact | [E3] |
| **EV004** | **2026-11-02 01:13:30** | **alert=Admin policy attached to user; severity=high** | exact | [E4] |
| **EV005** | **2026-11-02 01:14:20** | **eventName=CreateAccessKey; userName=c.ng** | exact | [E5] |
| **EV006** | **2026-11-02 01:16:02** | **eventName=ListBuckets; userName=c.ng** | exact | [E6] |
| **EV007** | **2026-11-02 01:21:47** | **eventName=RunInstances; userName=c.ng** | exact | [E7] |
| **EV008** | **2026-11-02 01:50:12** | **alert=Anomalous GPU instance launch; severity=high** | exact | [E8] |
| **EV009** | **2026-11-02 01:58:00** | **01:58 On-call paged by the GPU launch alert. The admin-policy alert at 01:13 went to email only.** | date inferred | [E9] |
| **EV010** | **2026-11-02 02:03:00** | **02:03 Deactivated both access keys for c.ng and the new key created for svc.reporting.** | date inferred | [E10] |
| EV011 | 2026-11-02 02:03:10 | eventName=UpdateAccessKey; userName=cloud.secops | exact | [E11] |
| **EV012** | **2026-11-02 02:04:00** | **eventName=DetachUserPolicy; userName=cloud.secops** | exact | [E12] |
| EV013 | 2026-11-02 02:06:00 | 02:06 Terminated the 4 GPU instances. | date inferred | [E13] |
| **EV014** | **2026-11-02 02:06:30** | **eventName=TerminateInstances; userName=cloud.secops** | exact | [E14] |
| **EV015** | **2026-11-02 03:10:00** | **03:10 Secret scanning found c.ng's access key in a public code repository commit dated 2026-10-30.** | date inferred | [E15] |

## 3. What happened

- **[confirmed]** Secret scanning found c.ng's access key in a public code repository commit dated 2026-10-30. [E15]
- **[confirmed]** c.ng activity (GetCallerIdentity) came from 198.51.100.77, an IP never before seen for this account. The account normally works from 192.0.2.80. [E2][E16]
- **[confirmed]** Using c.ng, the actor attached the AdministratorAccess policy to c.ng itself. [E3][E4]
- **[confirmed]** Using c.ng, the actor created a new access key for the svc.reporting user. [E5]
- **[confirmed]** The actor ran ListBuckets. Management events show no other storage activity, but S3 data-event logging was not enabled, so object reads cannot be ruled out. [E6][E17]
- **[confirmed]** The actor launched 4 p4d.24xlarge GPU instances. [E7][E8]
- **[confirmed]** The admin-policy alert went to email only. On-call was paged only by the later GPU launch alert. [E9]
- **[confirmed]** Responders deactivated the c.ng keys and the new svc.reporting key, detached AdministratorAccess from c.ng and terminated the 4 GPU instances. [E10][E12][E13]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `198.51.100.77` | ip | [E4] |

## 5. MITRE ATT&CK mapping

| Tactic | Technique | ID | Certainty | Behaviour | Evidence |
|---|---|---|---|---|---|
| initial-access, persistence, privilege-escalation, stealth | Valid Accounts: Cloud Accounts | T1078.004 | probable | The c.ng cloud account was used from an IP never before seen for it, consistent with use of the leaked key. | [E15][E16] |
| persistence, privilege-escalation | Account Manipulation: Additional Cloud Roles | T1098.003 | confirmed | The actor attached AdministratorAccess to c.ng. | [E3] |
| persistence, privilege-escalation | Account Manipulation: Additional Cloud Credentials | T1098.001 | confirmed | The actor created an additional access key for svc.reporting. | [E5] |
| discovery | Cloud Storage Object Discovery | T1619 | confirmed | The actor listed the storage buckets. | [E6] |
| defense-impairment | Modify Cloud Compute Infrastructure: Create Cloud Instance | T1578.002 | confirmed | The actor launched 4 GPU instances. | [E7] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**Immediate cause [probable]:** c.ng's access key, exposed in a public repository commit, was probably used from the unfamiliar IP 198.51.100.77 to act as c.ng. The records do not state which key authenticated the activity or who used it. [E15][E16]

**[confirmed]** The CI deploy policy on the contractors group granted iam:*, so a compromised contractor identity could attach AdministratorAccess to itself. Long-lived access keys were also allowed for contractors. [E18][E19]

### Contributing factors

- **[confirmed]** c.ng's long-lived access key was 400 days old, which made a leaked key usable long after creation. [E19]
- **[confirmed]** Long-lived keys were allowed for contractor users. [E19]
- **[confirmed]** The admin-policy alert was routed to email, not paging, so it did not trigger a timely response. [E20]

## 7. Impact assessment

- **Systems involved:** none identified
- **Accounts involved:** `c.ng`, `svc.reporting`
- **Data affected:** [possible] No object reads are confirmed. Management events show ListBuckets only, but because S3 data-event logging was off, reads cannot be ruled out and data exposure is possible. [E17]
- **Operational impact:** [confirmed] 4 p4d.24xlarge GPU instances were launched by the actor and later terminated by responders. [E7][E13]
- **Business impact:** [unknown] Financial cost of the GPU usage and any wider business impact are not stated in the evidence.

## 8. Response analysis

Milestones chosen by the model from the timeline; durations computed by code from timestamps.

| Milestone | Event | Time (UTC) | Time basis |
|---|---|---|---|
| attack start | EV002 | 2026-11-02 01:12:40 | exact |
| first detection | EV004 | 2026-11-02 01:13:30 | exact |
| response start | EV009 | 2026-11-02 01:58:00 | date inferred |
| containment | EV010 | 2026-11-02 02:03:00 | date inferred |

| Measure | From → to | Duration |
|---|---|---|
| time to detect | attack start → first detection | 50s |
| time to respond | first detection → response start | 44m 30s (approximate: inferred time) |
| time to contain | first detection → containment | 49m 30s (approximate: inferred time) |
| dwell time | attack start → containment | 50m 20s (approximate: inferred time) |

## 9. Detection gaps

- **[confirmed]** The high-severity admin-policy alert was sent to email only and did not page anyone. On-call was paged only by the later GPU launch alert. [E9][E20]
- **[confirmed]** S3 data-event logging was not enabled, so it cannot be determined whether objects were read. [E17]
- **[probable]** The leaked key in the public repository was found by secret scanning only during the response, not before use. No earlier detection is recorded. [E15]

## 10. Lessons learned

**Process**
- Alerting on privilege escalation must reach a human immediately. The email-only admin-policy alert delayed response until the GPU alert paged on-call. [E9][E20]

**Technology**
- Broad IAM permissions on a shared contractor group let one leaked credential escalate to full administrator. Only the cloud administrators group should hold iam:* and policy-attachment rights, and permission boundaries should block self-attachment. [E18] [P1]
- A 400-day-old long-lived contractor key allowed a leaked credential to be used long after it was created. Policy prohibits such keys. [E19] [P1]

**Governance**
- Missing S3 data-event logging left the data-exposure question unanswerable. Required log sources must be enabled for buckets with confidential data. [E17] [P2]

## 11. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Remove iam:* from the contractors group CI deploy policy. Restrict iam:* and policy attachment to the cloud administrators group and enforce permission boundaries. | Any member of the contractors group could attach AdministratorAccess to themselves. [E18] | [P1] | Cloud Security / IAM | Immediately (within 3 days) | A compromised contractor identity can no longer escalate itself to administrator. |
| high | Replace long-lived access keys for contractors with short-lived SSO credentials. Rotate or remove any remaining old keys, starting with keys older than 90 days. | c.ng's 400-day-old key was exposed publicly and then used. [E19] | [P1] | Cloud Platform / IAM | 30 days | Leaked credentials expire quickly and have less value. |
| high | Route the admin-policy-attached alert (and similar IAM privilege-change alerts) to paging, not email only. | The 01:13 admin-policy alert went to email only and on-call was paged only by the later GPU alert. [E9][E20] | - | Security Operations | 7 days | Faster response to privilege escalation in cloud accounts. |
| high | Enable S3 data-event logging for buckets holding confidential or restricted data. Keep logs for at least one year. | Object reads by the actor cannot be ruled out because data events were not logged. [E17] | [P2] | Cloud Platform / Security Engineering | 14 days | Future incidents can show whether data was read. |
| high | Treat bucket data as potentially exposed. Identify the data classification of the buckets that ListBuckets enumerated. If any is restricted, inform the privacy and legal team within the required window. | Reads cannot be ruled out and the actor enumerated buckets. [E6][E17] | [P3][P4] | Incident Response / Privacy & Legal | Immediately | Notification duties are assessed on time if restricted data is involved. |
| high | Complete a persistence review of every c.ng action. Delete (not only deactivate) the key created for svc.reporting and remove anything else the actor created. | The actor created a key for another identity, svc.reporting. [E5] | [P5] | Incident Response | Immediately (within 1 day) | No attacker foothold remains in the account. |
| high | Remove the leaked key from repository history, rotate every credential found there and enable push-time secret scanning. | c.ng's key was found in a public repository commit and was discovered only during the response. [E15] | [P6] | Engineering / AppSec | 7 days | Secrets are caught before publication and stale leaked secrets are invalidated. |

## 12. Open questions and remaining risks

- **Open:** Who committed the key to the public repository, and was it committed intentionally or by mistake?
- **Open:** Which key authenticated the activity from 198.51.100.77? Records link it to the leaked key only by inference.
- **Open:** Were any objects read from the enumerated buckets, and what is the data classification of those buckets?
- **Open:** What was the purpose of the 4 GPU instances (for example, whether they were used for resource abuse)? The evidence does not say.
- **Open:** Was every c.ng action in the cloud account reviewed for other persistence beyond the svc.reporting key?
- **Risk:** The leaked key may remain in public repository history until it is purged, and other credentials committed there may be exposed.
- **Risk:** The contractors group CI deploy policy still grants iam:* until it is corrected. No fix is recorded.
- **Risk:** Data exposure cannot be ruled out until storage access is assessed, because object-level logs do not exist.
- **Risk:** The svc.reporting key was deactivated, but its deletion and any other persistence are not recorded.

## 13. Validation log

- attempt 1: 0 validation problem(s)

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
| E16 | ir_notes.txt | line 12 | 198.51.100.77 has not been seen before for this account |
| E17 | ir_notes.txt | line 10 | S3 data-event logging is not enabled, so object reads cannot be ruled out |
| E18 | ir_notes.txt | line 7 | grants iam:* so any member could attach AdministratorAccess to themselves |
| E19 | ir_notes.txt | line 9 | long-lived access keys are allowed for contractor users |
| E20 | ir_notes.txt | line 8 | the admin-policy alert is routed to email, not paging |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | POL-07 §6 Cloud credentials | The iam:* permission and policy-attachment rights are granted only to the cloud administrators group |
| P2 | POL-12 §4 Required log sources | Storage data-access events (object reads) must be enabled for any bucket holding confidential or restricted data. |
| P3 | PB-04 §4 Data access | state that reads cannot be ruled out and treat the data as potentially exposed |
| P4 | POL-20 §4 Incidents involving restricted data | the privacy and legal team must be informed within 4 hours |
| P5 | PB-04 §2 Persistence review | Remove anything the attacker created, including keys created for other users. |
| P6 | PB-04 §5 Leaked secrets | enable push-time secret scanning |

_Knowledge-base sections given to the model: POL-07#6, PB-04#2, POL-12#4, PB-04#4, PB-04#5, POL-15#3, PB-05#1, POL-20#4_

**Evidence file hashes (SHA-256)**

- `cloud_alerts.csv`: `31f9d2354e94899f667d461a8b620734b193cd5d7ec840703351c3036b2ca4be`
- `cloudtrail.json`: `127fe8b88d48016fb651c9a36102901b5f69f6d12907b3134b35dd9a99de3740`
- `ir_notes.txt`: `e981b3f3916a1158dd66157678ec5ee25f120976efde81cdd115b6efc229e3e9`
