# Incident Postmortem: INC-2026-006: Leaked contractor access key used for admin self-escalation and GPU instance launch

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-006 |
| Category | credential_compromise |
| Severity | SEV2 |
| Classification confidence | 70% |
| Generated | 2026-11-23 20:46 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A secret scan found c.ng's access key in a public repository commit dated 2026-10-30. The c.ng account was then used from an IP not seen before for it to grant itself AdministratorAccess, create a key for svc.reporting, list buckets and launch 4 GPU instances. The leaked long-lived key was probably the entry point. A contractors-group policy granting iam:* allowed the self-escalation, and the key was 400 days old. The admin-policy alert went to email only. On-call was paged only after the later GPU alert. Responders deactivated the keys, detached the admin policy and terminated the 4 instances. Data exposure is not confirmed, but object reads cannot be ruled out because S3 data-event logging was not enabled.

**Severity rationale:** Unauthorised activity under the c.ng account is confirmed: self-granted AdministratorAccess, a new key for svc.reporting, and 4 GPU instances launched. Responders contained it. No large-scale sensitive data exposure is confirmed. Object reads cannot be ruled out because S3 data-event logging was off, so this is not rated SEV1.

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
| EV008 | 2026-11-02 01:50:12 | alert=Anomalous GPU instance launch; severity=high | exact | [E8] |
| **EV009** | **2026-11-02 01:58:00** | **01:58 On-call paged by the GPU launch alert. The admin-policy alert at 01:13 went to email only.** | date inferred | [E9] |
| EV010 | 2026-11-02 02:03:00 | 02:03 Deactivated both access keys for c.ng and the new key created for svc.reporting. | date inferred | [E10] |
| **EV011** | **2026-11-02 02:03:10** | **eventName=UpdateAccessKey; userName=cloud.secops** | exact | [E11] |
| **EV012** | **2026-11-02 02:04:00** | **eventName=DetachUserPolicy; userName=cloud.secops** | exact | [E12] |
| EV013 | 2026-11-02 02:06:00 | 02:06 Terminated the 4 GPU instances. | date inferred | [E13] |
| **EV014** | **2026-11-02 02:06:30** | **eventName=TerminateInstances; userName=cloud.secops** | exact | [E14] |
| **EV015** | **2026-11-02 03:10:00** | **03:10 Secret scanning found c.ng's access key in a public code repository commit dated 2026-10-30.** | date inferred | [E15] |

## 3. What happened

- **[confirmed]** Secret scanning found c.ng's access key in a public code repository commit dated 2026-10-30, before the suspicious activity began. [E15]
- **[confirmed]** On 2026-11-02 the c.ng identity made API calls from 198.51.100.77 with python-boto3. This IP has not been seen before for the account, whose normal source is 192.0.2.80. [E2][E16]
- **[confirmed]** c.ng attached the AdministratorAccess policy to itself. [E3]
- **[confirmed]** c.ng created a new access key for the svc.reporting user. [E5]
- **[confirmed]** c.ng listed storage buckets. Management events show ListBuckets only. [E6][E17]
- **[confirmed]** c.ng launched 4 p4d.24xlarge GPU instances. [E7]
- **[confirmed]** The admin-policy alert at 01:13 went to email only. On-call was paged by the GPU launch alert at 01:58. [E9]
- **[confirmed]** Responders deactivated the keys, detached AdministratorAccess from c.ng and terminated the 4 GPU instances. [E10][E12][E13]
- **[unknown]** Whether any bucket objects were read cannot be determined, because S3 data-event logging was not enabled. [E17]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `198.51.100.77` | ip | [E4] |

## 5. MITRE ATT&CK mapping

| Tactic | Technique | ID | Certainty | Behaviour | Evidence |
|---|---|---|---|---|---|
| initial-access, persistence, privilege-escalation, stealth | Valid Accounts: Cloud Accounts | T1078.004 | probable | A valid cloud account (c.ng) was used from a never-before-seen IP, and its key was exposed in a public repository. | [E2][E15] |
| persistence, privilege-escalation | Account Manipulation: Additional Cloud Roles | T1098.003 | confirmed | c.ng attached the AdministratorAccess policy to itself. | [E3] |
| persistence, privilege-escalation | Account Manipulation: Additional Cloud Credentials | T1098.001 | confirmed | An access key was created for a different identity, svc.reporting. | [E5] |
| discovery | Cloud Infrastructure Discovery | T1580 | confirmed | c.ng enumerated cloud resources with ListBuckets. | [E6] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**[probable]** A long-lived c.ng access key, 400 days old and found in a public repository commit, was probably used by an unauthorised party from a new IP. A CI deploy policy granting iam:* to the contractors group let the account attach AdministratorAccess to itself. That the leaked key was the key used is inferred, not stated. [E15][E16][E18][E19]

### Contributing factors

- **[confirmed]** The CI deploy policy on the contractors group granted iam:*, so any member could self-attach AdministratorAccess. [E19]
- **[confirmed]** Long-lived access keys were allowed for contractor users, and c.ng's key was 400 days old. [E18]

## 7. Detection gaps

- **[confirmed]** The high-severity admin-policy alert was routed to email, not paging. On-call was engaged only by the later GPU launch alert. [E9][E20]
- **[confirmed]** S3 data-event logging was not enabled, so object reads cannot be ruled out. [E17]

## 8. Lessons learned

**Process**
- A high-severity privilege-escalation alert that only reaches email loses the early response window. On-call was engaged only after the later GPU alert. [E9][E20]

**Technology**
- Long-lived keys outlive their usefulness and leak into code. A 400-day-old contractor key breached the rotation rule and was usable by anyone who found it. [E18] [P1]
- Without data-event logging, data exposure cannot be confirmed or excluded after an incident. [E17] [P2]

**Governance**
- Broad IAM rights on a contractor group turned one leaked key into full administrative access. Policy-attachment rights belong only to cloud administrators, backed by permission boundaries. [E19] [P1]

## 9. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Remove iam:* and policy-attachment rights from the contractors group CI deploy policy. Add permission boundaries that block self-attachment of administrative policies. | A contractor user attached AdministratorAccess to itself. [E19] | [P1] | Cloud security / IAM | Immediately (days) | A leaked contractor credential can no longer be escalated to administrator. |
| critical | Remove the leaked key from repository history, rotate every credential found there, and enable push-time secret scanning. | The c.ng key sat in a public commit dated 2026-10-30. [E15] | [P3] | Application security / Engineering | Immediately (days) | Closes the exposure path and stops future secret commits. |
| high | Replace long-lived contractor keys with short-lived single sign-on credentials. Rotate within 90 days any key that cannot yet be replaced. | A 400-day-old key was allowed for a contractor user. [E18] | [P1] | Cloud security / IAM | 30 days | Reduces the value and lifetime of any leaked credential. |
| high | Route the admin-policy-attached alert to paging with on-call. | The 01:13 alert went to email only and on-call was paged only after the GPU alert. [E9][E20] | - | Security operations | 7 days | Faster response to privilege escalation in cloud accounts. |
| high | Complete the persistence review of every c.ng action. Confirm the svc.reporting key is removed (not only deactivated) and check whether it was ever used. | c.ng created a key for another identity during the intrusion. [E5] | [P4] | Incident response | 3 days | Ensures no attacker-created access remains. |
| high | Enable S3 data-event logging for buckets holding confidential or restricted data. Until the review is complete, treat data in the buckets listed by c.ng as potentially exposed. | Object reads cannot be ruled out, and c.ng listed buckets. [E17] | [P5] | Cloud platform / Data owners | 14 days | Allows future data-access determinations and sound exposure assessment. |

## 10. Open questions and remaining risks

- **Open:** Who committed c.ng's key to the public repository, and was it intentional or accidental?
- **Open:** Were any S3 objects read? Data-event logging was off, so this cannot be determined from the available logs.
- **Open:** Which buckets did c.ng list, and do they hold confidential or restricted data?
- **Open:** Was the svc.reporting key used before it was deactivated?
- **Open:** Was the leaked key definitely the key used from 198.51.100.77?
- **Open:** What were the GPU instances used for?
- **Risk:** The leaked key remains in public repository history until removed; the evidence does not show that it has been.
- **Risk:** Other credentials in the same repository or commit may also be exposed.
- **Risk:** Other contractor users in the same group still have iam:* until the policy is corrected.
- **Risk:** Possible data exposure cannot be excluded.

## 11. Validation log

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
| E16 | ir_notes.txt | line 12 | 198.51.100.77 has not been seen before for this account. |
| E17 | ir_notes.txt | line 10 | Management events show ListBuckets only. |
| E18 | ir_notes.txt | line 9 | c.ng's key was 400 days old. |
| E19 | ir_notes.txt | line 7 | grants iam:* so any member could attach AdministratorAccess to themselves. |
| E20 | ir_notes.txt | line 8 | the admin-policy alert is routed to email, not paging. |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | POL-07 §6 Cloud credentials | Long-lived access keys are prohibited for human and contractor users |
| P2 | POL-12 §4 Required log sources | Storage data-access events (object reads) must be enabled for any bucket holding confidential or restricted data. |
| P3 | PB-04 §5 Leaked secrets | Remove leaked secrets from code repository history, rotate every credential found there, and enable push-time secret sca |
| P4 | PB-04 §2 Persistence review | Remove anything the attacker created, including keys created for other users. |
| P5 | PB-04 §4 Data access | state that reads cannot be ruled out and treat the data as potentially exposed. |

_Knowledge-base sections given to the model: POL-07#6, PB-04#2, POL-12#4, PB-04#4, PB-04#5, POL-15#3, PB-05#1, POL-20#4_

**Evidence file hashes (SHA-256)**

- `cloud_alerts.csv`: `31f9d2354e94899f667d461a8b620734b193cd5d7ec840703351c3036b2ca4be`
- `cloudtrail.json`: `127fe8b88d48016fb651c9a36102901b5f69f6d12907b3134b35dd9a99de3740`
- `ir_notes.txt`: `e981b3f3916a1158dd66157678ec5ee25f120976efde81cdd115b6efc229e3e9`
