# Incident Postmortem: INC-2026-006: Contractor cloud access key exposed in a public repository, self-escalated to admin, and used to launch GPU instances

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-006 |
| Category | credential_compromise |
| Severity | SEV2 |
| Classification confidence | 75% |
| Generated | 2026-11-23 20:19 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A key belonging to contractor user c.ng was found in a public repository commit dated 2026-10-30. On 2026-11-02 the c.ng identity was used from an IP not previously seen for the account. It attached AdministratorAccess to itself and created an access key for svc.reporting. The actor then listed buckets and launched 4 p4d.24xlarge GPU instances. The admin-policy alert went to email only. On-call was paged only after the later GPU alert. Responders deactivated the keys, detached the admin policy and terminated the instances. The attacker probably used the key exposed in the public repository, but this link is not confirmed. The contractors group's iam:* permission, which allowed self-escalation, was a confirmed contributing factor. Whether any S3 data was read is unknown, because data-event logging was not enabled.

**Severity rationale:** A contractor account (c.ng) was confirmed compromised and used from a previously unseen IP to gain admin rights, create a key for another identity and launch 4 GPU instances. Access was contained by disabling keys, detaching the policy and terminating the instances. No large-scale sensitive data exposure is confirmed. S3 object reads cannot be ruled out because data-event logging was off, so this remains an open question and not a confirmed exposure.

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

- **[confirmed]** Secret scanning during the response found c.ng's access key in a public code repository commit dated 2026-10-30. [E15]
- **[confirmed]** On 2026-11-02 the c.ng identity made API calls from 198.51.100.77 using python-boto3, starting with GetCallerIdentity. This IP had not been seen before for the account. The account normally works from 192.0.2.80. [E2][E16]
- **[confirmed]** The c.ng identity attached the AdministratorAccess policy to itself about 25 seconds after the first recorded call from the new IP. [E3]
- **[confirmed]** Using c.ng, the actor created a new access key for the svc.reporting identity. [E5]
- **[confirmed]** The actor then ran ListBuckets and launched 4 p4d.24xlarge instances. [E6][E7]
- **[confirmed]** The admin-policy alert at 01:13 went to email only. On-call was paged at 01:58 by the GPU launch alert, about 45 minutes after the admin-policy alert. [E9]
- **[confirmed]** The cloud secops team set c.ng's access key to Inactive, detached AdministratorAccess from c.ng and terminated the 4 GPU instances. The response notes also say the new svc.reporting key was deactivated. [E10][E11][E12][E14]
- **[unknown]** Whether any S3 objects were read cannot be determined. Management events show only ListBuckets, but data-event logging was off. [E17]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `198.51.100.77` | ip | [E4] |

## 5. Root cause

**[probable]** The attacker probably used c.ng's long-lived access key, which had been committed to a public repository. This is inferred from the key's discovery in the repo and its use from an IP never seen for the account. The evidence does not directly show how the attacker obtained the key. The key's 400-day age and the iam:* permission on the contractors group allowed a single leaked credential to become admin. [E2][E15][E16]

### Contributing factors

- **[confirmed]** The CI deploy policy attached to the contractors group grants iam:*, so any member could attach AdministratorAccess to themselves. [E18]
- **[confirmed]** Long-lived access keys were allowed for contractor users, and c.ng's key was 400 days old. [E19]
- **[confirmed]** A second persistence path was opened: the actor created a key for svc.reporting, so revoking c.ng alone would not have ended access. [E5]

## 6. Detection gaps

- **[confirmed]** The high-severity admin-policy alert was routed to email, not paging. On-call was engaged only by the later GPU launch alert. [E9][E20]
- **[confirmed]** S3 data-event logging was not enabled, so the scope of any data access cannot be determined. [E17]
- **[probable]** The exposed key was found by secret scanning only during the response, about three days after the commit date. Earlier detection of the public commit is not evidenced. [E15]

## 7. Lessons learned

**Process**
- Privilege-escalation alerts need an immediate paging path. The 01:13 admin-policy alert went to email while the attacker went on to launch GPU instances. [E9][E20]
- Responders must review everything the compromised identity created, such as keys for other users, not just the identity itself. Here the actor created a key for svc.reporting. [E5] [P1]

**Technology**
- Permissions that allow self-escalation (iam:* with policy attachment) must not sit in a broadly shared group. A single leaked contractor key became full admin within about a minute. [E18] [P2]
- Long-lived keys for contractors leave a leaked secret usable for a very long time. [E19] [P2]

**Governance**
- Without object-level logging, data exposure cannot be ruled out. The data must then be treated as potentially exposed. [E17] [P3]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Remove iam:* and policy-attachment rights from the contractors group's CI deploy policy. Enforce permission boundaries so non-admin users cannot attach administrative policies. | The contractors group's iam:* allowed c.ng to attach AdministratorAccess to itself. [E18] | [P2] | Cloud platform / IAM | Immediately (within days) | A leaked contractor credential can no longer be turned into admin access. |
| critical | Rotate every credential found in the public repository and remove the key from repository history. Enable push-time secret scanning. | c.ng's key was publicly committed on 2026-10-30 and was found only during the response. [E15] | [P4] | Security engineering / Dev platform | Immediately (within days) | Closes the exposure that most likely allowed the attacker in and prevents repeat leaks. |
| high | Replace long-lived contractor access keys with short-lived single sign-on credentials. Rotate any unavoidable keys within 90 days. | c.ng's key was 400 days old and long-lived keys were allowed for contractors. [E19] | [P2] | Cloud platform / IAM | 30 days | Limits the usable lifetime of any leaked credential. |
| high | Route admin-policy attachment and similar privilege-change alerts to paging instead of email. | The 01:13 alert went to email only. On-call was paged about 45 minutes later by the GPU alert. [E9][E20] | - | Security operations | 7 days | Faster response to privilege escalation, before resources are launched. |
| high | Enable S3 data-event logging for buckets holding confidential or restricted data. Until it is enabled and the buckets are classified, treat data in the account's buckets as potentially exposed. | Object reads cannot be ruled out because data-event logging was off. [E17] | [P3][P5] | Cloud platform / Security | 14 days | Future incidents can show whether data was read. |
| high | Complete the persistence review of all c.ng activity. Confirm that the svc.reporting key created by the actor is removed and unused, and that no other users, keys or policies were created. | The actor created a key for svc.reporting. The notes say it was deactivated, but whether it was used before then is not recorded. [E5][E10] | [P1] | Incident response | 3 days | Removes any remaining attacker foothold. |

## 9. Open questions and remaining risks

- **Open:** Who committed the key to the public repository? The notes list this as unknown.
- **Open:** Did the attacker obtain the key from the public repository? Only the discovery of the key there and its use from an unfamiliar IP are recorded, not the link between them.
- **Open:** Were any S3 objects read? Data-event logging was off, and the sensitivity of the buckets is not recorded. Should privacy/legal be consulted?
- **Open:** Was the svc.reporting key used before it was deactivated?
- **Open:** The notes say 'both access keys' for c.ng were deactivated, but only one UpdateAccessKey event is in the exported records. Which keys existed, and which one was used by the attacker?
- **Open:** Is the audit export complete? Only 9 events are included, and activity from 192.0.2.80 at 2026-11-01 15:40 (DescribeInstances) is unexplained.
- **Risk:** Any other credentials committed to the same repository may still be valid until rotated.
- **Risk:** Other contractors-group members still have iam:* until the policy is fixed.
- **Risk:** Possible access to S3 data is unresolved because object-level logs do not exist.

## 10. Validation log

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
| E17 | ir_notes.txt | line 10 | S3 data-event logging is not enabled, so object reads cannot be ruled out. |
| E18 | ir_notes.txt | line 7 | grants iam:* so any member could attach AdministratorAccess to themselves |
| E19 | ir_notes.txt | line 9 | long-lived access keys are allowed for contractor users; c.ng's key was 400 days old |
| E20 | ir_notes.txt | line 8 | the admin-policy alert is routed to email, not paging |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | PB-04 §2 Persistence review | Remove anything the attacker created, including keys created for other users |
| P2 | POL-07 §6 Cloud credentials | permission boundaries must stop users attaching administrative policies to themselves |
| P3 | POL-12 §4 Required log sources | Storage data-access events (object reads) must be enabled for any bucket holding confidential or restricted data |
| P4 | PB-04 §5 Leaked secrets | rotate every credential found there |
| P5 | PB-04 §4 Data access | state that reads cannot be ruled out and treat the data as potentially exposed |

_Knowledge-base sections given to the model: POL-07#6, PB-04#2, POL-12#4, PB-04#4, PB-04#5, POL-15#3, PB-05#1, POL-20#4_

**Evidence file hashes (SHA-256)**

- `cloud_alerts.csv`: `31f9d2354e94899f667d461a8b620734b193cd5d7ec840703351c3036b2ca4be`
- `cloudtrail.json`: `127fe8b88d48016fb651c9a36102901b5f69f6d12907b3134b35dd9a99de3740`
- `ir_notes.txt`: `e981b3f3916a1158dd66157678ec5ee25f120976efde81cdd115b6efc229e3e9`
