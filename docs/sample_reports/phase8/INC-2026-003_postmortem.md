# Incident Postmortem: INC-2026-003: Customer data export bucket acme-crm-exports publicly exposed for four days

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-003 |
| Category | data_exposure |
| Severity | SEV1 |
| Classification confidence | 85% |
| Generated | 2026-11-24 09:03 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

On 14 Sep d.reyes removed the public access block on acme-crm-exports and applied a policy allowing everyone to read and list it. This was done to let a vendor test an integration, and no change ticket was raised. On 17 Sep an unauthenticated external requester listed the bucket and downloaded both customer CSV files. Who this requester is is not confirmed. The exposed files held about 41,200 customer records (names, emails, phone numbers). No payment data was involved. Detection came from an external researcher's email after about 4 days. No internal alert existed for policy changes granting public access. cloud.secops re-enabled the public access block on 18 Sep and legal and privacy were informed the same day. The underlying weakness was that there was no account-level public access block and no policy guardrail against public buckets.

**Severity rationale:** Confirmed: the bucket was publicly readable, and an unauthenticated external requester downloaded both customer files holding about 41,200 customer records (names, emails, phone numbers). This is restricted customer personal data at scale, so SEV1 applies. Fast closure after the report does not lower severity. Legal and privacy were informed to assess notification duties.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| **EV001** | **2026-09-14 16:02:11** | **eventName=DeletePublicAccessBlock; userName=d.reyes** | exact | [E1] |
| **EV002** | **2026-09-14 16:02:48** | **policy={"Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:ListBucket"]}; eventName=PutBucketPolicy** | exact | [E2] |
| EV003 | 2026-09-15 10:04:12 | operation=REST.GET.OBJECT; key=sample_10rows.csv; remote_ip=192.0.2.44 | exact | [E3] |
| **EV004** | **2026-09-17 03:11:05** | **operation=REST.GET.BUCKET; remote_ip=198.51.100.23** | exact | [E4] |
| **EV005** | **2026-09-17 03:12:40** | **operation=REST.GET.OBJECT; key=customers_2026Q3.csv; remote_ip=198.51.100.23** | exact | [E5] |
| **EV006** | **2026-09-17 03:14:02** | **operation=REST.GET.OBJECT; key=customers_2026Q2.csv; remote_ip=198.51.100.23** | exact | [E6] |
| **EV007** | **2026-09-18 10:30:00** | **2026-09-18 10:30 Email from an external security researcher reporting the bucket was publicly listable.** | timezone assumed | [E7] |
| **EV008** | **2026-09-18 10:55:00** | **2026-09-18 10:55 cloud.secops re-enabled the public access block on the bucket.** | timezone assumed | [E8] |
| EV009 | 2026-09-18 10:55:30 | eventName=PutPublicAccessBlock; userName=cloud.secops | exact | [E9] |
| **EV010** | **2026-09-18 11:02:19** | **operation=REST.GET.BUCKET; remote_ip=198.51.100.23** | exact | [E10] |
| **EV011** | **2026-09-18 12:00:00** | **Legal and privacy team informed 2026-09-18 12:00 to assess notification duties.** | timezone assumed | [E11] |

## 3. What happened

- **[confirmed]** d.reyes deleted the public access block on bucket acme-crm-exports. [E1]
- **[confirmed]** Shortly afterwards d.reyes applied a bucket policy on acme-crm-exports allowing object reads and bucket listing to all principals. [E2]
- **[confirmed]** On 15 Sep the vendor-test identity fetched a small sample file from the bucket. This is consistent with the stated vendor testing purpose. [E3]
- **[confirmed]** On 17 Sep an unauthenticated requester (no requester identity, curl user agent) at 198.51.100.23 listed the bucket and downloaded customers_2026Q3.csv and customers_2026Q2.csv with HTTP 200. [E4][E5][E6]
- **[confirmed]** The exposed files held about 41,200 customer records (names, emails, phone numbers) and no payment data. [E12]
- **[confirmed]** On 18 Sep an external security researcher emailed that the bucket was publicly listable. This was the first report. [E7]
- **[confirmed]** cloud.secops re-enabled the public access block on the bucket at 10:55 on 18 Sep. [E8][E9]
- **[confirmed]** After the block was re-enabled, a further listing request from 198.51.100.23 was denied with HTTP 403. [E10]
- **[confirmed]** Legal and privacy were informed on 18 Sep at 12:00 to assess notification duties. [E11]

## 4. Indicators of compromise

_None identified._

## 5. MITRE ATT&CK mapping

| Tactic | Technique | ID | Certainty | Behaviour | Evidence |
|---|---|---|---|---|---|
| collection | Data from Cloud Storage | T1530 | confirmed | An unauthenticated external requester downloaded customer data objects directly from the cloud storage bucket. | [E5][E6] |
| discovery | Cloud Storage Object Discovery | T1619 | probable | The same external requester listed the bucket contents before downloading the files. | [E4] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**Immediate cause [confirmed]:** d.reyes made acme-crm-exports public to let a vendor test an integration, without a change ticket. [E13]

**[confirmed]** No account-level public access block and no policy guardrail existed to prevent a single user from making a bucket with customer data public. [E14]

### Contributing factors

- **[confirmed]** The change was made without a change ticket, so it received no review or approval. [E13]
- **[confirmed]** The exposure stayed open for about 4 days because nothing detected or reverted the change. [E15]

## 7. Impact assessment

- **Systems involved:** `acme-crm-exports`
- **Accounts involved:** `d.reyes`
- **Data affected:** [confirmed] Customer personal data (names, emails, phone numbers) for about 41,200 customers in two CSV files was exposed and downloaded by an external requester. No payment data was involved. [E5][E12]
- **Operational impact:** [unknown] The evidence does not describe any operational disruption.
- **Business impact:** [unknown] Legal and privacy were engaged to assess notification duties. Financial cost and the notification outcome are not stated in the evidence. [E11]

## 8. Response analysis

Milestones chosen by the model from the timeline; durations computed by code from timestamps.

| Milestone | Event | Time (UTC) | Time basis |
|---|---|---|---|
| attack start | EV001 | 2026-09-14 16:02:11 | exact |
| first detection | EV007 | 2026-09-18 10:30:00 | timezone assumed |
| response start | EV008 | 2026-09-18 10:55:00 | timezone assumed |
| containment | EV008 | 2026-09-18 10:55:00 | timezone assumed |

| Measure | From → to | Duration |
|---|---|---|
| time to detect | attack start → first detection | 3d 18h 27m (approximate: inferred time) |
| time to respond | first detection → response start | 25m (approximate: inferred time) |
| time to contain | first detection → containment | 25m (approximate: inferred time) |
| dwell time | attack start → containment | 3d 18h 52m (approximate: inferred time) |

## 9. Detection gaps

- **[confirmed]** No alert existed for bucket policy changes that grant access to everyone. Detection came from an outside party after about 4 days. [E15]

## 10. Lessons learned

**Process**
- Storage access changes must go through an approved change ticket. The change here bypassed review entirely. [E13] [P1]
- Vendor testing should use scoped, time-limited credentials and test data, not public access to production exports. A vendor identity already existed and fetched a sample file. [E13] [P2]

**Technology**
- Preventive guardrails are needed because one user could expose a customer data bucket alone. Account-level controls and policy guardrails must block public buckets. [E14] [P2]
- Detection relied on an external party. Internal alerting on public-access policy changes is needed to shorten exposure windows. [E15]

**Governance**
- Escalation to legal and privacy was timely in this case and should remain the standard for restricted data exposure. [E11] [P3]

## 11. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Enable an account-level public access block in every cloud account and add a policy guardrail (for example an organisation-level deny) that prevents public bucket policies on non-public buckets. | No account-level block or guardrail existed, which allowed a single user to expose customer data. [E14] | [P2] | Cloud Security | Within 7 days | Public exposure of storage cannot happen by a single user's change. |
| critical | Confirm the permissive bucket policy granting access to all principals has been removed from acme-crm-exports. Also review other buckets for public policies. | Only re-enabling the public access block is recorded. Removal of the public-allow policy is not recorded. [E2][E9] | - | Cloud Security | Within 1 day | The exposure cannot return if the block is later disabled. |
| high | Create an alert for bucket policy or public access block changes that grant access to everyone, routed to the security team. | The exposure was found by an outsider after 4 days because no alert existed. [E15] | - | Security Operations | Within 14 days | Detection within minutes instead of days. |
| high | Complete the review of all access logs for acme-crm-exports from 14 to 18 Sep to identify every requester who read customer files. Establish the identity of 198.51.100.23. Provide results to legal and privacy to support the notification assessment. | Downloads of both customer files by an unauthenticated requester are confirmed, but the requester's identity is not. [E5][E16] | [P4] | Incident Response with Privacy and Legal | Within 3 days | An accurate scope of affected customers and a sound basis for notification decisions. |
| high | Enforce approved change tickets for storage access and permission changes. Require vendor integration testing to use scoped, time-limited credentials with test data, and give any temporary exception an owner and expiry. | The bucket was made public for vendor testing with no ticket, and no owner or expiry is recorded. [E13] | [P1][P2][P5] | Cloud Platform and Change Management | Within 30 days | Reviewed, time-bound vendor access that avoids public production data. |

## 12. Open questions and remaining risks

- **Open:** Is 198.51.100.23 the external researcher who reported the issue? This is not confirmed, so it is not listed as a malicious indicator.
- **Open:** Was the public-allow bucket policy removed, or only the public access block re-enabled?
- **Open:** Were there other readers, or other copies of the customer files, beyond those in the access log extract? The completeness of the log is not stated.
- **Open:** Why was a vendor-test identity available if vendor access still required public exposure? Was public access actually needed for the test?
- **Open:** Who made the request to 198.51.100.23 after containment at 11:02 on 18 Sep? It was denied with 403.
- **Open:** What are the notification obligations and the financial cost? The assessment is pending.
- **Risk:** Customer data (names, emails, phone numbers) for about 41,200 customers was downloaded and may be held by an unidentified party.
- **Risk:** The permissive bucket policy may still be present; its removal is not recorded.
- **Risk:** No account-level public access block or guardrail is confirmed in place, so the same exposure could recur.

## 13. Validation log

- attempt 1: 0 validation problem(s)

## Evidence index

| Ref | File | Location | Quote |
|---|---|---|---|
| E1 | cloudtrail.json | Records[0] | 2026-09-14T16:02:11Z |
| E2 | cloudtrail.json | Records[1] | 2026-09-14T16:02:48Z |
| E3 | s3_access_logs.csv | row 1 | 2026-09-15T10:04:12Z |
| E4 | s3_access_logs.csv | row 2 | 2026-09-17T03:11:05Z |
| E5 | s3_access_logs.csv | row 3 | 2026-09-17T03:12:40Z |
| E6 | s3_access_logs.csv | row 4 | 2026-09-17T03:14:02Z |
| E7 | notes.txt | line 3 | 2026-09-18 10:30 |
| E8 | notes.txt | line 4 | 2026-09-18 10:55 |
| E9 | cloudtrail.json | Records[2] | 2026-09-18T10:55:30Z |
| E10 | s3_access_logs.csv | row 5 | 2026-09-18T11:02:19Z |
| E11 | notes.txt | line 9 | 2026-09-18 12:00 |
| E12 | notes.txt | line 5 | about 41,200 customer records (names, emails, phone numbers). No payment data. |
| E13 | notes.txt | line 2 | made acme-crm-exports public on 14 Sep to let a vendor test an integration |
| E14 | notes.txt | line 6 | there is no account-level public access block and no policy guardrail preventing public buckets |
| E15 | notes.txt | line 7 | Detection came from an outside party after 4 days. |
| E16 | notes.txt | line 8 | unclear whether 198.51.100.23 is the researcher who reported the issue. Not confirmed. |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | POL-15 §1 Change tickets | Every change to production systems, network rules, cloud permissions or storage access needs an approved change ticket. |
| P2 | POL-15 §3 Public exposure of storage | Vendor access must use scoped, time-limited credentials and test data, never public access to production data. |
| P3 | POL-20 §4 Incidents involving restricted data | must be informed within 4 hours of the security team becoming aware |
| P4 | PB-04 §4 Data access | Determine whether data was read. |
| P5 | POL-15 §2 Temporary exceptions | need a named owner and an expiry of at most 30 days |

_Knowledge-base sections given to the model: POL-20#4, POL-15#3, PIR-2025-031#1, POL-15#1, POL-20#1, SEV-01#2, PB-04#4, POL-15#2_

**Evidence file hashes (SHA-256)**

- `cloudtrail.json`: `2e95dfb2fe79457d28689143365fcef65b1fc1735b86ffcbc8398af37ca56df2`
- `notes.txt`: `de6dd03336b172a557a3c3cd86d25d7ee4c0445433d432ad74862e74f206d9be`
- `s3_access_logs.csv`: `94817772e13ff82dbae014dfdeb67d9a61dad58b8510ffdf36fe2c8eae822fcc`
