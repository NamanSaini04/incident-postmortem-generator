# Incident Postmortem: INC-2026-003: Customer CRM export bucket made public without approval; customer data downloaded by an unidentified external party

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-003 |
| Category | data_exposure |
| Severity | SEV1 |
| Classification confidence | 90% |
| Generated | 2026-11-23 20:42 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A user removed the bucket's public access block and applied a policy allowing read and list access, which made the bucket public. The stated reason was a vendor integration test, and no change ticket was raised. The bucket held two customer export files with about 41,200 customer records (names, emails, phone numbers). No payment data was involved. An unauthenticated external IP listed the bucket and downloaded both customer files on 17 Sep. Who operated that IP is not confirmed. An outside researcher reported the issue after 4 days. The public access block was restored 25 minutes after the report, and a later request was denied. No account-level public access block or policy guardrail existed, so a single user could expose the bucket. Legal and privacy were informed on 18 Sep to assess notification duties. The outcome of that assessment is not in the evidence.

**Severity rationale:** The access logs confirm that an unauthenticated external IP downloaded both customer export files (s3_access_logs.csv row 3, s3_access_logs.csv row 4). notes.txt line 5 describes them as about 41,200 customer records containing names, emails and phone numbers. That is restricted customer personal data read at scale, so SEV1 applies (POL-20 §4, SEV-01 §2). Closing the exposure quickly after the report does not lower severity because the data was already taken. No payment data was exposed (notes.txt line 5).

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| **EV001** | **2026-09-14 16:02:11** | **eventName=DeletePublicAccessBlock; userName=d.reyes** | exact | [E1] |
| **EV002** | **2026-09-14 16:02:48** | **policy={"Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:ListBucket"]}; eventName=PutBucketPolicy** | exact | [E2] |
| EV003 | 2026-09-15 10:04:12 | operation=REST.GET.OBJECT; key=sample_10rows.csv; remote_ip=192.0.2.44 | exact | [E3] |
| EV004 | 2026-09-17 03:11:05 | operation=REST.GET.BUCKET; remote_ip=198.51.100.23 | exact | [E4] |
| **EV005** | **2026-09-17 03:12:40** | **operation=REST.GET.OBJECT; key=customers_2026Q3.csv; remote_ip=198.51.100.23** | exact | [E5] |
| **EV006** | **2026-09-17 03:14:02** | **operation=REST.GET.OBJECT; key=customers_2026Q2.csv; remote_ip=198.51.100.23** | exact | [E6] |
| **EV007** | **2026-09-18 10:30:00** | **2026-09-18 10:30 Email from an external security researcher reporting the bucket was publicly listable.** | timezone assumed | [E7] |
| EV008 | 2026-09-18 10:55:00 | 2026-09-18 10:55 cloud.secops re-enabled the public access block on the bucket. | timezone assumed | [E8] |
| **EV009** | **2026-09-18 10:55:30** | **eventName=PutPublicAccessBlock; userName=cloud.secops** | exact | [E9] |
| **EV010** | **2026-09-18 11:02:19** | **operation=REST.GET.BUCKET; remote_ip=198.51.100.23** | exact | [E10] |
| **EV011** | **2026-09-18 12:00:00** | **Legal and privacy team informed 2026-09-18 12:00 to assess notification duties.** | timezone assumed | [E11] |

## 3. What happened

- **[confirmed]** On 14 Sep, user d.reyes deleted the public access block on bucket acme-crm-exports (EV001). [E1]
- **[confirmed]** Seconds later, d.reyes applied a bucket policy that allowed GetObject and ListBucket on the bucket, which made it public (EV002). [E2][E12]
- **[confirmed]** The bucket was made public so a vendor could test an integration. No change ticket was raised. [E12]
- **[confirmed]** On 15 Sep, the vendor-test identity downloaded a small sample file from the bucket (EV003). [E3]
- **[confirmed]** On 17 Sep, an unauthenticated requester at 198.51.100.23 using curl listed the bucket and then downloaded customers_2026Q3.csv and customers_2026Q2.csv. All three requests returned HTTP 200 (EV004, EV005, EV006). [E4][E5][E6]
- **[confirmed]** The exposed objects contained about 41,200 customer records (names, emails, phone numbers). No payment data was exposed. [E13]
- **[confirmed]** On 18 Sep, an external security researcher emailed that the bucket was publicly listable (EV007). cloud.secops re-enabled the public access block at 10:55 (EV008, EV009). [E7][E8][E9]
- **[confirmed]** After the block was restored, a further list request from 198.51.100.23 was denied with HTTP 403 (EV010). The same IP was therefore still probing the bucket after the fix. [E10]
- **[confirmed]** Legal and privacy were informed on 18 Sep at 12:00 to assess notification duties (EV011). [E11]
- **[unknown]** It is not known whether 198.51.100.23 belongs to the researcher who reported the issue. [E14]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `198.51.100.23` | ip | [E14] |

## 5. MITRE ATT&CK mapping

| Tactic | Technique | ID | Certainty | Behaviour | Evidence |
|---|---|---|---|---|---|
| collection | Data from Cloud Storage | T1530 | confirmed | An unauthenticated external requester downloaded the two customer export objects from the cloud storage bucket. | [E5][E6] |
| discovery | Cloud Storage Object Discovery | T1619 | probable | The same external IP listed the bucket contents just before downloading the files. | [E4] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**[confirmed]** A user removed the bucket's public access block and applied a read and list policy that made a production bucket holding customer data public, without a change ticket. No account-level public access block or policy guardrail existed to stop this. [E1][E2][E12][E15]

### Contributing factors

- **[confirmed]** No account-level public access block and no policy guardrail existed, so a single user could expose a bucket. [E15]
- **[confirmed]** The change was made without a change ticket, so no review step was triggered. [E12]
- **[probable]** Vendor testing was enabled by opening the bucket publicly. The bucket that held full customer exports was used for the test, although a vendor-test identity also existed. [E3][E12][E13]

## 7. Detection gaps

- **[confirmed]** No alert exists for bucket policy changes that grant access to everyone. Detection came from an outside party after 4 days. [E16]
- **[probable]** Bulk downloads of the customer files by an unauthenticated external IP on 17 Sep raised no alert. Nothing in the evidence shows internal detection before the researcher's email. [E5][E16]

## 8. Lessons learned

**Process**
- Storage access changes must go through an approved change ticket. This change bypassed review. [E12] [P1]
- Vendors need a safe path for integration testing, such as scoped credentials and test data, so that nobody opens production data to the public. [E12] [P2]

**Technology**
- Preventive guardrails are needed at account level. Without them, one user action exposed restricted data. [E15] [P2]
- Monitoring must detect public-access policy changes and anonymous bulk reads, rather than relying on outside reports. [E16]

**Governance**
- Severity follows confirmed data reads, not how fast the exposure was closed. Escalating the privacy and legal notification review quickly was correct. [E5][E11] [P3]

## 9. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Enable an account-level public access block in every cloud account and add a preventive policy guardrail that blocks public bucket policies. Any exception must be approved by security. | No account-level block or guardrail existed, so one user could expose the bucket. [E15] | [P2] | Cloud Security | Within 7 days | Prevents one user from making buckets public and avoids a repeat of this exposure. |
| critical | Complete the privacy and legal notification assessment for the 41,200 affected customers. Review all access logs for the exposure window to find any other reads, and record the limits of log coverage. | Confirmed downloads of restricted customer data by an unidentified IP. [E5][E13] | [P4][P5] | Privacy / Legal with Incident Response | Immediately and ongoing | Meets notification obligations and gives a complete picture of who accessed the data. |
| high | Create an alert for bucket policy changes or public-access-block deletions that grant access to everyone. Also alert on anonymous bulk object reads from storage access logs. | The exposure lasted 4 days and was found only through an external report. [E16] | - | Security Operations | Within 14 days | Cuts detection time from days to minutes. |
| high | Enforce approved change tickets for cloud storage access changes. Provide vendors with scoped, time-limited credentials and test data for integration testing. | The public exposure was made for a vendor test without a ticket. [E12] | [P1][P2] | Cloud Platform / IT Governance | Within 30 days | Adds review before risky access changes and gives vendors a safe test route. |
| medium | Audit all other buckets and storage shares for public policies or missing public access blocks. | The missing account-level control may have left other buckets exposed too. [E15] | - | Cloud Security | Within 14 days | Finds similar exposures before an outside party does. |

## 10. Open questions and remaining risks

- **Open:** Who operated 198.51.100.23, and is it the reporting researcher? This is not confirmed.
- **Open:** Was the downloaded data copied, retained or shared further?
- **Open:** Was security approval requested for the public exposure? Only the missing change ticket is documented.
- **Open:** Do the access logs cover the full period 14-18 Sep, and were there any other reads? Only the records provided are known.
- **Open:** What did the legal and privacy assessment decide about notifying customers or regulators?
- **Open:** Are other buckets in the account exposed in the same way?
- **Risk:** The downloaded customer names, emails and phone numbers may be held by an unidentified party and could be misused.
- **Risk:** Other storage resources may be exposed because no account-level public access block or guardrail is confirmed in place.
- **Risk:** Until alerting is added, a similar exposure would again go unnoticed by internal monitoring.

## 11. Validation log

- attempt 1: 2 validation problem(s)
- attempt 1 problem: what_happened[1]: quote '"Principal":"*"' not found in R003 (cloudtrail.json Records[1])
- attempt 1 problem: root_cause: quote '"Principal":"*"' not found in R003 (cloudtrail.json Records[1])
- attempt 2: 0 validation problem(s)

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
| E12 | notes.txt | line 2 | made acme-crm-exports public on 14 Sep |
| E13 | notes.txt | line 5 | about 41,200 customer records (names, emails, phone numbers). No payment data. |
| E14 | notes.txt | line 8 | unclear whether 198.51.100.23 is the researcher who reported the issue. Not confirmed. |
| E15 | notes.txt | line 6 | there is no account-level public access block and no policy guardrail preventing public buckets |
| E16 | notes.txt | line 7 | no alert exists for bucket policy changes that grant access to everyone |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | POL-15 §1 Change tickets | Every change to production systems, network rules, cloud permissions or storage access needs an approved change ticket. |
| P2 | POL-15 §3 Public exposure of storage | Vendor access must use scoped, time-limited credentials and test data, never public access to production data. |
| P3 | SEV-01 §2 Rules | Fast containment after detection does not lower severity if data was already taken. |
| P4 | POL-20 §4 Incidents involving restricted data | so they can assess notification duties |
| P5 | PB-04 §4 Data access | Determine whether data was read. |

_Knowledge-base sections given to the model: POL-20#4, POL-15#3, PIR-2025-031#1, POL-15#1, POL-20#1, SEV-01#2, PB-04#4, POL-15#2_

**Evidence file hashes (SHA-256)**

- `cloudtrail.json`: `2e95dfb2fe79457d28689143365fcef65b1fc1735b86ffcbc8398af37ca56df2`
- `notes.txt`: `de6dd03336b172a557a3c3cd86d25d7ee4c0445433d432ad74862e74f206d9be`
- `s3_access_logs.csv`: `94817772e13ff82dbae014dfdeb67d9a61dad58b8510ffdf36fe2c8eae822fcc`
