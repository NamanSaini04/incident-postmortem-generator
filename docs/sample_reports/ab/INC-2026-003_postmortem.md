# Incident Postmortem: INC-2026-003: Customer export bucket acme-crm-exports made public for 4 days; customer files downloaded by an unidentified external party

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-003 |
| Category | data_exposure |
| Severity | SEV1 |
| Classification confidence | 90% |
| Generated | 2026-11-23 20:13 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

An employee removed the bucket's public access block and applied an everyone-readable policy on 14 Sep, so the customer export bucket was publicly listable and readable. The change was made so a vendor could test an integration. No change ticket was raised. The bucket held two customer files with about 41,200 customer records (names, emails, phone numbers). No payment data was included. On 17 Sep an unauthenticated external IP listed the bucket and downloaded both customer files successfully. Who operated that IP is not confirmed. It may or may not be the researcher who reported the issue. Detection came from an external researcher's email after 4 days. No alert existed for public-access policy changes, and no account-level block or guardrail was in place. The access block was restored about 25 minutes after the report, and a later request from the same IP was denied. Legal and privacy were informed the same day.

**Severity rationale:** Access logs confirm that both customer export files, about 41,200 records of names, emails and phone numbers, were downloaded without authentication from an external IP (what_happened[2], what_happened[3]). This is confirmed exposure of restricted customer personal data at scale. Fast containment does not lower severity when data was already taken. The identity and intent of the downloader are not confirmed.

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
| EV008 | 2026-09-18 10:55:00 | 2026-09-18 10:55 cloud.secops re-enabled the public access block on the bucket. | timezone assumed | [E8] |
| **EV009** | **2026-09-18 10:55:30** | **eventName=PutPublicAccessBlock; userName=cloud.secops** | exact | [E9] |
| **EV010** | **2026-09-18 11:02:19** | **operation=REST.GET.BUCKET; remote_ip=198.51.100.23** | exact | [E10] |
| **EV011** | **2026-09-18 12:00:00** | **Legal and privacy team informed 2026-09-18 12:00 to assess notification duties.** | timezone assumed | [E11] |

## 3. What happened

- **[confirmed]** On 14 Sep user d.reyes deleted the public access block on acme-crm-exports and then applied a bucket policy allowing everyone to get and list objects (EV001, EV002). [E1][E2]
- **[confirmed]** The bucket was made public to let a vendor test an integration. No change ticket was raised. [E12]
- **[confirmed]** The bucket held customers_2026Q3.csv and customers_2026Q2.csv, about 41,200 customer records with names, emails and phone numbers. No payment data was involved. [E13]
- **[confirmed]** On 17 Sep, IP 198.51.100.23 made unauthenticated requests: a bucket listing, then full downloads of customers_2026Q3.csv and customers_2026Q2.csv, all returning HTTP 200 (EV004-EV006). [E4][E5][E6]
- **[confirmed]** On 18 Sep at 10:30 an external security researcher emailed that the bucket was publicly listable. At 10:55 cloud.secops re-enabled the public access block (EV007, EV008, EV009). [E7][E8][E9]
- **[confirmed]** After the block was restored, a bucket listing request from 198.51.100.23 was denied with HTTP 403 (EV010). [E10]
- **[confirmed]** The legal and privacy team was informed on 18 Sep at 12:00 to assess notification duties (EV011). [E11]
- **[unknown]** It is not known whether 198.51.100.23 belongs to the researcher who reported the issue. Its intent and any onward use of the data are also unknown. [E14]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `198.51.100.23` | ip | [E14] |

## 5. Root cause

**[confirmed]** A user removed the bucket's public access block and applied an everyone-readable policy on a production bucket holding customer data, to let a vendor test an integration. No approval or change ticket was raised, and no preventive control stopped it. [E1][E2][E12][E15]

### Contributing factors

- **[confirmed]** There was no account-level public access block and no policy guardrail preventing public buckets, so one user's change was enough to expose the data. [E15]
- **[confirmed]** The change was made without a change ticket. [E12]
- **[confirmed]** Vendor testing was enabled by opening a bucket that contained customer personal data, rather than by using test data. [E12][E13]

## 6. Detection gaps

- **[confirmed]** No alert existed for bucket policy changes that grant access to everyone, so the 14 Sep change was not flagged. [E16]
- **[confirmed]** Detection came from an outside party after 4 days, not from internal monitoring. [E16]

## 7. Lessons learned

**People**
- Once the report arrived, the response was quick. The block was restored within about 25 minutes and legal and privacy were informed within 4 hours, in line with policy. [E8][E11] [P1]

**Process**
- Vendor integration testing needs a defined path with scoped credentials and test data, so staff do not open production data to the public. [E12] [P2]

**Technology**
- Preventive guardrails must make public buckets impossible without an explicit approved exception. Relying on individual users failed here. [E15] [P2]
- Internal monitoring must detect public-exposure changes. Relying on outside reporters let the exposure last 4 days, and customer files were downloaded in that time. [E5][E16]

**Governance**
- Storage access changes were made outside change control. Change tickets must be enforced and checked for cloud storage permissions. [E12] [P3]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Enable the account-level public access block in every cloud account. Add an organisation-level policy guardrail that denies removing it or granting public principals, except through an approved, time-limited exception. | A single user removed the bucket-level block and applied an everyone-readable policy because no account-level block or guardrail existed. [E15] | [P2] | Cloud security / platform | Within 7 days | Prevents accidental or unapproved public exposure of storage. |
| critical | Complete the privacy and legal assessment of notification duties for about 41,200 customers. Base it on the confirmed downloads in the access logs, and record the decision. | Access logs confirm full downloads of both customer files by an external IP. [E5][E13] | [P1] | Privacy and legal with security incident response | Immediately and ongoing | Meets regulatory and customer-notification obligations. |
| high | Create alerts for deletion of public access blocks and for bucket policies granting access to everyone. Route them to the security on-call. | The exposure went undetected for 4 days because no alert existed. [E1][E16] | [P2] | Security operations | Within 14 days | Detects exposure in minutes instead of days. |
| high | Review storage access logs for the full exposure window (14-18 Sep) for all requesters, not only 198.51.100.23. Try to establish who operates 198.51.100.23 and whether the downloaded data was retained or shared. | The downloader is unattributed, and the notes say it is not confirmed to be the reporting researcher. [E6][E14] | [P4] | Security incident response | Within 7 days | Establishes the true extent of data exposure. |
| high | Provide a vendor integration-testing path using scoped, time-limited credentials and synthetic test data. Prohibit public access to production data. | Public access to a bucket holding customer data was used for vendor testing. [E12] | [P2] | Engineering / vendor management | Within 30 days | Removes the incentive to open production data to vendors. |
| high | Audit all other buckets and file shares in all cloud accounts for public policies or missing public access blocks. | No account-level block existed, so other buckets may be exposed in the same way. [E15] | - | Cloud security | Within 7 days | Finds and closes any similar exposures. |
| medium | Enforce approved change tickets for storage permission changes. Detect cloud permission changes with no linked ticket and review them. | The public-access change was made with no ticket and no review. [E12] | [P3] | IT governance / cloud platform | Within 30 days | Creates a review point before risky storage changes. |

## 9. Open questions and remaining risks

- **Open:** Is 198.51.100.23 the researcher who reported the issue, or an unrelated party? Its intent and any onward use of the downloaded files are unknown (notes.txt line 8).
- **Open:** Does the access log export cover all requests during 14-18 Sep? Only five rows were provided, so other reads cannot be ruled out from this pack.
- **Open:** Why did 198.51.100.23 send another request at 11:02 on 18 Sep, after the researcher report and the block restoration (s3_access_logs.csv row 5)?
- **Open:** What did the privacy and legal assessment decide on notification duties? The outcome is not recorded.
- **Open:** Did the vendor actually use the public access? The one vendor-test request in the logs used an IAM identity (s3_access_logs.csv row 1). Was a time-limited exception with a named owner defined? None is recorded.
- **Open:** Times from the analyst notes are assumed to be UTC (timezone_assumed flag).
- **Risk:** The downloaded customer files (names, emails, phone numbers) are outside company control and could be misused. The downloader is unidentified.
- **Risk:** Other buckets and accounts may lack public access protections, because no account-level block or guardrail existed.
- **Risk:** Customer notification and regulatory obligations may still be pending.

## 10. Validation log

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
| E12 | notes.txt | line 2 | to let a vendor test an integration |
| E13 | notes.txt | line 5 | about 41,200 customer records (names, emails, phone numbers) |
| E14 | notes.txt | line 8 | unclear whether 198.51.100.23 is the researcher who reported the issue |
| E15 | notes.txt | line 6 | no policy guardrail preventing public buckets |
| E16 | notes.txt | line 7 | no alert exists for bucket policy changes that grant access to everyone |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | POL-20 §4 Incidents involving restricted data | the privacy and legal team must be informed within 4 hours of the security team becoming aware |
| P2 | POL-15 §3 Public exposure of storage | Vendor access must use scoped, time-limited credentials and test data, never public access to production data. |
| P3 | POL-15 §1 Change tickets | Every change to production systems, network rules, cloud permissions or storage access needs an approved change ticket. |
| P4 | PB-04 §4 Data access | Determine whether data was read. |

_Knowledge-base sections given to the model: POL-20#4, POL-15#3, PIR-2025-031#1, POL-15#1, POL-20#1, SEV-01#2, PB-04#4, POL-15#2_

**Evidence file hashes (SHA-256)**

- `cloudtrail.json`: `2e95dfb2fe79457d28689143365fcef65b1fc1735b86ffcbc8398af37ca56df2`
- `notes.txt`: `de6dd03336b172a557a3c3cd86d25d7ee4c0445433d432ad74862e74f206d9be`
- `s3_access_logs.csv`: `94817772e13ff82dbae014dfdeb67d9a61dad58b8510ffdf36fe2c8eae822fcc`
