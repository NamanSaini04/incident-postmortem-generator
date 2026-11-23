# Incident Postmortem: INC-2026-003: INC-2026-003: Customer CRM export bucket publicly exposed for about 4 days

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-003 |
| Category | data_exposure |
| Severity | SEV2 |
| Classification confidence | 90% |
| Generated | 2026-11-23 19:21 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

On 14 Sep an engineer (d.reyes) removed the public access block on acme-crm-exports and applied a bucket policy allowing everyone to list and read it. The stated purpose was a vendor integration test, and no change ticket was raised. On 17 Sep an anonymous client at 198.51.100.23 listed the bucket and downloaded customers_2026Q3.csv and customers_2026Q2.csv. An external researcher reported the exposure on 18 Sep, and cloud.secops restored the block about 25 minutes later. No account-level guardrail prevented the change and no alert fired, so detection took about 4 days and came from outside the company. It is not confirmed whether the downloading IP belongs to the researcher. Legal and privacy were informed to assess notification duties.

**Severity rationale:** The bucket held about 41,200 customer records (names, emails, phone numbers) and was publicly listable. Both customer files were served in full to an unauthenticated external IP, so unauthorized copying of the data is confirmed. No payment data was involved, and the exposure was closed within about 25 minutes of the external report. Whether notification is required is still being assessed.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| **EV001** | **2026-09-14 16:02:11** | **eventName=DeletePublicAccessBlock; userName=d.reyes** | exact | [E1] |
| **EV002** | **2026-09-14 16:02:48** | **eventName=PutBucketPolicy; userName=d.reyes** | exact | [E2] |
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

- **[confirmed]** User d.reyes deleted the public access block on acme-crm-exports (EV001). [E1]
- **[confirmed]** About 40 seconds later d.reyes applied a bucket policy allowing GetObject and ListBucket to all principals (EV002). [E2]
- **[confirmed]** The change was made so a vendor could test an integration, and no change ticket was raised. [E12]
- **[probable]** On 15 Sep the IAM user vendor-test fetched sample_10rows.csv from the bucket (EV003). This is consistent with the intended vendor test. [E3]
- **[confirmed]** On 17 Sep an unauthenticated client at 198.51.100.23 using curl listed the bucket (EV004) and downloaded customers_2026Q3.csv (EV005) and customers_2026Q2.csv (EV006). All requests returned HTTP 200 with tens of megabytes sent per file. [E4][E5][E6]
- **[confirmed]** The exposed files contained about 41,200 customer records (names, emails, phone numbers). No payment data was involved. [E13]
- **[confirmed]** An external security researcher emailed on 18 Sep reporting the bucket was publicly listable (EV007). cloud.secops re-enabled the public access block at 10:55 (EV008, EV009). [E7][E8][E9]
- **[confirmed]** After the block was restored, a bucket listing request from 198.51.100.23 was denied with HTTP 403 (EV010). [E10]
- **[confirmed]** Legal and privacy were informed on 18 Sep to assess notification duties (EV011). [E11]
- **[unknown]** Whether 198.51.100.23 is the researcher who reported the issue is not confirmed. [E14]

## 4. Indicators of compromise

_None identified._

## 5. Root cause

**[confirmed]** A manual, untracked change removed the bucket's public access block and applied an allow-all-principals policy to a bucket holding customer exports. The environment had no account-level public access block or policy guardrail to stop it. [E1][E2][E12][E15]

### Contributing factors

- **[confirmed]** No change ticket or review was raised for the exposure, so no approval or risk check took place. [E12]
- **[confirmed]** No account-level public access block or policy guardrail existed, so a single user could make the bucket public. [E15]
- **[possible]** The bucket held full customer exports while it was made public for a test that fetched only a small sample file. Test data or scoped access might have avoided the exposure. Whether the vendor needed public access is not established. [E3][E13]

## 6. Detection gaps

- **[confirmed]** No alert existed for bucket policy changes that grant access to everyone. [E16]
- **[confirmed]** Detection came from an outside party after 4 days, not from internal monitoring. Neither the removal of the public access block nor the anonymous downloads on 17 Sep triggered internal detection. [E7][E16]

## 7. Lessons learned

**People**
- Once the report arrived, the response was quick: the block was restored about 25 minutes after the email, and Legal and privacy were engaged the same day. This should be preserved in the runbook. [E7][E8][E11]

**Process**
- Temporary external access for vendors must go through a ticketed, reviewed and time-boxed process. [E12]

**Technology**
- Preventive guardrails are needed so that public exposure of a bucket cannot be enabled by one user's manual change. [E15]
- Alerting on high-risk storage permission changes would have shortened a 4-day exposure that was found only through an external report. [E16]

## 8. Corrective actions

| Priority | Action | Why | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|
| critical | Enable account-level S3 public access block and add an organization-level policy guardrail that denies removing it or attaching allow-all-principals bucket policies, with a tightly controlled exception path. | No account-level block or guardrail existed, which allowed the single-user change. [E15] | Cloud Platform / Cloud Security | Within 1 week | Prevents accidental or unreviewed public exposure of buckets across the account. |
| critical | Complete the scope assessment. Review all access logs for acme-crm-exports across the full exposure window for any requester besides 198.51.100.23, and attempt to establish whether 198.51.100.23 is the reporting researcher, for example by asking the researcher. | Both customer files were downloaded by an unattributed external IP, and its link to the researcher is unconfirmed. [E5][E6][E14] | Incident Response | Within 3 days | Establishes the true extent of data access to inform notification decisions. |
| high | Create high-severity alerts on DeletePublicAccessBlock and on PutBucketPolicy statements granting access to all principals, routed to the security on-call. | No alert existed, and detection took 4 days via an outside party. [E1][E16] | Security Operations | Within 2 weeks | Reduces time to detect risky exposure from days to minutes. |
| high | Support Legal and privacy with a data inventory of the two exposed files so they can finalize notification duties for the affected customers. | About 41,200 customer records were exposed and were downloaded by an external party. [E11][E13] | Legal & Privacy with Incident Response | Per regulatory deadlines; start immediately | Meets legal obligations and supports affected customers. |
| medium | Require a ticketed change with security review for any external data sharing. Use scoped, time-limited access for the named vendor and sample or masked data for integration tests instead of making a bucket public. | The bucket was made public for a vendor test with no change ticket, and the test fetched only a small sample file. [E3][E12] | Engineering Management / Cloud Security | Within 30 days | Allows vendor testing without exposing production customer data. |

## 9. Open questions and remaining risks

- **Open:** Is 198.51.100.23 the external researcher who reported the issue? The notes say this is not confirmed (R012).
- **Open:** Did any other party access the bucket during the exposure window? Only the access log rows in the evidence pack were reviewed, and their completeness is not established.
- **Open:** Was public access actually needed for the vendor test, given that the vendor-test IAM user made an authenticated request (R014)?
- **Open:** Do other buckets share this misconfiguration risk? The notes state there is no account-level guardrail (R010), but no other buckets were reviewed in this evidence.
- **Risk:** The two customer files were downloaded by an external party, and the data cannot be recalled. The downstream use of the data is unknown.
- **Risk:** Without an account-level public access block or guardrail, the same exposure could recur on this or other buckets until the corrective actions are completed.
- **Risk:** Notification obligations are still being assessed, and affected customers may be at risk of phishing or social engineering using names, emails and phone numbers.

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
| E14 | notes.txt | line 8 | unclear whether 198.51.100.23 is the researcher who reported the issue. Not confirmed. |
| E15 | notes.txt | line 6 | there is no account-level public access block and no policy guardrail preventing public buckets |
| E16 | notes.txt | line 7 | no alert exists for bucket policy changes that grant access to everyone |

**Evidence file hashes (SHA-256)**

- `cloudtrail.json`: `2e95dfb2fe79457d28689143365fcef65b1fc1735b86ffcbc8398af37ca56df2`
- `notes.txt`: `de6dd03336b172a557a3c3cd86d25d7ee4c0445433d432ad74862e74f206d9be`
- `s3_access_logs.csv`: `94817772e13ff82dbae014dfdeb67d9a61dad58b8510ffdf36fe2c8eae822fcc`
