# Incident Postmortem: INC-2026-003: Customer CRM export bucket made public and customer files downloaded by an unidentified external party

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-003 |
| Category | data_exposure |
| Severity | SEV1 |
| Classification confidence | 85% |
| Generated | 2026-11-23 20:12 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A staff member removed the bucket's public access block and applied a policy allowing everyone to list and read the bucket, to let a vendor test an integration. No change ticket was raised. Two customer files (about 41,200 records of names, emails and phone numbers) were exposed, and the logs show both were downloaded anonymously by an external IP on 17 Sep. The exposure was found only when an outside researcher emailed, about 4 days after it began. No internal alert exists for policy changes granting public access. Secops re-enabled the public access block within 25 minutes of the report. A later anonymous request was denied, which suggests the exposure was closed. The exposure was possible because no account-level public access block or policy guardrail existed. It is not confirmed whether the downloading IP belongs to the reporting researcher. Legal and privacy are assessing notification duties.

**Severity rationale:** Customer personal data (about 41,200 records: names, emails, phone numbers) sat in a publicly accessible bucket. Access logs show both customer files were downloaded by an unauthenticated external IP before the exposure was closed. Legal and privacy were engaged to assess notification duties. No payment data was involved. The downloader's identity and intent are not confirmed, but the exposure and download are.

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
| EV010 | 2026-09-18 11:02:19 | operation=REST.GET.BUCKET; remote_ip=198.51.100.23 | exact | [E10] |
| **EV011** | **2026-09-18 12:00:00** | **Legal and privacy team informed 2026-09-18 12:00 to assess notification duties.** | timezone assumed | [E11] |

## 3. What happened

- **[confirmed]** User d.reyes deleted the public access block on bucket acme-crm-exports. [E1]
- **[confirmed]** Within a minute, d.reyes applied a bucket policy that allowed all principals to read objects and list the bucket (EV002). [E2]
- **[confirmed]** The change was made so a vendor could test an integration. No change ticket was raised. [E12]
- **[probable]** On 15 Sep the vendor-test identity retrieved a small sample file from the bucket (EV003). This is consistent with the stated purpose, and nothing in the evidence suggests misuse. [E3]
- **[confirmed]** On 17 Sep an unauthenticated requester at 198.51.100.23 listed the bucket and then downloaded customers_2026Q3.csv and customers_2026Q2.csv, both with HTTP 200 (EV004-EV006). [E4][E5][E6]
- **[confirmed]** The exposure was reported by an external security researcher by email on 18 Sep. Detection came from an outside party about 4 days after the exposure began. [E7][E13]
- **[confirmed]** cloud.secops re-enabled the public access block 25 minutes after the report (EV008, EV009). A later anonymous request from 198.51.100.23 was refused with 403 (EV010). [E8][E9][E10]
- **[confirmed]** The exposed files contain about 41,200 customer records (names, emails, phone numbers). No payment data was involved. Legal and privacy were informed to assess notification duties. [E11][E14]
- **[unknown]** Whether the downloading IP 198.51.100.23 is the researcher who reported the issue is not known. [E15]

## 4. Indicators of compromise

_None identified._

## 5. Root cause

**[confirmed]** A user was able to remove the bucket's public access block and apply an allow-everyone policy on a bucket holding customer exports, with no change approval. No account-level public access block or policy guardrail existed to prevent it. [E1][E12][E16]

### Contributing factors

- **[confirmed]** There was no account-level public access block and no policy guardrail preventing public buckets. [E16]
- **[confirmed]** The temporary public exposure for vendor testing bypassed change management, so no reviewer assessed the risk or set an end date. [E12]
- **[probable]** The bucket held full customer exports while it was being used for an integration test, so a policy change exposed real customer data. [E12][E14]

## 6. Detection gaps

- **[confirmed]** No alert exists for bucket policy changes that grant access to everyone, so the public policy went unnoticed for about 4 days. [E13]
- **[probable]** Detection depended on an outside researcher. The evidence shows no internal detection of the anonymous listing and downloads on 17 Sep. [E5][E13]

## 7. Lessons learned

**Process**
- Temporary external sharing needs a ticketed approval with a defined scope and expiry. The unticketed change had neither. [E12]
- The response to the researcher's report was fast, with the block restored 25 minutes after the email and Legal engaged the same day. External reports should keep a clear route to secops. [E8][E11]

**Technology**
- Preventive account-level controls are needed, because relying on individual users to keep buckets private failed. [E16]
- Monitoring should alert on changes that make storage public, so exposure is found in minutes rather than by outsiders after days. [E13]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Enable an account-level public access block, and add a preventive policy guardrail that stops users from deleting the block or attaching allow-everyone bucket policies without a break-glass approval. | Nothing technical prevented the user from making a customer-data bucket public. [E2][E16] | - | Cloud Platform / Security Engineering | Within 7 days | Prevents a single user action from exposing a bucket publicly. |
| critical | Complete the privacy and legal assessment of notification duties for the roughly 41,200 affected customers, using the access log evidence of the two downloads. | Customer personal data was confirmed downloaded by an external party. [E11][E14] | - | Legal and Privacy | Immediate, per regulatory deadlines | Meets legal obligations and supports affected customers. |
| high | Create a high-severity alert for deletion of public access blocks and for bucket policies that grant access to all principals, routed to the security on-call. | The exposure was found by an outside party after about 4 days because no alert existed. [E1][E13] | - | Security Operations | Within 14 days | Cuts detection time from days to minutes. |
| high | Require a change ticket for any external sharing. Share with vendors through scoped, time-limited access for named identities, and keep customer exports out of buckets used for integration tests. | Public access was granted without a ticket for a vendor test, in a bucket that held full customer exports. [E12] | - | Cloud Platform / IT Change Management | Within 30 days | Provides approval, scoping and expiry for vendor access. |
| high | Resolve who operates 198.51.100.23, for example by asking the reporting researcher to confirm. Review access logs for the whole exposure window for any other external access. | The downloader's identity is unconfirmed, and the sources of the remaining downloads are only partly established. [E5][E15] | - | Security Operations / Incident Response | Within 7 days | Establishes whether the data went to a researcher or to an unknown party. |
| medium | Audit all other buckets for public policies or missing public access blocks. | The missing guardrail was account-wide, so other buckets may be exposed in the same way. [E16] | - | Cloud Security | Within 14 days | Finds and closes similar exposures. |

## 9. Open questions and remaining risks

- **Open:** Is 198.51.100.23 the researcher who reported the issue, or an unrelated party? The evidence does not confirm either.
- **Open:** Were the downloaded files copied or shared onward? Nothing in the evidence shows.
- **Open:** Why was bucket-wide public access used instead of scoped access for the vendor-test identity? The notes do not say.
- **Open:** Were any other buckets or accounts changed in the same way? The evidence covers only acme-crm-exports.
- **Open:** Is the access log complete for the whole exposure window? The evidence shows only five rows.
- **Risk:** Customer names, emails and phone numbers were downloaded by an unconfirmed party, creating a risk of phishing or misuse of the contact data.
- **Risk:** No account-level block or guardrail is in place yet, so the same exposure could recur until corrective actions are completed.

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
| E12 | notes.txt | line 2 | made acme-crm-exports public on 14 Sep to let a vendor test an integration |
| E13 | notes.txt | line 7 | Detection came from an outside party after 4 days. |
| E14 | notes.txt | line 5 | about 41,200 customer records (names, emails, phone numbers) |
| E15 | notes.txt | line 8 | unclear whether 198.51.100.23 is the researcher who reported the issue |
| E16 | notes.txt | line 6 | there is no account-level public access block and no policy guardrail preventing public buckets |

**Evidence file hashes (SHA-256)**

- `cloudtrail.json`: `2e95dfb2fe79457d28689143365fcef65b1fc1735b86ffcbc8398af37ca56df2`
- `notes.txt`: `de6dd03336b172a557a3c3cd86d25d7ee4c0445433d432ad74862e74f206d9be`
- `s3_access_logs.csv`: `94817772e13ff82dbae014dfdeb67d9a61dad58b8510ffdf36fe2c8eae822fcc`
