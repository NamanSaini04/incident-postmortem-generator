# Incident Postmortem: INC-2026-005: Departing sales employee exported CRM pipeline and pricing data and uploaded files to personal cloud storage

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-005 |
| Category | insider_threat |
| Severity | SEV2 |
| Classification confidence | 75% |
| Generated | 2026-11-23 19:47 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

After resigning, a sales employee exported all-region opportunities and the 2027 price book from the CRM. Two uploads to a personal cloud storage service followed within about 20 minutes. The uploads probably contained the exported files, because the file names match, but this is not confirmed from file content. The DLP rule logged both uploads but allowed them, because the rule runs in audit-only mode. The data involved was pipeline forecast and pricing. The exported fields contain no customer personal data or payment data. The exposure was probably enabled by an audit-only DLP rule, unrestricted bulk export rights in the CRM, and no process to reduce export rights on resignation. Security reviewed the DLP alerts on 2026-11-18. The employee was interviewed, CRM and VPN access were suspended, and the laptop was collected. Deletion of the uploaded files from the personal cloud account is not verified, and copies may remain.

**Severity rationale:** A resigned employee's account confirmed exports of pipeline and pricing data from the CRM. Two uploads to personal cloud storage followed, and the files were probably the exported data. The DLP control allowed the uploads. Access was suspended and the laptop collected. The exported fields contain no customer personal or payment data, so SEV1 is not met. Deletion of external copies is not verified, so containment is incomplete.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| EV001 | 2026-11-14 10:12:00 | action=view; user=r.mehta; src_host=LT-SALES-07 | exact | [E1] |
| **EV002** | **2026-11-17 16:02:11** | **action=export; user=r.mehta; src_host=LT-SALES-07** | exact | [E2] |
| **EV003** | **2026-11-17 16:05:40** | **action=export; user=r.mehta; src_host=LT-SALES-07** | exact | [E3] |
| **EV004** | **2026-11-17 16:21:33** | **method=POST; url=https://upload.personal-cloud.test/v2/files; user=r.mehta; src_host=LT-SALES-07 (seen in 2 so** | exact | [E4][E5] |
| **EV005** | **2026-11-17 16:22:10** | **method=POST; url=https://upload.personal-cloud.test/v2/files; user=r.mehta; src_host=LT-SALES-07 (seen in 2 so** | exact | [E6][E7] |
| EV006 | 2026-11-17 16:30:00 | method=GET; url=https://intranet.example/hr/leave; user=r.mehta; src_host=LT-SALES-07 | exact | [E8] |
| **EV007** | **2026-11-18 09:15:00** | **2026-11-18 09:15 Security reviewed the DLP alerts as part of the weekly DLP report.** | timezone assumed | [E9] |
| EV008 | 2026-11-18 14:00:00 | 2026-11-18 14:00 Interview with r.mehta: said the files were copied "for personal reference" and agreed to del | timezone assumed | [E10] |
| **EV009** | **2026-11-18 14:40:00** | **2026-11-18 14:40 r.mehta's CRM and VPN access suspended; laptop collected.** | timezone assumed | [E11] |

## 3. What happened

- **[confirmed]** r.mehta (Sales) resigned on 2026-11-14 with a last working day of 2026-11-28. [E12]
- **[confirmed]** On 2026-11-17 r.mehta exported all-region opportunities (4820 records) and the 2027 price book from the CRM on LT-SALES-07 (EV002, EV003). [E2][E3]
- **[probable]** Within about 20 minutes of the exports, two POST uploads from LT-SALES-07 to a personal cloud storage destination were recorded (EV004, EV005). DLP alerts name the files Opportunities_export.xlsx and Price_book_2027.xlsx. The file names match the exports, so it is probable that these are the exported data. [E4][E5][E7]
- **[confirmed]** The DLP policy for uploads to personal cloud storage fired for both uploads but only audited them; the action was allowed. [E5][E7]
- **[confirmed]** The data involved was pipeline forecast and pricing. The exported fields contain no customer personal data and no payment data. [E13]
- **[confirmed]** Security reviewed the DLP alerts on 2026-11-18 as part of the weekly DLP report (EV007). [E9]
- **[confirmed]** In an interview the employee said the files were copied for personal reference and agreed to delete them. CRM and VPN access were then suspended and the laptop collected (EV008, EV009). [E10][E11]
- **[unknown]** Whether the uploaded files were deleted from the personal cloud account is not verified. [E14]
- **[confirmed]** All activity came from the employee's managed laptop LT-SALES-07 on the office network. [E15]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `upload.personal-cloud.test` | domain | [E5] |
| `https://upload.personal-cloud.test/v2/files` | url | [E4] |

## 5. Root cause

**[probable]** The upload was probably possible because the personal-cloud DLP rule was audit-only and logged without blocking. This was compounded by unrestricted bulk CRM export rights, with no reduction of export rights after resignation. [E16][E17][E18]

### Contributing factors

- **[confirmed]** No process exists to reduce CRM export rights when an employee resigns. The exports happened three days after the resignation date. [E12][E18]
- **[confirmed]** The CRM lets any sales user bulk-export all regions' opportunities, which is broader than a single user's role may need. [E17]

## 6. Detection gaps

- **[confirmed]** The DLP rule for personal cloud uploads has run in audit-only mode since the 2025 rollout, so it detected but did not prevent the uploads. [E5][E16]
- **[probable]** The alerts were reviewed the next morning in the weekly DLP report rather than at upload time. The evidence shows no real-time alerting or response, so the data stayed outside the company for several hours before review. [E5][E9]

## 7. Lessons learned

**Process**
- Resignation should trigger a review of data access and export rights for the departing employee. [E18]
- Containment steps that rely on the employee deleting data need verification. [E14]

**Technology**
- A DLP rule that only audits cannot stop exfiltration. Rules covering high-risk destinations need a blocking mode. [E7][E16]

**Governance**
- Bulk-export privileges in the CRM should follow least privilege rather than being open to any sales user. [E17]

## 8. Corrective actions

| Priority | Action | Why | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|
| high | Move the personal-cloud upload DLP rule from audit-only to block mode, with a tested exception process. | The rule logged both uploads but allowed them. [E5][E16] | Security Engineering | 30 days | Uploads of company files to personal storage are stopped when they happen, not just logged. |
| high | Create an HR-to-IT process that restricts CRM bulk-export rights and raises DLP monitoring when a resignation is recorded. | No process reduces export rights on resignation. The exports occurred three days after the resignation date. [E12][E18] | HR and IT Security | 60 days | Less risk of data leaving with departing staff. |
| high | Pursue verified deletion of the uploaded files, through the employee's written attestation and legal channels, and record the outcome. | Deletion is unverified and copies may remain. [E14] | Legal and Security | 7 days | Lower risk that pricing and pipeline data remain outside company control. |
| medium | Restrict bulk export of all-region opportunities to roles that need it, and alert on large exports. | Any sales user can bulk-export all regions' opportunities. [E2][E17] | CRM Administration | 60 days | Smaller exposure from any single account. |
| medium | Triage high-risk DLP alerts, such as uploads to personal cloud storage, in near real time rather than only in the weekly report. | The alerts were reviewed as part of the weekly DLP report the day after the uploads. [E9] | Security Operations | 45 days | Faster containment of exfiltration. |

## 9. Open questions and remaining risks

- **Open:** Were the uploaded files deleted from the personal cloud account, and were they copied or shared further? (hr_ticket.txt line 10)
- **Open:** Do the uploaded files contain the exported CRM data? Only file names link the uploads to the exports; file content was not compared.
- **Open:** What was the employee's intent, and is the data intended for the new employer? The new employer was not disclosed. (hr_ticket.txt line 2)
- **Open:** Did the employee move data through any channel other than the two logged uploads? The evidence pack covers only the CRM audit, DLP and proxy records.
- **Open:** Did the CRM or any other control flag the 4820-record export at the time? The evidence shows no such alert.
- **Open:** The times for 2026-11-18 events are marked as timezone assumed (EV007 to EV009), so the exact gap between upload and review is approximate.
- **Risk:** Copies of the pipeline forecast and 2027 pricing may remain in the personal cloud account (hr_ticket.txt line 10).
- **Risk:** The DLP rule and CRM export rights are unchanged in the evidence, so the same exposure path remains for other departing employees (hr_ticket.txt line 6, hr_ticket.txt line 8).

## 10. Validation log

- attempt 1: 1 validation problem(s)
- attempt 2: 0 validation problem(s)

## Evidence index

| Ref | File | Location | Quote |
|---|---|---|---|
| E1 | crm_audit.csv | row 1 | 2026-11-14T10:12:00Z |
| E2 | crm_audit.csv | row 2 | 2026-11-17T16:02:11Z |
| E3 | crm_audit.csv | row 3 | 2026-11-17T16:05:40Z |
| E4 | proxy_logs.csv | row 1 | 2026-11-17T16:21:33Z |
| E5 | dlp_alerts.json | alerts[0] | 2026-11-17T16:21:35Z |
| E6 | proxy_logs.csv | row 2 | 2026-11-17T16:22:10Z |
| E7 | dlp_alerts.json | alerts[1] | 2026-11-17T16:22:12Z |
| E8 | proxy_logs.csv | row 3 | 2026-11-17T16:30:00Z |
| E9 | hr_ticket.txt | line 3 | 2026-11-18 09:15 |
| E10 | hr_ticket.txt | line 4 | 2026-11-18 14:00 |
| E11 | hr_ticket.txt | line 5 | 2026-11-18 14:40 |
| E12 | hr_ticket.txt | line 2 | resigned on 2026-11-14 with a last working day of 2026-11-28 |
| E13 | hr_ticket.txt | line 9 | The exported fields contain no customer personal data and no payment data. |
| E14 | hr_ticket.txt | line 10 | deletion from the personal cloud account is not verified; copies may remain |
| E15 | hr_ticket.txt | line 11 | All activity came from r.mehta's managed laptop LT-SALES-07 on the office network. |
| E16 | hr_ticket.txt | line 6 | the DLP rule for personal cloud uploads has run in audit-only mode since the 2025 rollout |
| E17 | hr_ticket.txt | line 8 | the CRM lets any sales user bulk-export all regions' opportunities |
| E18 | hr_ticket.txt | line 7 | there is no process to reduce CRM export rights when an employee resigns |

**Evidence file hashes (SHA-256)**

- `crm_audit.csv`: `7d28884af6faded6d541bc4707e5803eacab9283f2f45e2ca0efc36e73cd6a3a`
- `dlp_alerts.json`: `f8546fccea8ad6e43a5a6c59b5a32cfc3d43ad85c124c6f3901cb8988595ab8e`
- `hr_ticket.txt`: `b951425f2c381ae91f31a23b92d6584aadb0202968bf888dd9790a1468dbcb3d`
- `proxy_logs.csv`: `f5d660d08c35b534192542a65ee72a8c346035254784574a49622fe7ef69ab13`
