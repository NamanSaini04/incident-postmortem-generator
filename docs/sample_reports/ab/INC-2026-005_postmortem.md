# Incident Postmortem: INC-2026-005: Departing sales employee uploaded confidential pipeline and pricing exports to personal cloud storage

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-005 |
| Category | insider_threat |
| Severity | SEV2 |
| Classification confidence | 80% |
| Generated | 2026-11-23 20:17 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A sales employee who had resigned exported all-region opportunities and the 2027 price book from the CRM, then uploaded two files to a personal cloud service. The upload was not blocked because the DLP rule for personal cloud uploads has been in audit-only mode since the 2025 rollout. The files were probably the CRM exports. The data was pipeline forecast and pricing, with no customer personal or payment data. Any sales user can bulk-export all regions' opportunities, and there is no process to reduce export rights when someone resigns. Security reviewed the alerts the next morning as part of the weekly DLP report. CRM and VPN access were suspended and the laptop collected that afternoon. Alerts were probably not triaged in real time. Deletion of the uploaded copies from the personal cloud account is not verified, and the employee's intent is not established.

**Severity rationale:** Confirmed: a departing employee's managed laptop was used to export and upload Confidential pipeline and pricing data to personal cloud storage, and the DLP rule only logged the upload. The exported fields contain no customer personal data or payment data, so the SEV1 criteria are not met. Access was suspended and the laptop collected. Deletion of the uploaded copies is not verified.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| EV001 | 2026-11-14 10:12:00 | action=view; object=Account ACME-112; record_count=1; user=r.mehta; src_host=LT-SALES-07 | exact | [E1] |
| **EV002** | **2026-11-17 16:02:11** | **action=export; object=Opportunities (all regions); record_count=4820; user=r.mehta; src_host=LT-SALES-07** | exact | [E2] |
| **EV003** | **2026-11-17 16:05:40** | **action=export; object=Price book 2027; record_count=1; user=r.mehta; src_host=LT-SALES-07** | exact | [E3] |
| **EV004** | **2026-11-17 16:21:33** | **method=POST; url=https://upload.personal-cloud.test/v2/files; user=r.mehta; src_host=LT-SALES-07 (seen in 2 so** | exact | [E4][E5] |
| **EV005** | **2026-11-17 16:22:10** | **method=POST; url=https://upload.personal-cloud.test/v2/files; user=r.mehta; src_host=LT-SALES-07 (seen in 2 so** | exact | [E6][E7] |
| EV006 | 2026-11-17 16:30:00 | method=GET; url=https://intranet.example/hr/leave; user=r.mehta; src_host=LT-SALES-07 | exact | [E8] |
| **EV007** | **2026-11-18 09:15:00** | **2026-11-18 09:15 Security reviewed the DLP alerts as part of the weekly DLP report.** | timezone assumed | [E9] |
| **EV008** | **2026-11-18 14:00:00** | **2026-11-18 14:00 Interview with r.mehta: said the files were copied "for personal reference" and agreed to del** | timezone assumed | [E10] |
| **EV009** | **2026-11-18 14:40:00** | **2026-11-18 14:40 r.mehta's CRM and VPN access suspended; laptop collected.** | timezone assumed | [E11] |

## 3. What happened

- **[confirmed]** r.mehta (Sales) resigned on 2026-11-14 with a last working day of 2026-11-28. [E12]
- **[confirmed]** After the resignation, on 2026-11-17, r.mehta exported all-region opportunities (4820 records) and the 2027 price book from the CRM on laptop LT-SALES-07 (EV002, EV003). [E2][E3]
- **[confirmed]** Shortly after the exports, two files (Opportunities_export.xlsx and Price_book_2027.xlsx) were uploaded to a personal cloud storage destination. The DLP policy alerted in audit mode and the action was allowed (EV004, EV005). [E4][E5][E6][E7]
- **[probable]** The uploaded files were probably the CRM exports made minutes earlier. The filenames and the export objects match, but no record links them directly. [E2][E5]
- **[confirmed]** The data involved was pipeline forecast and pricing. The exported fields contain no customer personal data and no payment data. [E13]
- **[confirmed]** On 2026-11-18 Security reviewed the DLP alerts in the weekly DLP report (EV007). In an interview the employee said the files were copied "for personal reference" and agreed to delete them (EV008). CRM and VPN access were then suspended and the laptop collected (EV009). [E9][E10][E11]
- **[confirmed]** All recorded activity came from the employee's managed laptop on the office network. [E14]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `upload.personal-cloud.test` | domain | [E5] |
| `https://upload.personal-cloud.test/v2/files` | url | [E4] |

## 5. Root cause

**[confirmed]** The DLP rule for personal cloud uploads has run in audit-only mode since the 2025 rollout. It therefore logged but did not block the upload of Confidential data to personal cloud storage by a user who had just resigned. [E5][E15]

### Contributing factors

- **[confirmed]** The CRM lets any sales user bulk-export all regions' opportunities. [E16]
- **[confirmed]** No process reduces CRM export rights when an employee resigns. The exports happened three days after the resignation date. [E12][E17]

## 6. Detection gaps

- **[confirmed]** The DLP control produced alerts but was in audit mode, so it could not prevent the upload. [E7][E15]
- **[probable]** The alerts were reviewed as part of the weekly DLP report the morning after the upload, so they were probably not triaged in real time. [E9]

## 7. Lessons learned

**People**
- Insider-case handling should follow the playbook order. The laptop was collected after the interview, not before it. [E10][E11] [P1]

**Process**
- Resignation must trigger an access review. Without it, a leaver kept bulk-export rights during the notice period. [E17] [P2]

**Technology**
- A DLP rule left in audit mode only records exfiltration. Tuning-phase rules need an end date and a switch to blocking. [E15] [P3]

**Governance**
- Confidential data such as pricing and pipeline needs least-privilege export rights. [E16] [P4]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Switch the DLP rule for uploads of confidential data to personal cloud storage from audit to block mode. | The upload was only logged and allowed. Policy limits audit mode to 30 days of tuning. [E15] | [P3] | Security Engineering | Within 7 days | Prevents repeat uploads of confidential data to personal cloud storage. |
| high | Triage DLP alerts for personal cloud uploads as high and in near real time, not only in the weekly report. | The alerts were reviewed in the weekly DLP report, the morning after the upload. [E9] | [P3] | Security Operations | Within 14 days | Faster containment of uploads by departing employees. |
| high | Create a leaver workflow in which HR notifies IT of resignations and IT removes bulk-export and sensitive-data rights for the notice period unless a manager approves otherwise in writing. | No process reduced export rights after the resignation, and the exports followed three days later. [E12][E17] | [P2] | HR and IT Identity & Access | Within 30 days | Removes the bulk-export capability from leavers during the notice period. |
| high | Restrict CRM bulk export of all-region opportunities and price book data to roles with a documented business need. | Any sales user can export all regions' opportunities. [E16] | [P4] | Sales Operations and CRM Admin | Within 30 days | Reduces the volume of confidential data any one user can take. |
| high | Obtain a written deletion attestation from the employee, verify deletion where possible, and record any copies that cannot be confirmed deleted as a remaining risk. | The employee only verbally agreed to delete, and deletion from the personal cloud account is not verified. [E10][E18] | [P5] | Security Incident Response with Legal and HR | Before the last working day, 2026-11-28 | Documents and limits the residual risk from copies of confidential data. |
| medium | Update the insider-case runbook and train responders to preserve devices and logs and involve HR and legal before the interview. | The interview took place before the laptop was collected. [E10][E11] | [P1] | Security Incident Response | Within 45 days | Better evidence preservation in future insider cases. |

## 9. Open questions and remaining risks

- **Open:** Were the uploaded files deleted from the personal cloud account, and do other copies exist? (hr_ticket.txt line 10: deletion is not verified; copies may remain.)
- **Open:** What was the employee's intent? The employee said "for personal reference" and the new employer is undisclosed; neither is verified.
- **Open:** Were HR and legal involved before the interview? Was the laptop imaged and the logs preserved before the interview? The records show only that the laptop was collected after it.
- **Open:** Did the employee use other channels or earlier exports? The evidence covers only the CRM audit rows, DLP alerts and proxy rows provided.
- **Open:** Did HR notify IT of the resignation within one business day? The evidence shows no process to reduce export rights but does not record whether IT was told.
- **Risk:** Confidential pipeline forecast and pricing data may remain in the employee's personal cloud account, because deletion is not verified.
- **Risk:** The DLP rule for personal cloud uploads still allows uploads until it is switched to block mode.
- **Risk:** Any sales user can still bulk-export all-region opportunities, and there is still no process to reduce export rights when someone resigns.

## 10. Validation log

- attempt 1: 0 validation problem(s)

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
| E14 | hr_ticket.txt | line 11 | All activity came from r.mehta's managed laptop LT-SALES-07 on the office network. |
| E15 | hr_ticket.txt | line 6 | the DLP rule for personal cloud uploads has run in audit-only mode since the 2025 rollout |
| E16 | hr_ticket.txt | line 8 | the CRM lets any sales user bulk-export all regions' opportunities |
| E17 | hr_ticket.txt | line 7 | there is no process to reduce CRM export rights when an employee resigns |
| E18 | hr_ticket.txt | line 10 | deletion from the personal cloud account is not verified; copies may remain |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | PB-05 §3 Insider cases | preserve logs and devices first |
| P2 | POL-07 §5 Joiners, movers and leavers | IT reviews the leaver's access and removes bulk-export, admin and sensitive-data rights for the notice period |
| P3 | POL-12 §5 Data loss prevention | DLP rules may run in audit mode for at most 30 days of tuning |
| P4 | POL-20 §2 Confidential data | Bulk exports of confidential data require a business reason and are limited to roles that need them. |
| P5 | PB-05 §4 Deletion and copies | Obtain a written deletion attestation and verify it where possible |

_Knowledge-base sections given to the model: POL-12#5, POL-20#1, POL-07#5, POL-20#2, PB-05#4, POL-07#4, POL-15#3, PB-05#3_

**Evidence file hashes (SHA-256)**

- `crm_audit.csv`: `7d28884af6faded6d541bc4707e5803eacab9283f2f45e2ca0efc36e73cd6a3a`
- `dlp_alerts.json`: `f8546fccea8ad6e43a5a6c59b5a32cfc3d43ad85c124c6f3901cb8988595ab8e`
- `hr_ticket.txt`: `b951425f2c381ae91f31a23b92d6584aadb0202968bf888dd9790a1468dbcb3d`
- `proxy_logs.csv`: `f5d660d08c35b534192542a65ee72a8c346035254784574a49622fe7ef69ab13`
