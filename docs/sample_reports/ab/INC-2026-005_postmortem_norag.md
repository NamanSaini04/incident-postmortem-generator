# Incident Postmortem: INC-2026-005: Resigned sales employee exported CRM pipeline and pricing data and uploaded it to personal cloud storage

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-005 |
| Category | insider_threat |
| Severity | SEV2 |
| Classification confidence | 65% |
| Generated | 2026-11-23 20:16 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A sales employee who had resigned exported all-region opportunities and the 2027 price book from the CRM and uploaded both files to a personal cloud storage site. DLP flagged both uploads, but the rule was audit-only, so the uploads were allowed. Security reviewed the alerts the next day in the weekly DLP report, interviewed the employee, suspended CRM and VPN access and collected the laptop. The data was pipeline forecast and pricing. The exported fields contained no customer personal data or payment data. The incident was probably enabled by unrestricted bulk export in the CRM, no reduction of export rights on resignation, and a non-blocking DLP rule. Deletion of the uploaded files from the personal cloud account is not verified, so copies may remain.

**Severity rationale:** A user with legitimate access exported all-region opportunities and the 2027 price book and uploaded both files to personal cloud storage. The DLP rule only audited the uploads and did not block them. Access was suspended and the laptop collected, so the incident is contained. The exported fields contain no customer personal data or payment data, so SEV1 is not met. Deletion of the copies is unverified, so the exposure is not confirmed closed.

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
| EV008 | 2026-11-18 14:00:00 | 2026-11-18 14:00 Interview with r.mehta: said the files were copied "for personal reference" and agreed to del | timezone assumed | [E10] |
| **EV009** | **2026-11-18 14:40:00** | **2026-11-18 14:40 r.mehta's CRM and VPN access suspended; laptop collected.** | timezone assumed | [E11] |

## 3. What happened

- **[confirmed]** User r.mehta exported all-region opportunities (4820 records) from the CRM on the managed laptop LT-SALES-07. [E2]
- **[confirmed]** A few minutes later the same user exported the 2027 price book. [E3]
- **[confirmed]** Both exported files were uploaded from LT-SALES-07 to a personal cloud storage destination, as shown by proxy POST requests and matching DLP alerts. [E4][E5][E6][E7]
- **[confirmed]** The DLP policy for uploads to personal cloud storage fired for both uploads but was in audit mode, and the action was recorded as allowed. [E5][E7]
- **[confirmed]** The user had resigned before the exports, with a last working day of 2026-11-28. [E12]
- **[confirmed]** Security reviewed the DLP alerts the next day as part of the weekly DLP report (EV007). [E9]
- **[confirmed]** In the interview, the user said the files were copied for personal reference and agreed to delete them. The stated motive is the user's own account and is not independently verified. [E10]
- **[confirmed]** CRM and VPN access were suspended and the laptop was collected (EV009). [E11]
- **[confirmed]** The data involved was pipeline forecast and pricing. The exported fields contain no customer personal data or payment data. [E13]
- **[unknown]** Whether the uploaded files were deleted from the personal cloud account is not verified, and copies may remain. [E14]
- **[confirmed]** All recorded activity came from the user's managed laptop on the office network. [E15]

## 4. Indicators of compromise

_None identified._

## 5. Root cause

**[probable]** Preventive controls probably did not stop a resigned employee from taking company data. The CRM allowed bulk export of all regions' opportunities, export rights were not reduced on resignation, and the DLP rule for personal cloud uploads only audited and did not block. [E16][E17][E18]

### Contributing factors

- **[confirmed]** Any sales user can bulk-export all regions' opportunities from the CRM. [E16]
- **[confirmed]** There is no process to reduce CRM export rights when an employee resigns. [E12][E17]
- **[confirmed]** The DLP rule for personal cloud uploads has run in audit-only mode since the 2025 rollout. [E18]

## 6. Detection gaps

- **[confirmed]** DLP detected the uploads but could not stop them because the rule was audit-only. The alerts were reviewed in the weekly DLP report, which is a periodic review rather than real-time response. [E5][E9]

## 7. Lessons learned

**Process**
- HR resignation events were not connected to access reduction. The employee kept full export ability for days after resigning. [E2][E17]

**Technology**
- A DLP rule left in audit mode since rollout detects exfiltration but does not prevent it. Both uploads completed. [E7][E18]

**Governance**
- Broad default export rights in the CRM let one user take all-region pipeline and pricing data. Least-privilege export entitlements are needed. [E16]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Verify and enforce removal of the uploaded files from the personal cloud account through HR and legal channels, and obtain written confirmation from the employee. Complete this before the last working day. | Deletion is unverified and copies may remain. The employee's last working day is 2026-11-28. [E12][E14] | - | Security with HR and Legal | Immediately (before 2026-11-28) | Reduces the risk of continued exposure of pipeline and pricing data. |
| high | Move the DLP personal cloud upload rule from audit to block, after testing for false positives. | Audit-only mode allowed both uploads. [E5][E18] | - | Security Engineering | 30 days | Prevents uploads of sensitive files to personal storage. |
| high | Restrict CRM bulk export to roles that need it, scoped by region, and require approval or alerting for large exports. | Any sales user can bulk-export all regions' opportunities. [E2][E16] | - | Sales Operations / CRM Admin | 60 days | Limits the data one user can take. |
| high | Create a resignation process that reduces CRM export rights and adds monitoring for departing employees as soon as notice is given. | No process exists, and the exports happened days after resignation. [E12][E17] | - | HR with Security and IT | 45 days | Closes the exposure window between resignation and departure. |
| medium | Review DLP alerts for departing employees daily instead of only in the weekly report. | The alerts were reviewed only in the weekly report. [E9] | - | Security Operations | 30 days | Faster containment of departing-employee data movement. |

## 9. Open questions and remaining risks

- **Open:** Were the uploaded files deleted from the personal cloud account, and do any copies remain? (hr_ticket.txt line 10)
- **Open:** What was the employee's real intent, and is there any link to the new employer, which has not been disclosed? (hr_ticket.txt line 2, hr_ticket.txt line 4)
- **Open:** Were there other exports or uploads outside the records provided, for example from other devices or accounts? Only LT-SALES-07 activity is recorded. (hr_ticket.txt line 11)
- **Open:** Did any alert or review fire on the CRM exports themselves? None is recorded. (crm_audit.csv row 2)
- **Risk:** Copies of pipeline forecast and pricing data may remain in the employee's personal cloud account. (hr_ticket.txt line 10)
- **Risk:** The same control gaps (unrestricted export, audit-only DLP, no resignation process) still apply to other employees until fixed. (hr_ticket.txt line 6, hr_ticket.txt line 7, hr_ticket.txt line 8)

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
| E13 | hr_ticket.txt | line 9 | Data involved: pipeline forecast and pricing. |
| E14 | hr_ticket.txt | line 10 | deletion from the personal cloud account is not verified; copies may remain |
| E15 | hr_ticket.txt | line 11 | managed laptop LT-SALES-07 |
| E16 | hr_ticket.txt | line 8 | the CRM lets any sales user bulk-export all regions' opportunities |
| E17 | hr_ticket.txt | line 7 | there is no process to reduce CRM export rights when an employee resigns |
| E18 | hr_ticket.txt | line 6 | has run in audit-only mode since the 2025 rollout |

**Evidence file hashes (SHA-256)**

- `crm_audit.csv`: `7d28884af6faded6d541bc4707e5803eacab9283f2f45e2ca0efc36e73cd6a3a`
- `dlp_alerts.json`: `f8546fccea8ad6e43a5a6c59b5a32cfc3d43ad85c124c6f3901cb8988595ab8e`
- `hr_ticket.txt`: `b951425f2c381ae91f31a23b92d6584aadb0202968bf888dd9790a1468dbcb3d`
- `proxy_logs.csv`: `f5d660d08c35b534192542a65ee72a8c346035254784574a49622fe7ef69ab13`
