# Incident Postmortem: INC-2026-005: Sales leaver uploaded confidential pipeline and pricing exports to personal cloud storage

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-005 |
| Category | insider_threat |
| Severity | SEV2 |
| Classification confidence | 80% |
| Generated | 2026-11-23 20:45 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A sales employee who had resigned exported all-region opportunities (4,820 records) and the 2027 price book from the CRM on 2026-11-17. Two uploads to a personal cloud storage site followed from the managed laptop. The DLP rule only logged them and allowed them. The data was confidential pipeline and pricing data. The exported fields contained no customer personal or payment data. Security reviewed the alerts the next morning in the weekly DLP report, and CRM and VPN access was suspended and the laptop collected later that day. No earlier triage is recorded, so earlier triage probably did not happen. Contributing factors: no process to cut export rights on resignation, and any sales user can bulk-export all regions. Deletion of the uploaded files from the personal cloud account is not verified, so copies may remain. This is not confirmed either way.

**Severity rationale:** Confirmed upload of confidential pricing and pipeline data to personal cloud storage by a user who had resigned. Access was suspended and the laptop collected within about a day. The exported fields contain no customer personal or payment data, so this is not SEV1. Deletion of the uploaded copies is not verified, so the exposure is not fully closed.

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

- **[confirmed]** r.mehta (Sales) resigned on 2026-11-14 with a last working day of 2026-11-28. [E12]
- **[confirmed]** On 2026-11-17, three days after resigning, r.mehta exported all-region opportunities (4,820 records) and the 2027 price book from the CRM on laptop LT-SALES-07 (EV002, EV003). [E2][E3]
- **[confirmed]** About 16–20 minutes after the exports, two POST uploads to a personal-storage site went out from the same laptop (EV004, EV005). The DLP alerts recorded them as allowed, in audit mode. [E4][E5][E6][E7]
- **[probable]** The uploaded files are probably the CRM exports. The file names (Opportunities_export.xlsx, Price_book_2027.xlsx) and the timing match, but no record states that the files are the same. [E5][E7]
- **[confirmed]** The data involved was pipeline forecast and pricing. The exported fields contain no customer personal data and no payment data. [E13]
- **[confirmed]** On 2026-11-18 Security reviewed the DLP alerts in the weekly report (EV007) and interviewed the employee (EV008). The employee said the files were copied for personal reference and agreed to delete them. CRM and VPN access was suspended and the laptop collected (EV009). [E9][E10][E11]
- **[confirmed]** All activity came from the employee's managed laptop on the office network, so there is no sign of an external actor in the evidence. [E14]
- **[unknown]** Whether the uploaded files were deleted from the personal cloud account is not determined. The employee agreed to delete them, but the analyst note says deletion is not verified and copies may remain. [E10][E15]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `https://upload.personal-cloud.test/v2/files` | url | [E4] |
| `upload.personal-cloud.test` | domain | [E5] |

## 5. MITRE ATT&CK mapping

| Tactic | Technique | ID | Certainty | Behaviour | Evidence |
|---|---|---|---|---|---|
| exfiltration | Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | confirmed | Files were uploaded by HTTPS POST from the laptop to a personal cloud storage service. | [E4][E5] |
| collection | Data from Information Repositories | T1213 | probable | Bulk data was exported from the CRM, an internal information repository, shortly before the upload. | [E2] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**[confirmed]** The DLP rule for personal cloud uploads ran in audit-only mode, so the uploads of confidential data were logged but not blocked. [E5][E16]

### Contributing factors

- **[confirmed]** There is no process to reduce CRM export rights when an employee resigns. [E17]
- **[confirmed]** The CRM lets any sales user bulk-export all regions' opportunities, so no business need or role restriction applied. [E18]

## 7. Detection gaps

- **[probable]** The personal cloud upload alerts were reviewed in the weekly DLP report the next morning. No earlier triage is recorded, and the rule did not block. [E5][E9]
- **[probable]** The all-region bulk CRM export by a user who had just resigned raised no recorded alert or review. The CRM audit log recorded it only as an export. [E2][E17]

## 8. Lessons learned

**Process**
- Leaver risk starts at notice. Export rights were not reviewed after the resignation, and the bulk exports came three days later. [E17] [P1]
- A verbal agreement to delete is not enough, and the personal cloud copies remain unverified. Deletion needs an attestation and verification, and the remaining risk must be recorded. [E10][E15] [P2]
- The interview (EV008) took place before the laptop was collected (EV009). The playbook says to preserve devices and logs first, and the evidence does not show HR or legal involvement before the interview. [E10][E11] [P3]

**Technology**
- A DLP rule left in audit mode since 2025 gives visibility but no protection. Rules covering confidential uploads to personal cloud must move to block after tuning. [E16] [P4]

**Governance**
- Bulk export of confidential sales data should be limited to roles that need it, not open to every sales user. [E18] [P5]

## 9. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Switch the DLP rule for uploads to personal cloud storage from audit to block for confidential and restricted data, and route its alerts to same-day triage as high. | Both uploads were allowed in audit mode and only seen in the next weekly review. [E5][E16] | [P4] | Security Engineering | Within 2 weeks | Confidential uploads to personal cloud are prevented, and any attempts are triaged quickly. |
| high | Obtain a written deletion attestation from the former employee. Verify deletion of the files in the personal cloud account where possible, and record any copies that cannot be confirmed deleted as a remaining risk. Involve HR and legal on next steps. | Deletion was agreed verbally only, and copies may remain. [E10][E15] | [P2] | Security Incident Response with HR and Legal | Before the last working day, 2026-11-28 (the access suspension of 2026-11-18 is already in place) | Documented closure or an explicitly accepted residual risk. |
| high | Create a leaver workflow: HR notifies IT within one business day of notice, and IT removes bulk-export and sensitive-data rights for the notice period unless a manager approves otherwise in writing. | No process reduced export rights after the resignation, and the exports happened three days later. [E12][E17] | [P1] | HR and IT Operations | Within 30 days | Leavers cannot bulk-export confidential data during the notice period. |
| medium | Restrict CRM bulk export of all-region opportunities and pricing to roles with a business need, and alert on large exports. | Any sales user can export all regions' opportunities. [E2][E18] | [P5] | Sales Operations and CRM Admin | Within 60 days | Smaller data exposure per user and earlier signal on unusual exports. |
| medium | Update the insider-case procedure so devices and logs are preserved before the employee interview, and the HR and legal involvement is recorded. | The interview preceded laptop collection, and no HR or legal involvement is recorded. [E10][E11] | [P3] | Security Incident Response | Within 30 days | Better evidence preservation and a defensible process in future insider cases. |

## 10. Open questions and remaining risks

- **Open:** Have the uploaded files been deleted from the personal cloud account, and do other copies exist? hr_ticket.txt line 10 says this is not verified.
- **Open:** Are the uploaded files identical to the CRM exports? The names and timing match, but no record states it.
- **Open:** Was other data exported or sent elsewhere between the resignation and 2026-11-18, for example by other channels or devices? The available logs show only these activities.
- **Open:** What was the purpose of the copying? The employee's statement of 'personal reference' is unverified, and the new employer is not disclosed.
- **Open:** Were HR and legal involved before the interview? The evidence does not say.
- **Open:** The HR note times (EV007 to EV009) have an assumed timezone, so the exact response intervals are approximate.
- **Risk:** Confidential pipeline and pricing files may still exist in the personal cloud account (hr_ticket.txt line 10 says deletion is not verified).
- **Risk:** The same DLP and export gaps still apply to other staff until the rule blocks and export rights are restricted.

## 11. Validation log

- attempt 1: 1 validation problem(s)
- attempt 1 problem: summary_points[3]: summary point states a probable finding as fact; hedge it (e.g. 'probably', 'may', 'not confirmed'): 'Security reviewed the alerts the next morning in the weekly DLP report. CRM and '
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
| E13 | hr_ticket.txt | line 9 | Data involved: pipeline forecast and pricing. |
| E14 | hr_ticket.txt | line 11 | managed laptop LT-SALES-07 on the office network |
| E15 | hr_ticket.txt | line 10 | deletion from the personal cloud account is not verified; copies may remain |
| E16 | hr_ticket.txt | line 6 | has run in audit-only mode since the 2025 rollout |
| E17 | hr_ticket.txt | line 7 | no process to reduce CRM export rights when an employee resigns |
| E18 | hr_ticket.txt | line 8 | any sales user bulk-export all regions' opportunities |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | POL-07 §5 Joiners, movers and leavers | IT reviews the leaver's access and removes bulk-export, admin and sensitive-data rights for the notice period |
| P2 | PB-05 §4 Deletion and copies | Obtain a written deletion attestation and verify it where possible |
| P3 | PB-05 §3 Insider cases | Involve HR and legal before interviewing the employee, and preserve logs and devices first. |
| P4 | POL-12 §5 Data loss prevention | After that, rules covering uploads of confidential or restricted data to personal cloud storage must block. |
| P5 | POL-20 §2 Confidential data | Bulk exports of confidential data require a business reason and are limited to roles that need them. |

_Knowledge-base sections given to the model: POL-12#5, POL-20#1, POL-07#5, POL-20#2, PB-05#4, POL-07#4, POL-15#3, PB-05#3_

**Evidence file hashes (SHA-256)**

- `crm_audit.csv`: `7d28884af6faded6d541bc4707e5803eacab9283f2f45e2ca0efc36e73cd6a3a`
- `dlp_alerts.json`: `f8546fccea8ad6e43a5a6c59b5a32cfc3d43ad85c124c6f3901cb8988595ab8e`
- `hr_ticket.txt`: `b951425f2c381ae91f31a23b92d6584aadb0202968bf888dd9790a1468dbcb3d`
- `proxy_logs.csv`: `f5d660d08c35b534192542a65ee72a8c346035254784574a49622fe7ef69ab13`
