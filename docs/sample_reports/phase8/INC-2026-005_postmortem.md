# Incident Postmortem: INC-2026-005: Departing sales employee uploaded CRM pipeline and pricing exports to personal cloud storage

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-005 |
| Category | insider_threat |
| Severity | SEV2 |
| Classification confidence | 85% |
| Generated | 2026-11-24 09:05 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A sales user who had resigned exported all-region opportunities and the 2027 price book from the CRM. Proxy and DLP records show both files were uploaded to a personal cloud service from the managed laptop. The exported data was pipeline forecast and pricing. The ticket says it contained no customer personal data and no payment data. The DLP rule for personal cloud uploads has been audit-only since the 2025 rollout, so the uploads were logged but allowed. There is no process to reduce CRM export rights on resignation, and any sales user can bulk-export all regions' opportunities. Both made the export possible. Security reviewed the DLP alerts the following morning, and the review was part of the weekly DLP report. This probably means the alerts were not handled as real-time, high-priority triage, though that is not confirmed. Access was suspended and the laptop collected later that day. The employee said the files were copied for personal reference and agreed to delete them. Deletion from the personal cloud account is not verified, so copies may remain.

**Severity rationale:** A confirmed insider action by r.mehta, a resigned employee, moved confidential pipeline and pricing exports to personal cloud storage, and access was then suspended. The exported fields contain no customer personal data and no payment data (hr_ticket.txt line 9), so there is no confirmed large-scale exposure of sensitive personal data or credentials. Deletion of the uploaded copies is not verified, which remains an open risk.

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

- **[confirmed]** Sales employee r.mehta resigned on 2026-11-14 with a last working day of 2026-11-28. The new employer was not disclosed. [E12]
- **[confirmed]** On 2026-11-17, r.mehta exported all regions' opportunities (4820 records) and the 2027 price book from the CRM on LT-SALES-07 (EV002, EV003). [E2][E3]
- **[confirmed]** Within about 20 minutes of the exports, two POST uploads to upload.personal-cloud.test from LT-SALES-07 were recorded by the proxy and by DLP (EV004, EV005). [E4][E5][E6][E7]
- **[probable]** The uploaded files are probably the CRM exports. The file names match the exported objects and the uploads followed the exports closely, but no record ties them together directly. [E2][E5][E7]
- **[confirmed]** DLP flagged both uploads but the rule was in audit mode, so the uploads were allowed. [E5][E7][E13]
- **[confirmed]** On 2026-11-18 Security reviewed the DLP alerts as part of the weekly DLP report (EV007). [E9]
- **[confirmed]** In an interview, r.mehta said the files were copied for personal reference and agreed to delete them (EV008). This is the employee's own account and is not independently verified. [E10]
- **[confirmed]** r.mehta's CRM and VPN access was suspended and the laptop collected (EV009). [E11]
- **[confirmed]** Deletion of the files from the personal cloud account has not been verified, and copies may remain. [E14]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `upload.personal-cloud.test` | domain | [E5] |
| `https://upload.personal-cloud.test/v2/files` | url | [E4] |

## 5. MITRE ATT&CK mapping

| Tactic | Technique | ID | Certainty | Behaviour | Evidence |
|---|---|---|---|---|---|
| collection | Data from Information Repositories | T1213 | confirmed | The user bulk-exported opportunity and price book data from the CRM repository. | [E2][E3] |
| exfiltration | Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | confirmed | The exported files were uploaded to a personal cloud storage service over HTTPS. | [E4][E5] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**Immediate cause [confirmed]:** r.mehta, a resigned employee using their own managed laptop and account, exported CRM pipeline and pricing data and uploaded it to a personal cloud storage service. [E2][E4][E15]

**[confirmed]** The DLP rule for personal cloud uploads has stayed in audit-only mode since the 2025 rollout, so uploads of confidential data to personal cloud storage were detected but not blocked. [E5][E13]

### Contributing factors

- **[confirmed]** No process reduces CRM export rights when an employee resigns. The export happened three days after the resignation date, with the notice period still running. [E12][E16]
- **[confirmed]** The CRM lets any sales user bulk-export all regions' opportunities. [E17]
- **[probable]** DLP alerts for personal cloud uploads were handled through the weekly DLP report review rather than real-time triage, which probably delayed the human response. [E9]

## 7. Impact assessment

- **Systems involved:** `LT-SALES-07`, `upload.personal-cloud.test`
- **Accounts involved:** `r.mehta`
- **Data affected:** [confirmed] Pipeline forecast and pricing data (4820 opportunity records and the 2027 price book) were uploaded to personal cloud storage. The exported fields contain no customer personal data and no payment data. [E2][E18]
- **Operational impact:** [confirmed] The employee's CRM and VPN access was suspended and the laptop collected. No other operational disruption is recorded. [E11]
- **Business impact:** [unknown] The business impact is not determined. The evidence does not say whether the data reached a competitor or what any cost was.

## 8. Response analysis

Milestones chosen by the model from the timeline; durations computed by code from timestamps.

| Milestone | Event | Time (UTC) | Time basis |
|---|---|---|---|
| attack start | EV002 | 2026-11-17 16:02:11 | exact |
| first detection | EV004 | 2026-11-17 16:21:33 | exact |
| response start | EV007 | 2026-11-18 09:15:00 | timezone assumed |
| containment | EV009 | 2026-11-18 14:40:00 | timezone assumed |

| Measure | From → to | Duration |
|---|---|---|
| time to detect | attack start → first detection | 19m 22s |
| time to respond | first detection → response start | 16h 53m 27s (approximate: inferred time) |
| time to contain | first detection → containment | 22h 18m 27s (approximate: inferred time) |
| dwell time | attack start → containment | 22h 37m 49s (approximate: inferred time) |

## 9. Detection gaps

- **[confirmed]** The DLP rule only logged the personal cloud uploads (audit mode, action allowed), so there was no prevention and no blocking at the time of upload. [E5][E7]
- **[probable]** Human review of the DLP alerts happened the day after the uploads, through the weekly DLP report process, and probably not as a high-priority real-time alert. [E5][E9]

## 10. Lessons learned

**People**
- In this case the interview came before access suspension and device collection. The insider playbook says to preserve logs and devices first, so the interview may have given the employee a chance to act on the data. The records do not show whether this happened. [E10][E11] [P1]

**Process**
- Leaver controls must start when notice is given. Bulk-export rights stayed in place during the notice period and were used. [E16] [P2]
- DLP alerts for personal cloud uploads should be triaged as high priority when they occur, not only in periodic reports. [E9] [P3]

**Technology**
- A DLP rule left in audit mode after rollout detects data loss but does not prevent it. Rules covering confidential uploads to personal cloud must move to blocking after the tuning period. [E13] [P3]

**Governance**
- Confidential data such as pricing and pipeline should be exportable only by roles with a business need, not by every sales user. [E17] [P4]

## 11. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Switch the DLP rule for uploads of confidential data to personal cloud storage from audit to block mode, with a defined exception process. | The rule has been audit-only since 2025, so both uploads were allowed. [E5][E13] | [P3] | Security Engineering | Within 2 weeks | Uploads of confidential files to personal cloud are stopped at the time of the attempt. |
| high | Create a leaver process under which HR notifies IT within one business day of notice, and IT removes bulk-export and sensitive-data rights for the notice period unless the manager approves otherwise in writing. | No process reduced CRM export rights after the resignation, and the export took place three days later. [E12][E16] | [P2] | HR and IT | Within 30 days | Leavers cannot bulk-export confidential data during the notice period. |
| high | Restrict CRM bulk export of all-region opportunities and price book data to roles with a documented business need. | Any sales user could export all regions' opportunities. [E17] | [P4] | Sales Operations and IT | Within 30 days | Less confidential data can be removed from the CRM in one action. |
| high | Obtain a written deletion attestation from r.mehta and verify it where possible. Record any copies that cannot be confirmed deleted as a remaining risk, and consider legal advice on further steps. | Deletion from the personal cloud account is not verified and copies may remain. [E10][E14] | [P5] | Security and Legal | Immediately, before the last working day (2026-11-28) | Documents the remaining exposure of the pricing and pipeline data and reduces the chance that copies persist. |
| medium | Triage DLP alerts for personal cloud uploads as high priority with same-day review, outside the weekly report. | The alerts were reviewed through the weekly DLP report process, the day after the uploads. [E9] | [P3] | Security Operations | Within 2 weeks | Shorter time from upload to response while preventive controls are being rolled out. |
| low | Brief HR and Security on the insider-case order of work: involve HR and legal, then preserve logs and devices, then interview the employee. | The interview took place before the laptop was collected. [E10][E11] | [P1] | Security and HR | Within 60 days | More consistent handling of insider cases and better preservation of evidence. |

## 12. Open questions and remaining risks

- **Open:** Were the files deleted from the personal cloud account, and do other copies exist (for example downloaded or shared)? The ticket marks deletion as not verified.
- **Open:** What was the employee's real purpose? The only statement is 'for personal reference' (hr_ticket.txt line 4), and the new employer is not disclosed (hr_ticket.txt line 2).
- **Open:** Did the employee export or upload other data before 2026-11-17? Only three CRM audit rows are in the evidence pack.
- **Open:** Were HR and legal involved before the interview and was evidence preserved first? The records do not say.
- **Open:** The HR ticket entries for 2026-11-18 are marked as having an assumed timezone, so the exact response times are not firm.
- **Open:** Is there any business or competitive impact from the pricing and pipeline data leaving the company? The evidence does not say.
- **Risk:** Copies of the pipeline forecast and 2027 pricing data may remain in the employee's personal cloud account.
- **Risk:** Other employees currently have the same bulk-export rights, and the DLP rule is still audit-only, unless these have changed since the incident.

## 13. Validation log

- attempt 1: 1 validation problem(s)
- attempt 1 problem: summary_points[4]: summary point states a probable finding as fact; hedge it (e.g. 'probably', 'may', 'not confirmed'): 'Security reviewed the DLP alerts the following morning as part of the weekly DLP'
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
| E13 | hr_ticket.txt | line 6 | audit-only mode since the 2025 rollout |
| E14 | hr_ticket.txt | line 10 | deletion from the personal cloud account is not verified; copies may remain |
| E15 | hr_ticket.txt | line 11 | All activity came from r.mehta's managed laptop LT-SALES-07 |
| E16 | hr_ticket.txt | line 7 | there is no process to reduce CRM export rights when an employee resigns |
| E17 | hr_ticket.txt | line 8 | the CRM lets any sales user bulk-export all regions' opportunities |
| E18 | hr_ticket.txt | line 9 | Data involved: pipeline forecast and pricing |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | PB-05 §3 Insider cases | preserve logs and devices first |
| P2 | POL-07 §5 Joiners, movers and leavers | removes bulk-export, admin and sensitive-data rights for the notice period |
| P3 | POL-12 §5 Data loss prevention | DLP alerts for personal cloud uploads are triaged as high, not only in periodic reports. |
| P4 | POL-20 §2 Confidential data | Bulk exports of confidential data require a business reason and are limited to roles that need them. |
| P5 | PB-05 §4 Deletion and copies | Obtain a written deletion attestation and verify it where possible |

_Knowledge-base sections given to the model: POL-12#5, POL-20#1, POL-07#5, POL-20#2, PB-05#4, POL-07#4, POL-15#3, PB-05#3_

**Evidence file hashes (SHA-256)**

- `crm_audit.csv`: `7d28884af6faded6d541bc4707e5803eacab9283f2f45e2ca0efc36e73cd6a3a`
- `dlp_alerts.json`: `f8546fccea8ad6e43a5a6c59b5a32cfc3d43ad85c124c6f3901cb8988595ab8e`
- `hr_ticket.txt`: `b951425f2c381ae91f31a23b92d6584aadb0202968bf888dd9790a1468dbcb3d`
- `proxy_logs.csv`: `f5d660d08c35b534192542a65ee72a8c346035254784574a49622fe7ef69ab13`
