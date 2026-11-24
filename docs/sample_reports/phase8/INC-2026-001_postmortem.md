# Incident Postmortem: INC-2026-001: j.patel mailbox compromise after look-alike login phishing, with external email forwarding

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-001 |
| Category | credential_compromise |
| Severity | SEV2 |
| Classification confidence | 80% |
| Generated | 2026-11-24 09:00 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A phishing email with a look-alike login link was delivered to j.patel, and j.patel's host then browsed to the page and sent a POST to it. Credentials were probably captured by the fake page. Exchange Online and OfficeHome sign-ins from a foreign IP using a scripted user agent followed within minutes. The attacker created inbox rule 'sync', and 3 emails were forwarded to an external address before the rule was removed. The content and sensitivity of those emails are unknown. The root cause was that MFA was not enforced for j.patel. The account had been excluded from conditional access during the 2025 migration and the exception was never removed. The gateway rated the phishing message clean, and the impossible-travel alert had not been triaged when the responder picked up the forwarding-rule alert. Sessions were revoked, the password was reset, the rule was removed and the phishing message was purged from 14 mailboxes. Possible SharePoint access has not been checked.

**Severity rationale:** The j.patel account was confirmed compromised, and the attacker created an inbox rule that forwarded 3 emails externally (analyst_notes.txt line 6). The account was contained. The evidence does not confirm large-scale sensitive data exposure. SharePoint access was not checked (analyst_notes.txt line 10).

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| EV001 | 2026-10-06 08:55:31 | result=success; app=Exchange Online; user=j.patel; src_ip=198.51.100.7 | exact | [E1] |
| **EV002** | **2026-10-06 09:14:02** | **subject=Action required: password expires today; action=delivered; url=https://login-micros0ft.test/reset?u=jp** | exact | [E2] |
| EV003 | 2026-10-06 09:14:05 | subject=Action required: password expires today; action=delivered; url=https://login-micros0ft.test/reset?u=ak | exact | [E3] |
| **EV004** | **2026-10-06 09:18:40** | **method=GET; url=https://login-micros0ft.test/reset?u=jpatel; user=j.patel; src_host=LT-OPS-114** | exact | [E4] |
| **EV005** | **2026-10-06 09:19:02** | **method=POST; url=https://login-micros0ft.test/submit; user=j.patel; src_host=LT-OPS-114** | exact | [E5] |
| EV006 | 2026-10-06 09:20:11 | subject=October product update; action=delivered; url=https://vendor.example/news; recipient=j.patel@contoso.e | exact | [E6] |
| **EV007** | **2026-10-06 09:22:15** | **result=success; app=Exchange Online; user=j.patel; src_ip=203.0.113.45** | exact | [E7] |
| EV008 | 2026-10-06 09:23:02 | result=success; app=OfficeHome; user=j.patel; src_ip=203.0.113.45 | exact | [E8] |
| **EV009** | **2026-10-06 09:24:00** | **rule=Impossible travel; user=j.patel; severity=medium** | exact | [E9] |
| **EV010** | **2026-10-06 09:31:10** | **rule=New inbox forwarding rule to external address; user=j.patel; severity=high** | exact | [E10] |
| **EV011** | **2026-10-06 09:52:00** | **09:52 Picked up AL-5527 from the queue. AL-5521 had not been triaged yet.** | date inferred | [E11] |
| **EV012** | **2026-10-06 09:58:00** | **09:58 Revoked all active sessions for j.patel.** | date inferred | [E12] |
| **EV013** | **2026-10-06 10:01:44** | **result=failure; app=Exchange Online; user=j.patel; src_ip=203.0.113.45** | exact | [E13] |
| EV014 | 2026-10-06 10:05:00 | 10:05 Reset password for j.patel and confirmed with user by phone. | date inferred | [E14] |
| **EV015** | **2026-10-06 10:12:00** | **10:12 Removed inbox rule 'sync'. Message trace shows 3 emails forwarded to mailbox-sync@exfil-drop.test before** | date inferred | [E15] |
| EV016 | 2026-10-06 10:40:00 | 10:40 Purged phishing message from 14 mailboxes. a.khan received it but proxy shows no click. | date inferred | [E16] |

## 3. What happened

- **[confirmed]** Before the attack, j.patel signed in to Exchange Online from the company London VPN egress without MFA being required. [E1][E17]
- **[confirmed]** A phishing email from a look-alike helpdesk sender, with a look-alike login link, was delivered to j.patel and a.khan. The gateway verdict was clean. [E2][E3]
- **[confirmed]** Host LT-OPS-114, used by j.patel, loaded the look-alike reset page (GET, HTTP 200) and then sent a POST to its /submit endpoint. [E4][E5]
- **[probable]** j.patel's credentials were probably captured by the fake page. About three minutes after the POST, a successful Exchange Online sign-in came from an NL IP with a scripted user agent and no MFA required. The captured credentials are not directly shown in the records. [E5][E7]
- **[confirmed]** The attacker IP signed in successfully to Exchange Online and OfficeHome as j.patel, and MFA was not required. [E7][E8]
- **[confirmed]** SIEM raised an impossible-travel alert and then a high-severity alert for an external forwarding rule 'sync', created from the attacker IP. [E9][E10]
- **[confirmed]** Message trace showed 3 emails were forwarded to the external address before the rule was removed. [E15]
- **[confirmed]** Responders revoked sessions, reset the password with phone confirmation from the user, removed the inbox rule and purged the phishing message from 14 mailboxes. [E12][E14][E16]
- **[confirmed]** A further sign-in attempt from the attacker IP failed after sessions had been revoked. The records do not state why it failed. [E13]
- **[confirmed]** a.khan received the phishing message, but the proxy shows no click. [E16]
- **[unknown]** Whether the attacker accessed SharePoint is not determined, because it was not checked.

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `203.0.113.45` | ip | [E7] |
| `mailbox-sync@exfil-drop.test` | email | [E15] |
| `exfil-drop.test` | domain | [E15] |
| `login-micros0ft.test` | domain | [E2] |
| `micros0ft-helpdesk.test` | domain | [E2] |
| `it-support@micros0ft-helpdesk.test` | email | [E2] |
| `https://login-micros0ft.test/reset?u=jpatel` | url | [E2] |
| `https://login-micros0ft.test/reset?u=akhan` | url | [E3] |
| `https://login-micros0ft.test/submit` | url | [E5] |

## 5. MITRE ATT&CK mapping

| Tactic | Technique | ID | Certainty | Behaviour | Evidence |
|---|---|---|---|---|---|
| initial-access | Phishing: Spearphishing Link | T1566.002 | confirmed | A phishing email with a link to a look-alike login page was delivered to j.patel and a.khan. | [E2][E3] |
| initial-access, persistence, privilege-escalation, stealth | Valid Accounts: Cloud Accounts | T1078.004 | probable | The attacker signed in to cloud services (Exchange Online, OfficeHome) as j.patel from an external IP without MFA, which suggests valid credentials were used. | [E7][E8] |
| collection | Email Collection: Email Forwarding Rule | T1114.003 | confirmed | An inbox rule forwarded messages to an external address, and 3 emails were forwarded. | [E10][E15] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**Immediate cause [probable]:** j.patel opened the look-alike login page and submitted data to it, which probably gave the attacker valid credentials. [E4][E5]

**[confirmed]** MFA was not enforced for j.patel. The account was excluded from the conditional access policy during the 2025 migration and the exception was never removed, so a password alone was enough to sign in. [E18]

### Contributing factors

- **[confirmed]** The email gateway rated the phishing message clean and delivered it. The look-alike domain had been registered 2 days earlier. [E19]
- **[confirmed]** The proxy allowed access to the uncategorized look-alike domain (HTTP 200 on GET). [E4]
- **[confirmed]** The impossible-travel alert AL-5521 was still untriaged when the responder picked up AL-5527. [E11]

## 7. Impact assessment

- **Systems involved:** `Exchange Online`, `OfficeHome`, `LT-OPS-114`
- **Accounts involved:** `j.patel`
- **Data affected:** [confirmed] 3 emails from j.patel's mailbox were forwarded to an external address. The rule targeted messages containing 'invoice'. The content and sensitivity of the forwarded emails are not recorded, and SharePoint access was not checked. [E10][E15]
- **Operational impact:** [unknown] Operational impact is not stated in the evidence.
- **Business impact:** [unknown] Business and financial impact is not stated in the evidence.

## 8. Response analysis

Milestones chosen by the model from the timeline; durations computed by code from timestamps.

| Milestone | Event | Time (UTC) | Time basis |
|---|---|---|---|
| attack start | EV002 | 2026-10-06 09:14:02 | exact |
| first detection | EV009 | 2026-10-06 09:24:00 | exact |
| response start | EV011 | 2026-10-06 09:52:00 | date inferred |
| containment | EV012 | 2026-10-06 09:58:00 | date inferred |

| Measure | From → to | Duration |
|---|---|---|
| time to detect | attack start → first detection | 9m 58s |
| time to respond | first detection → response start | 28m (approximate: inferred time) |
| time to contain | first detection → containment | 34m (approximate: inferred time) |
| dwell time | attack start → containment | 43m 58s (approximate: inferred time) |

## 9. Detection gaps

- **[confirmed]** The email gateway rated the phishing message clean, so the message reached users and was not blocked or flagged. [E2][E19]
- **[confirmed]** The impossible-travel alert AL-5521 had not been triaged when the responder started on the later forwarding-rule alert, so the first alert did not trigger a response. [E9][E11]
- **[confirmed]** Sign-ins from a foreign IP with a scripted user agent succeeded with no MFA challenge and no block. Detection relied on after-the-fact alerts. [E7]

## 10. Lessons learned

**Process**
- Alerts that match playbook triggers, such as impossible travel, need to be triaged even when a higher-severity alert arrives. The medium alert was left untriaged. [E11] [P1]
- Scoping must cover file access in collaboration platforms for the whole period of attacker access. SharePoint was left unchecked. [E20] [P2]

**Technology**
- Password-only access from outside the corporate network must not be possible. The attacker signed in from an external IP with no MFA requirement. [E7] [P3]

**Governance**
- Migration-time MFA exceptions need an owner and an expiry, and must be removed when the migration ends. A stale exception left j.patel exposed to a password-only sign-in. [E18] [P4]

## 11. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Enforce MFA for j.patel and confirm it is registered to the real user. Audit all conditional-access exceptions, remove expired or migration-era ones, and require an owner and an expiry date of 90 days or less. | The root cause was an MFA exclusion left over from the 2025 migration. [E18] | [P4][P5] | IAM | Immediately for j.patel; exception audit within 7 days | A stolen password alone can no longer give access to the mailbox. |
| high | Complete scoping: review SharePoint and OneDrive file access and mailbox audit logs for the full attacker-access window. Check proxy logs for clicks by all 14 phishing recipients, not only a.khan. | SharePoint access is unchecked, and the evidence records a click check only for a.khan. [E16][E20] | [P2] | SOC / Incident Response | Within 2 days | Establishes the true extent of data exposure and any other victims. |
| high | Block the phishing domains at the email and proxy layers, and block the attacker IP. | The attacker IP made another sign-in attempt after revocation, and the phishing domain was reachable through the proxy. The records do not show any block being applied. [E4][E13] | [P5][P6] | Network Security / Messaging | Within 24 hours | Stops further use of the phishing infrastructure and repeat sign-in attempts. |
| medium | Tune email gateway and proxy handling of newly registered look-alike and uncategorized domains, for example by warning or blocking. | A look-alike domain registered 2 days earlier was rated clean and delivered, and the proxy allowed the visit. [E2][E4][E19] | - | Messaging / Network Security | Within 30 days | Fewer phishing messages reach users, and fewer users reach the phishing pages. |
| medium | Change SOC queue handling so that alerts matching playbook triggers (impossible travel, scripted user agent, new forwarding rules) are triaged together for the same user. Consider correlating them into a single high-severity case. | The impossible-travel alert was untriaged while the responder worked on the forwarding-rule alert. [E9][E11] | [P1] | SOC | Within 30 days | Earlier recognition of account takeover and faster containment. |

## 12. Open questions and remaining risks

- **Open:** Did the attacker access SharePoint or other data? This was not checked (analyst_notes.txt line 10).
- **Open:** Were credentials actually entered on the fake page? Only a POST with HTTP 302 is recorded (proxy_logs.csv row 2).
- **Open:** What did the 3 forwarded emails contain, and were more messages forwarded or read in other ways?
- **Open:** Why did the 10:01 sign-in from the attacker IP fail, and was the attacker IP blocked?
- **Open:** Did any of the other phishing recipients, besides a.khan, click the link? Only a.khan's proxy check is recorded (analyst_notes.txt line 7).
- **Open:** How many other accounts have stale MFA or conditional-access exclusions?
- **Risk:** Unreviewed SharePoint and OneDrive access by the attacker may mean wider data exposure than confirmed.
- **Risk:** Other accounts with stale MFA exceptions remain exposed to password-only sign-in.
- **Risk:** The phishing and exfiltration domains and the attacker IP are not recorded as blocked.
- **Risk:** Other recipients of the phishing message may have interacted with it.

## 13. Validation log

- attempt 1: 0 validation problem(s)

## Evidence index

| Ref | File | Location | Quote |
|---|---|---|---|
| E1 | auth_logs.csv | row 1 | 2026-10-06T08:55:31Z |
| E2 | email_gateway.csv | row 1 | 2026-10-06T09:14:02Z |
| E3 | email_gateway.csv | row 2 | 2026-10-06T09:14:05Z |
| E4 | proxy_logs.csv | row 1 | 2026-10-06T09:18:40Z |
| E5 | proxy_logs.csv | row 2 | 2026-10-06T09:19:02Z |
| E6 | email_gateway.csv | row 3 | 2026-10-06T09:20:11Z |
| E7 | auth_logs.csv | row 2 | 2026-10-06T09:22:15Z |
| E8 | auth_logs.csv | row 3 | 2026-10-06T09:23:02Z |
| E9 | siem_alerts.json | alerts[0] | 2026-10-06T09:24:00Z |
| E10 | siem_alerts.json | alerts[1] | 2026-10-06T09:31:10Z |
| E11 | analyst_notes.txt | line 3 | 09:52 |
| E12 | analyst_notes.txt | line 4 | 09:58 |
| E13 | auth_logs.csv | row 4 | 2026-10-06T10:01:44Z |
| E14 | analyst_notes.txt | line 5 | 10:05 |
| E15 | analyst_notes.txt | line 6 | 10:12 |
| E16 | analyst_notes.txt | line 7 | 10:40 |
| E17 | analyst_notes.txt | line 11 | 198.51.100.7 is our London VPN egress |
| E18 | analyst_notes.txt | line 8 | MFA was not enforced for j.patel |
| E19 | analyst_notes.txt | line 9 | the email gateway rated the phishing message clean |
| E20 | analyst_notes.txt | line 10 | Not checked yet. |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | PB-01 §1 Triggers | Impossible travel, sign-in from a new country with a scripted user agent, new inbox forwarding rules |
| P2 | PB-01 §3 Scoping | file access in collaboration platforms |
| P3 | POL-07 §2 Multi-factor authentication | A password alone must never be enough to sign in from outside the corporate network. |
| P4 | POL-07 §3 Exceptions to MFA and conditional access | Exceptions created during migrations must be removed when the migration ends. |
| P5 | PB-01 §2 Containment | confirm MFA is enforced and registered to the real user |
| P6 | PB-01 §4 Eradication and recovery | block the phishing domains at email and proxy layers |

_Knowledge-base sections given to the model: PB-01#3, PB-01#2, PB-01#1, POL-07#3, PB-01#4, PIR-2025-014#1, POL-07#2, PB-04#1_

**Evidence file hashes (SHA-256)**

- `analyst_notes.txt`: `8780237fd87d750f4044110145655aee9007a91df7064dec9ea5b85c25060a3d`
- `auth_logs.csv`: `38e6f9c3142274cda6cfedbfebfcb9b0795bb254d6a40448045446a8e7ecf330`
- `email_gateway.csv`: `ae827d6b29d1798f666e7e0e30fd53767e33c8a7caa59b007a50548983b8c36d`
- `proxy_logs.csv`: `7392fb696c84ccc4c56fbe001c7ea8e7c2315fc48e47bb3dfdf17852b037ef27`
- `siem_alerts.json`: `8d1524bf2fcdf2a4dcc888199117e7c07669bb1429cf07b624c5e84835bdf078`
