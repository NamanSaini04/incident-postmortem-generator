# Incident Postmortem: INC-2026-001: Credential phishing leading to j.patel mailbox compromise and external email forwarding

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-001 |
| Category | credential_compromise |
| Severity | SEV2 |
| Classification confidence | 85% |
| Generated | 2026-11-23 20:40 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A look-alike 'password expires' phishing email was delivered to j.patel, and the proxy shows j.patel's host visiting the phishing page and posting to its submit URL. The stolen password was probably used for a successful Exchange Online sign-in from an external IP, where MFA was not required. The attacker created an inbox rule forwarding mail to an external address; 3 emails were forwarded before the rule was removed. j.patel had been excluded from MFA conditional access during a 2025 migration and the exception was never removed. The email gateway rated the phishing message clean, and the impossible-travel alert had not been triaged when the forwarding-rule alert was picked up. Sessions were revoked, the password reset, the rule removed and the phishing message purged from 14 mailboxes. Whether SharePoint was accessed has not been checked.

**Severity rationale:** Confirmed compromise of the j.patel account. The attacker signed in from an external IP and created a forwarding rule, and 3 emails were forwarded externally before the rule was removed. The account was contained by session revocation, a password reset and rule removal. No large-scale sensitive data or credential exposure is confirmed. SharePoint access has not been checked, so severity should be revisited if it shows data access.

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
| EV012 | 2026-10-06 09:58:00 | 09:58 Revoked all active sessions for j.patel. | date inferred | [E12] |
| **EV013** | **2026-10-06 10:01:44** | **result=failure; app=Exchange Online; user=j.patel; src_ip=203.0.113.45** | exact | [E13] |
| EV014 | 2026-10-06 10:05:00 | 10:05 Reset password for j.patel and confirmed with user by phone. | date inferred | [E14] |
| **EV015** | **2026-10-06 10:12:00** | **10:12 Removed inbox rule 'sync'. Message trace shows 3 emails forwarded to mailbox-sync@exfil-drop.test before** | date inferred | [E15] |
| EV016 | 2026-10-06 10:40:00 | 10:40 Purged phishing message from 14 mailboxes. a.khan received it but proxy shows no click. | date inferred | [E16] |

## 3. What happened

- **[confirmed]** A phishing email with a look-alike sender domain and a link to a look-alike login page was delivered to j.patel at 09:14 (EV002). [E2]
- **[confirmed]** j.patel's host LT-OPS-114 loaded the phishing page and then sent a POST to its submit URL (EV004, EV005). That j.patel entered credentials is inferred from the POST, not directly stated. [E4][E5]
- **[confirmed]** About 3 minutes after the POST, a successful Exchange Online sign-in for j.patel came from 203.0.113.45 (NL) with a python-requests user agent. MFA was not required (EV007), and OfficeHome was also accessed successfully (EV008). [E7][E8]
- **[confirmed]** An inbox rule 'sync' was created from 203.0.113.45 to forward messages containing 'invoice' to an external address. Message trace shows 3 emails were forwarded before the rule was removed (EV010, EV015). [E10][E15]
- **[confirmed]** The SOC revoked j.patel's sessions, reset the password, removed the 'sync' rule and purged the phishing message from 14 mailboxes (EV012, EV014, EV015, EV016). [E12][E14][E15][E16]
- **[confirmed]** After the sessions were revoked, a further Exchange Online sign-in attempt from 203.0.113.45 failed (EV013). [E13]
- **[confirmed]** a.khan also received the phishing message (EV003), but the proxy shows no click. [E3][E16]

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
| initial-access | Phishing: Spearphishing Link | T1566.002 | confirmed | A phishing email containing a link to a look-alike login page was delivered and the link was visited from j.patel's host. | [E2][E4] |
| initial-access, persistence, privilege-escalation, stealth | Valid Accounts: Cloud Accounts | T1078.004 | probable | A scripted client from an external IP signed in successfully to j.patel's cloud mailbox without MFA, most likely using the phished password. | [E7] |
| collection | Email Collection: Email Forwarding Rule | T1114.003 | confirmed | An inbox rule forwarded mail to an external address and 3 emails were forwarded. | [E10][E15] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**[probable]** j.patel probably entered credentials on the look-alike login page, and the attacker used them to sign in from outside the corporate network. Because j.patel was excluded from MFA, the password alone was enough. The credential submission is inferred from the POST and the sign-in about 3 minutes later; it is not directly confirmed. [E5][E7][E17]

### Contributing factors

- **[confirmed]** j.patel was excluded from the conditional access policy during the 2025 migration and the exception was never removed, so MFA was not enforced. [E17]
- **[confirmed]** The email gateway rated the phishing message clean although the look-alike domain was registered only 2 days earlier, so it was delivered. [E2][E18]

## 7. Detection gaps

- **[confirmed]** The gateway did not flag the phishing message and delivered it to j.patel and a.khan. [E3][E18]
- **[confirmed]** The impossible-travel alert AL-5521 (09:24) had not been triaged when the analyst picked up the high-severity forwarding-rule alert AL-5527 (raised 09:31) at 09:52. The forwarding rule stayed active until 10:12. [E9][E11][E15]
- **[confirmed]** SharePoint access by the attacker was not checked, so the full scope of attacker activity is not established. [E19]

## 8. Lessons learned

**People**
- Credential phishing via a look-alike login page that ends in an inbox rule has happened before. Staff awareness and detection of this pattern need reinforcing. [E10] [P1]

**Process**
- Alerts that match playbook triggers, such as impossible travel, need to be triaged promptly. Here the lower-severity alert was still untriaged while the forwarding rule was already active. [E11] [P2]
- Scoping must cover collaboration platforms for the whole period of attacker access, not only mail. SharePoint was still unchecked at the time of the notes. [E19] [P3]

**Technology**
- Gateway reputation checks missed a look-alike domain registered 2 days earlier, so layered controls (proxy blocking, newly-registered-domain handling) are needed. [E18] [P4]

**Governance**
- Migration-era MFA exceptions need an owner and an expiry, and must be removed when the migration ends. An unreviewed exception left j.patel's account protected only by a password. [E17] [P5][P6]

## 9. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Remove the conditional access exclusion for j.patel, enforce MFA, and confirm MFA is registered to the real user. | j.patel's account was excluded from MFA and the attacker signed in with no MFA requirement. [E7][E17] | [P7] | IAM | Immediately (within 24 hours) | A stolen password alone can no longer be used to sign in to this account. |
| critical | Complete scoping: review SharePoint/OneDrive file access and mailbox audit logs for j.patel from the first attacker sign-in onward, and review the 3 forwarded emails for sensitive content. | SharePoint access was not checked, and the content of the 3 forwarded emails is not recorded. [E15][E19] | [P3] | SOC / Incident Response | Within 48 hours | Establishes the true impact and confirms or revises severity. |
| high | Audit all MFA and conditional access exceptions, especially those created in the 2025 migration. Remove expired or ownerless ones and run the monthly IAM review. | The migration exception was never removed, which suggests other stale exceptions may exist. [E17] | [P5] | IAM | Within 2 weeks | Closes other accounts that rely on a password alone. |
| high | Block the phishing domains at the email and proxy layers and block the attacker IP, then record that this was done. | The notes record no domain or IP blocking, the phishing site was reachable (status 200), and the attacker IP kept trying to sign in after session revocation. [E4][E13] | [P4][P7] | Network Security / Email Security | Within 24 hours | Prevents further visits to the phishing site and further attacker sign-ins. |
| high | Improve alert triage so impossible-travel and other playbook-trigger alerts are worked or escalated when a related high-severity alert exists for the same user. | AL-5521 was untriaged when AL-5527 was picked up, and the forwarding rule stayed active until 10:12. [E10][E11] | [P2] | SOC | Within 1 month | Shorter time between attacker access and containment. |
| medium | Tune email gateway handling of newly registered and look-alike sender domains, such as quarantine or warning banners. | A message from a look-alike domain registered 2 days earlier was rated clean and delivered. [E2][E18] | [P4] | Email Security | Within 1 month | Fewer phishing messages from newly registered look-alike domains reach users. |
| medium | Check proxy logs for clicks from all 14 purged recipients, not only a.khan, and review their mailboxes for inbox rules. | The notes state a click check only for a.khan, while the message reached 14 mailboxes. [E16] | [P3] | SOC / Incident Response | Within 48 hours | Finds any other compromised users. |

## 10. Open questions and remaining risks

- **Open:** Did the attacker access SharePoint or other collaboration data? This is not checked (analyst_notes.txt line 10).
- **Open:** Did j.patel actually submit credentials on the phishing page? Only a POST with a 302 response is recorded (proxy_logs.csv row 2).
- **Open:** What did the 3 forwarded emails contain, and did the rule forward anything else between 09:31 and 10:12?
- **Open:** Did any of the other 13 recipients of the phishing message click the link? Only a.khan is recorded as checked (analyst_notes.txt line 7).
- **Open:** Have the phishing domains and attacker IP been blocked, and has MFA been enforced for j.patel? No record shows either.
- **Open:** What did the attacker do in the OfficeHome session (auth_logs.csv row 3) beyond signing in?
- **Risk:** Possible unreviewed attacker access to SharePoint or other cloud data (analyst_notes.txt line 10).
- **Risk:** The phishing domains and attacker IP may not yet be blocked, and other recipients may have clicked.
- **Risk:** Other accounts may still hold stale MFA exceptions like the one that left j.patel exposed (analyst_notes.txt line 8).

## 11. Validation log

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
| E17 | analyst_notes.txt | line 8 | MFA was not enforced for j.patel |
| E18 | analyst_notes.txt | line 9 | the look-alike domain was registered 2 days earlier |
| E19 | analyst_notes.txt | line 10 | attacker may also have accessed SharePoint. Not checked yet. |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | PIR-2025-014 §1 Summary | entered credentials on a look-alike login page |
| P2 | PB-01 §1 Triggers | Impossible travel, sign-in from a new country with a scripted user agent |
| P3 | PB-01 §3 Scoping | file access in collaboration platforms (for example SharePoint and OneDrive) |
| P4 | PB-01 §4 Eradication and recovery | block the phishing domains at email and proxy layers |
| P5 | POL-07 §3 Exceptions to MFA and conditional access | Exceptions created during migrations must be removed when the migration ends. |
| P6 | POL-07 §2 Multi-factor authentication | A password alone must never be enough to sign in from outside the corporate network. |
| P7 | PB-01 §2 Containment | confirm MFA is enforced and registered to the real user |

_Knowledge-base sections given to the model: PB-01#3, PB-01#2, PB-01#1, POL-07#3, PB-01#4, PIR-2025-014#1, POL-07#2, PB-04#1_

**Evidence file hashes (SHA-256)**

- `analyst_notes.txt`: `8780237fd87d750f4044110145655aee9007a91df7064dec9ea5b85c25060a3d`
- `auth_logs.csv`: `38e6f9c3142274cda6cfedbfebfcb9b0795bb254d6a40448045446a8e7ecf330`
- `email_gateway.csv`: `ae827d6b29d1798f666e7e0e30fd53767e33c8a7caa59b007a50548983b8c36d`
- `proxy_logs.csv`: `7392fb696c84ccc4c56fbe001c7ea8e7c2315fc48e47bb3dfdf17852b037ef27`
- `siem_alerts.json`: `8d1524bf2fcdf2a4dcc888199117e7c07669bb1429cf07b624c5e84835bdf078`
