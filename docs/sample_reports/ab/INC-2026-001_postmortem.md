# Incident Postmortem: INC-2026-001: Probable phishing-led takeover of j.patel's mailbox, with external forwarding rule and no MFA

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-001 |
| Category | credential_compromise |
| Severity | SEV2 |
| Classification confidence | 80% |
| Generated | 2026-11-23 20:10 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A look-alike password-expiry phishing email was delivered to j.patel and a.khan. j.patel's host then loaded the phishing page and sent a POST to its submit URL. a.khan showed no click. j.patel's credentials were probably captured. The account was then signed in from 203.0.113.45 using a scripted client. This link is probable, not confirmed. An inbox rule created from that IP forwarded 3 emails to an external address before it was removed. What those emails contained is not confirmed. MFA was not enforced for j.patel because of a 2025 migration exception that was never removed. This is the probable enabling condition. The account was contained (sessions revoked, password reset, rule removed, phishing message purged from 14 mailboxes). A later sign-in attempt from the same IP failed. Detection was slow in part because the impossible-travel alert had not been triaged when the forwarding-rule alert was picked up. Whether SharePoint was accessed is not checked and remains unknown.

**Severity rationale:** The j.patel account was confirmed accessed from 203.0.113.45, and a forwarding rule sent 3 emails to an external address before removal. The incident was contained (sessions revoked, password reset, rule removed). No large-scale sensitive data exposure is confirmed. The content of the 3 forwarded emails and any SharePoint access are not established, so SEV1 is not supported on current evidence.

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
| EV013 | 2026-10-06 10:01:44 | result=failure; app=Exchange Online; user=j.patel; src_ip=203.0.113.45 | exact | [E13] |
| EV014 | 2026-10-06 10:05:00 | 10:05 Reset password for j.patel and confirmed with user by phone. | date inferred | [E14] |
| **EV015** | **2026-10-06 10:12:00** | **10:12 Removed inbox rule 'sync'. Message trace shows 3 emails forwarded to mailbox-sync@exfil-drop.test before** | date inferred | [E15] |
| EV016 | 2026-10-06 10:40:00 | 10:40 Purged phishing message from 14 mailboxes. a.khan received it but proxy shows no click. | date inferred | [E16] |

## 3. What happened

- **[confirmed]** A phishing email with the subject 'Action required: password expires today' from a look-alike sender domain was delivered to j.patel. [E2]
- **[confirmed]** The same phishing message was delivered to a.khan. The proxy shows no click by a.khan. The message was purged from 14 mailboxes. [E3][E16]
- **[confirmed]** From host LT-OPS-114, j.patel loaded the look-alike reset page (HTTP 200) and then sent a POST to its submit URL. [E4][E5]
- **[probable]** j.patel's credentials were probably entered into the look-alike page and captured. The POST is recorded, but its content and the credential capture are not directly shown. [E5][E7]
- **[confirmed]** j.patel signed in successfully to Exchange Online, then OfficeHome, from 203.0.113.45 (NL) using a python-requests user agent. MFA was not required for these sign-ins. [E7][E8][E9]
- **[confirmed]** An inbox rule 'sync' was created from 203.0.113.45. It forwarded messages containing 'invoice' to an external address. [E10]
- **[confirmed]** Message trace shows 3 emails were forwarded to the external address before the rule was removed. Their content and sensitivity are not documented. [E15]
- **[confirmed]** Responder actions: sessions revoked, password reset and confirmed with the user by phone, and rule 'sync' removed. A later Exchange Online sign-in attempt from 203.0.113.45 failed. [E12][E13][E14][E15]
- **[unknown]** Whether the attacker accessed SharePoint is not determined. It was not checked. [E17]

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

## 5. Root cause

**[probable]** j.patel was probably phished on a look-alike login page. A password alone was then enough to sign in from outside the network, because the account had been excluded from the MFA conditional access policy during the 2025 migration and the exception was never removed. The credential capture is inferred from the sequence of events rather than directly shown. [E5][E7][E18]

### Contributing factors

- **[confirmed]** j.patel was excluded from the conditional access policy during the 2025 migration, and the exception was never removed, so MFA was not enforced. [E18]
- **[confirmed]** The email gateway rated the phishing message clean and delivered it. The look-alike domain had been registered 2 days earlier. [E19]
- **[confirmed]** The proxy allowed j.patel's request to the uncategorized look-alike domain (HTTP 200) and its POST (302). No blocking is recorded. [E4][E5]

## 6. Detection gaps

- **[confirmed]** The impossible-travel alert AL-5521 had not been triaged when the analyst picked up the later forwarding-rule alert AL-5527. [E9][E11]
- **[confirmed]** The gateway scored the look-alike phishing message clean, so no preventive or detective signal was raised at delivery. [E2][E19]

## 7. Lessons learned

**Process**
- Alerts that are playbook triggers, such as impossible travel, should be triaged promptly and correlated with related alerts on the same user. The earlier alert sat untriaged while the later one was handled. [E11] [P1]
- Scoping must cover collaboration-platform file access and mailbox activity for the whole period of attacker access. SharePoint was left unchecked. [E17] [P2]

**Technology**
- MFA must apply to every interactive sign-in. The scripted sign-in from an external IP succeeded with a password alone. [E7] [P3]

**Governance**
- MFA exceptions created during migrations must be removed when the migration ends. A stale exception left a single account protected only by a password. [E18] [P4]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Remove the MFA exclusion for j.patel and enforce MFA registered to the real user. Audit all conditional access exceptions for owner, business reason and expiry, and remove any left over from the 2025 migration. | A password alone allowed sign-in from an external IP because of a stale migration exception. [E18] | [P4][P5] | IAM | Immediately for j.patel; exception audit within 2 weeks | A stolen password alone no longer grants access, and no stale exceptions remain. |
| high | Complete scoping: review mailbox audit logs and file access (SharePoint, OneDrive) for j.patel for the whole attacker-access window. Review the 3 forwarded emails to assess what was exposed. | SharePoint access is unchecked and the content of the forwarded emails is unknown. [E15][E17] | [P2] | SOC / Incident Response | Within 2 days | Establishes the true data exposure and whether notification or further containment is needed. |
| high | Block the phishing domains at email and proxy layers and block 203.0.113.45. The evidence does not record that this was done. | The look-alike domain was reachable from the corporate network, and attacker sign-ins came from 203.0.113.45. [E4][E7] | [P5][P6] | Network Security / Email Security | Within 24 hours | Prevents repeat access to the phishing infrastructure and further use of the attacker IP. |
| medium | Set a triage target and correlate alerts by user, so that an untriaged impossible-travel alert is reviewed together with later alerts on the same user. | AL-5521 was still untriaged when the forwarding-rule alert was handled. [E10][E11] | [P1] | SOC | Within 30 days | Faster containment of account takeovers and less attacker dwell time. |
| medium | Review the email gateway's handling of newly registered look-alike domains and credential-harvesting links. Check whether other recipients beyond the 14 purged mailboxes clicked, using proxy logs. | The gateway rated the phishing message clean despite a domain registered 2 days earlier. Only a.khan's click status is documented. [E16][E19] | [P2] | Email Security / SOC | Within 30 days | Fewer look-alike phishing messages delivered, and confirmation that no other users were affected. |

## 9. Open questions and remaining risks

- **Open:** Did the attacker access SharePoint or OneDrive? This was not checked.
- **Open:** What did the 3 forwarded emails contain, and did any hold sensitive or customer data?
- **Open:** Were j.patel's credentials actually captured by the look-alike page? The POST content is not in evidence.
- **Open:** What else did the attacker do in the mailbox between the first attacker sign-in (EV007) and session revocation (EV012)?
- **Open:** Were the phishing domains and 203.0.113.45 blocked, and was MFA enforced for j.patel after the incident? None of this is recorded.
- **Open:** Was host LT-OPS-114 examined?
- **Open:** Did any recipients other than a.khan click the link? Only a.khan's click status is documented.
- **Risk:** The MFA exclusion for j.patel may still be in place, and other stale MFA exceptions may exist. Remediation is not recorded.
- **Risk:** Attacker access to SharePoint or other data is not ruled out.
- **Risk:** The phishing domains may still be reachable if they were not blocked.

## 10. Validation log

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
| E17 | analyst_notes.txt | line 10 | Open question: attacker may also have accessed SharePoint. Not checked yet. |
| E18 | analyst_notes.txt | line 8 | MFA was not enforced for j.patel |
| E19 | analyst_notes.txt | line 9 | the email gateway rated the phishing message clean |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | PB-01 §1 Triggers | Impossible travel, sign-in from a new country with a scripted user agent, new inbox forwarding rules |
| P2 | PB-01 §3 Scoping | file access in collaboration platforms (for example SharePoint and OneDrive) |
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
