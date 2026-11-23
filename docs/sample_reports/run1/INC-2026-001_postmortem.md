# Incident Postmortem: INC-2026-001: INC-2026-001: Phished credentials used to compromise j.patel's mailbox, with external forwarding of email

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-001 |
| Category | credential_compromise |
| Severity | SEV2 |
| Classification confidence | 85% |
| Generated | 2026-11-23 16:44 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A look-alike 'password expires' phishing email was delivered to j.patel and a.khan after the email gateway rated it clean (EV002, EV003). j.patel's host loaded the phishing page and then sent a POST to its /submit endpoint (EV004, EV005). About three minutes later, a non-MFA sign-in to j.patel's account came from 203.0.113.45 (EV007). MFA was not enforced for j.patel because of an exception left over from a 2025 migration. The attacker created an inbox rule 'sync' that forwarded 'invoice' mail externally (EV010), and 3 emails were forwarded before the rule was removed (EV015). The SOC revoked sessions, reset the password, removed the rule and purged the phishing message from 14 mailboxes. The impossible-travel alert AL-5521 was not triaged first, and possible SharePoint access remains unchecked.

**Severity rationale:** A user account was taken over and an external forwarding rule sent at least 3 emails to an attacker-controlled address (R006). The scope is not fully known: SharePoint access was not checked (R010) and the content of the forwarded emails is not recorded. Impact is limited to one confirmed compromised account, and the response contained the incident within about an hour of the first alert.

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
| **EV014** | **2026-10-06 10:05:00** | **10:05 Reset password for j.patel and confirmed with user by phone.** | date inferred | [E14] |
| **EV015** | **2026-10-06 10:12:00** | **10:12 Removed inbox rule 'sync'. Message trace shows 3 emails forwarded to mailbox-sync@exfil-drop.test before** | date inferred | [E15] |
| **EV016** | **2026-10-06 10:40:00** | **10:40 Purged phishing message from 14 mailboxes. a.khan received it but proxy shows no click.** | date inferred | [E16] |

## 3. What happened

- **[confirmed]** A phishing email with the subject 'Action required: password expires today' was delivered to j.patel and a.khan. The gateway rated it clean, and the link pointed to a look-alike domain. [E2][E3][E17]
- **[probable]** j.patel's host LT-OPS-114 requested the phishing URL and then sent a POST to the site's /submit endpoint. The sequence is consistent with credential entry on the fake page, but the submitted content is not in the evidence. [E4][E5]
- **[probable]** About 3 minutes after the POST, j.patel signed in to Exchange Online and then OfficeHome from 203.0.113.45 (NL) using a python-requests user agent. The SIEM raised an impossible-travel alert against the earlier GB sign-in from the company VPN egress. Attribution of the NL sign-ins to the attacker is a strong inference from the alert, the scripted user agent and the later rule creation. [E7][E8][E9]
- **[confirmed]** An inbox rule 'sync' was created from 203.0.113.45. It forwarded messages containing 'invoice' to an external address, and 3 emails were forwarded before the rule was removed. [E10][E15]
- **[confirmed]** The SOC picked up the high-severity forwarding-rule alert AL-5527 first, while the earlier impossible-travel alert AL-5521 had not been triaged. It then revoked sessions, reset the password with phone confirmation, removed the rule and purged the phishing message from 14 mailboxes. [E11][E12][E14][E16]
- **[confirmed]** A sign-in attempt from the attacker IP failed at 10:01:44, after sessions were revoked and before the password reset. The records do not say why it failed. [E13]
- **[confirmed]** a.khan received the phishing message, and the analyst reports no proxy evidence of a click. [E16]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `203.0.113.45` | ip | [E7] |
| `login-micros0ft.test` | domain | [E2] |
| `micros0ft-helpdesk.test` | domain | [E2] |
| `exfil-drop.test` | domain | [E15] |
| `it-support@micros0ft-helpdesk.test` | email | [E2] |
| `mailbox-sync@exfil-drop.test` | email | [E15] |
| `https://login-micros0ft.test/reset?u=akhan` | url | [E3] |
| `https://login-micros0ft.test/reset?u=jpatel` | url | [E2] |
| `https://login-micros0ft.test/submit` | url | [E5] |

## 5. Root cause

**[probable]** j.patel's credentials were most likely harvested by a look-alike phishing page, and the attacker could use them directly because MFA was not enforced. The account had been excluded from the conditional access policy during the 2025 migration and the exception was never removed. The MFA gap is confirmed. The credential-harvest step is inferred from the proxy POST followed by the attacker sign-in. [E5][E7][E18]

### Contributing factors

- **[confirmed]** The email gateway rated the phishing message clean and delivered it. The look-alike domain had been registered only 2 days earlier. [E2][E17]
- **[confirmed]** A stale conditional access exception left over from the 2025 migration was never reviewed or removed, so a password alone was enough to sign in. [E18]
- **[possible]** The proxy categorised the phishing site as 'uncategorized' and the request succeeded. This suggests newly registered or uncategorized domains were not blocked, though no policy is described. [E4]

## 6. Detection gaps

- **[confirmed]** The impossible-travel alert AL-5521 (medium severity) fired at 09:24 but was still untriaged when the analyst picked up the later forwarding-rule alert at 09:52. Containment began roughly 30 minutes after the first alert, and mail was forwarded externally in that window. [E9][E11][E15]
- **[confirmed]** The gateway verdict for the phishing message was 'clean', so there was no pre-delivery detection of the look-alike domain. [E17]

## 7. Lessons learned

**People**
- Reporting and containment work: purging the message from 14 mailboxes and checking proxy logs for a.khan limited the spread. The proxy check showed no click by a.khan. [E16]

**Process**
- Triage order based on alert severity alone can leave an earlier, correlated account-compromise signal untriaged. Impossible-travel alerts on accounts without MFA should be reviewed together with other alerts for the same user. [E10][E11]

**Technology**
- Gateway reputation checks did not catch a domain registered 2 days earlier, so other layers must compensate, such as MFA, proxy controls and post-delivery purge. [E17]

**Governance**
- Temporary conditional access exceptions need an owner and an expiry date. A migration-era exception was left in place and removed MFA protection from an active account. [E18]

## 8. Corrective actions

| Priority | Action | Why | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|
| critical | Enforce MFA for j.patel and audit all conditional access exclusions. Remove those without a documented, time-bound justification. | The compromise succeeded because MFA was not enforced after a migration exception was never removed. [E18] | Identity & Access Management | Immediately for j.patel; audit within 7 days | A phished password alone no longer gives access, and other stale exemptions are found. |
| high | Complete the SharePoint review for j.patel's account covering the period from the first attacker sign-in at 09:22 to the session revocation at 09:58, and identify the content of the 3 forwarded emails. | SharePoint access was flagged as a possibility but not checked, and the exposure from the 3 forwarded emails is unquantified. [E15][E19] | Security Operations / Incident Response | Within 24-48 hours | Establishes the true scope of exposure and any notification obligations. |
| high | Add correlation or priority uplift so that an impossible-travel alert on a user without MFA, or one followed by an inbox-rule alert for the same user, is triaged immediately. | The medium-severity impossible-travel alert was untriaged while the attacker created a forwarding rule. [E9][E11] | Security Operations | 30 days | Faster containment of account takeovers, before mail is exfiltrated. |
| medium | Block the malicious domains login-micros0ft.test, micros0ft-helpdesk.test and exfil-drop.test and the sender and forwarding addresses at the gateway and proxy. Review whether uncategorized or newly registered domains can be restricted or put through browser isolation. | The gateway rated the phishing message clean, and the proxy returned the uncategorized phishing page to the user. [E4][E17] | Email & Network Security | Blocks immediately; policy review within 30 days | Prevents reuse of this infrastructure and reduces exposure to newly registered phishing domains. |

## 9. Open questions and remaining risks

- **Open:** Did the attacker access SharePoint? The analyst notes say this was not checked (R010).
- **Open:** What was in the 3 emails forwarded to mailbox-sync@exfil-drop.test? The evidence records only the count (R006).
- **Open:** Were credentials actually submitted to login-micros0ft.test? The proxy shows only the POST and a 302 response (R020).
- **Open:** What did the attacker do between the first sign-in at 09:22 and session revocation at 09:58 beyond creating the inbox rule? Only auth logs and the rule alert are in the evidence pack.
- **Open:** Why did the 10:01:44 sign-in from 203.0.113.45 fail? Was it the session revocation or another control? (R015)
- **Open:** Do other accounts have stale conditional access exclusions from the 2025 migration? Only j.patel's exclusion is documented (R008).
- **Open:** Did any of the other 12 recipients of the message (14 mailboxes purged in total) click the link? Only a.khan's proxy activity is mentioned (R007).
- **Risk:** Possible unreviewed SharePoint access by the attacker (R010).
- **Risk:** Unknown sensitivity of the 3 emails already forwarded externally (R006).
- **Risk:** Other accounts may still carry a stale MFA exemption of the kind found on j.patel (R008). This is not confirmed.
- **Risk:** The phishing domain was only 2 days old when the message was delivered (R009), so similar look-alike domains may not be caught by the gateway.

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
| E17 | analyst_notes.txt | line 9 | the email gateway rated the phishing message clean |
| E18 | analyst_notes.txt | line 8 | MFA was not enforced for j.patel |
| E19 | analyst_notes.txt | line 10 | attacker may also have accessed SharePoint. Not checked yet. |

**Evidence file hashes (SHA-256)**

- `analyst_notes.txt`: `8780237fd87d750f4044110145655aee9007a91df7064dec9ea5b85c25060a3d`
- `auth_logs.csv`: `38e6f9c3142274cda6cfedbfebfcb9b0795bb254d6a40448045446a8e7ecf330`
- `email_gateway.csv`: `ae827d6b29d1798f666e7e0e30fd53767e33c8a7caa59b007a50548983b8c36d`
- `proxy_logs.csv`: `7392fb696c84ccc4c56fbe001c7ea8e7c2315fc48e47bb3dfdf17852b037ef27`
- `siem_alerts.json`: `8d1524bf2fcdf2a4dcc888199117e7c07669bb1429cf07b624c5e84835bdf078`
