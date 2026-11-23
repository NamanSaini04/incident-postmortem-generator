# Incident Postmortem: INC-2026-001: Probable phishing-led credential compromise of j.patel with external mail forwarding

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-001 |
| Category | credential_compromise |
| Severity | SEV2 |
| Classification confidence | 80% |
| Generated | 2026-11-23 20:09 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A look-alike 'password expires' email was delivered to j.patel and a.khan. The gateway rated it clean. j.patel's host visited the phishing page and posted to its submit URL. Credentials were probably entered, but this is not directly confirmed. Minutes later, j.patel's account was signed into from a different country (NL) by a scripted client, with no MFA required. The attacker created an inbox rule forwarding mail to an external address. Three emails were forwarded before the rule was removed. The root cause was probably credential theft via phishing combined with an account excluded from MFA. That exclusion was left over from the 2025 migration and never removed. The impossible-travel alert was not triaged before the analyst picked up the later forwarding-rule alert. Response then revoked sessions, reset the password, removed the rule and purged the email. Whether SharePoint was accessed is not confirmed. It was not checked.

**Severity rationale:** The j.patel account was confirmed compromised, with attacker sign-ins and an external forwarding rule, and it was contained. Three emails were confirmed forwarded externally. The evidence does not show what they contained or any large-scale sensitive data exposure. SharePoint access was not checked, so this rating may need review.

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
| **EV014** | **2026-10-06 10:05:00** | **10:05 Reset password for j.patel and confirmed with user by phone.** | date inferred | [E14] |
| **EV015** | **2026-10-06 10:12:00** | **10:12 Removed inbox rule 'sync'. Message trace shows 3 emails forwarded to mailbox-sync@exfil-drop.test before** | date inferred | [E15] |
| EV016 | 2026-10-06 10:40:00 | 10:40 Purged phishing message from 14 mailboxes. a.khan received it but proxy shows no click. | date inferred | [E16] |

## 3. What happened

- **[confirmed]** A phishing email titled 'Action required: password expires today' from a look-alike domain was delivered to j.patel, with a link to a look-alike login page. The gateway verdict was 'clean'. [E2]
- **[probable]** The same email was delivered to a.khan, but the proxy shows no click, so a.khan was probably not compromised. From j.patel's host LT-OPS-114, the phishing URL was fetched (GET, status 200) and then a POST was sent to the site's submit URL (status 302). This probably means credentials were submitted, but the POST contents are not in the evidence. [E4][E5][E16]
- **[confirmed]** Within about three minutes of the POST, j.patel's account signed in successfully to Exchange Online and OfficeHome from 203.0.113.45 (NL) using a python-requests client. MFA was not required. The earlier normal sign-in came from the London VPN egress. [E7][E8]
- **[confirmed]** An inbox rule 'sync' was created from 203.0.113.45. It forwarded messages containing 'invoice' to an external address. Message trace shows 3 emails were forwarded before the rule was removed. The content of those emails is not recorded. [E10][E15]
- **[confirmed]** The SOC revoked j.patel's sessions, reset the password (confirmed with the user by phone), removed the forwarding rule and purged the phishing message from 14 mailboxes. A sign-in attempt from 203.0.113.45 at 10:01:44 failed, after the session revocation. [E12][E13][E14][E15][E16]
- **[unknown]** Whether the attacker accessed SharePoint or other data is unknown. It was not checked. [E17]

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

**[probable]** j.patel probably submitted credentials to a look-alike phishing page, and the attacker then signed in from 203.0.113.45. The sign-in succeeded without MFA because the account had been excluded from the conditional access policy during the 2025 migration and the exception was never removed. The credential submission is inferred from the POST and the following sign-in, not directly confirmed. [E5][E7][E18]

### Contributing factors

- **[confirmed]** MFA was not enforced for j.patel. The account was excluded from the conditional access policy during the 2025 migration and the exception was never removed. [E18]
- **[confirmed]** The email gateway rated the phishing message clean even though the look-alike domain was registered 2 days earlier. [E19]
- **[confirmed]** The proxy allowed j.patel's host to reach the uncategorized phishing site (status 200) and post to it. [E4]

## 6. Detection gaps

- **[confirmed]** The medium-severity impossible-travel alert AL-5521 (09:24) had not been triaged when the analyst picked up the high-severity forwarding-rule alert AL-5527 at 09:52. This was about 28 minutes after the first alert and about 21 minutes after the second. Forwarding of 3 emails occurred before the rule was removed at 10:12. [E9][E11][E15]
- **[probable]** Neither the gateway nor the proxy blocked or flagged the newly registered look-alike domain. No alert fired on the phishing click or credential POST. The first alerts came from post-compromise activity. [E2][E5][E9]

## 7. Lessons learned

**People**
- Quick purge and a.khan's non-click limited spread. Incident scoping must also cover cloud data access, which was left unchecked here. [E16][E17]

**Process**
- Alert triage needs to account for multiple alerts on the same user. A medium impossible-travel alert on j.patel sat untriaged while a related high-severity alert was handled. [E9][E11]

**Technology**
- Gateway reputation verdicts alone did not catch a look-alike domain registered 2 days earlier. Domain age and look-alike signals are needed at the mail and web layers. [E4][E19]

**Governance**
- Temporary MFA exclusions need an owner and an expiry. This one outlived the 2025 migration and left a single phished password sufficient for access. [E18]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Audit all conditional access exclusions, remove stale ones (including any remaining from the 2025 migration), and enforce MFA for j.patel. Add an expiry and an owner to every future exception. | j.patel's account was excluded from MFA and the attacker signed in with no MFA required. [E7][E18] | - | Identity & Access Management | Immediate (within 1 week) | A stolen password alone no longer gives access. |
| high | Review j.patel's SharePoint, OneDrive and mailbox activity from the first attacker sign-in (EV007) through the failed 10:01 attempt (EV013). Establish what the 3 forwarded emails contained and whether other data was accessed. | SharePoint access was not checked, and the content of the forwarded emails is not recorded. [E15][E17] | - | SOC / Incident Response | Immediate (within 48 hours) | Confirms or rules out wider data exposure and validates the severity rating. |
| high | Alert on, or block, creation of inbox rules that forward to external addresses. Auto-escalate when such a rule follows a sign-in from a new country or a scripted user agent. | An external forwarding rule created from the attacker IP forwarded 3 emails before it was removed. [E10][E15] | - | Messaging / Security Engineering | 30 days | Limits mail exfiltration and speeds response. |
| high | Tune the email gateway and proxy to treat newly registered and look-alike domains as suspicious, with detonation, rewriting or blocking of links. Add the observed indicators to blocklists. | The look-alike phishing domain was rated clean by the gateway and reached through the proxy as uncategorized. [E4][E19] | - | Email & Network Security | 30 days | Reduces phishing delivery and click-through to new look-alike domains. |
| medium | Revise SOC queue handling so that multiple open alerts for the same user are correlated and triaged together, with a time-to-triage target for medium alerts on identity events such as impossible travel. | AL-5521 was untriaged when the analyst picked up AL-5527, roughly 28 minutes after the first alert. [E9][E11] | - | SOC Management | 60 days | Shortens attacker dwell time and the exposure window. |

## 9. Open questions and remaining risks

- **Open:** Did the attacker access SharePoint or other data? This was not checked.
- **Open:** Were credentials actually entered on the phishing page at EV005? Only the POST and the following sign-in are recorded.
- **Open:** What did the 3 forwarded emails contain, and did they include sensitive data?
- **Open:** How many other users received the phishing message beyond j.patel and a.khan? It was purged from 14 mailboxes, and clicks were checked only for a.khan.
- **Open:** What was the reason for the failed sign-in at 10:01:44 (EV013)? The reason is not recorded, and the password reset came after it.
- **Open:** Were any other inbox rules, OAuth grants or sign-ins created by the attacker? Only the rule 'sync' is documented.
- **Risk:** Possible unreviewed access to SharePoint or other j.patel resources.
- **Risk:** Other recipients of the phishing message may have clicked, since proxy review is documented only for a.khan.
- **Risk:** Other accounts may have stale MFA exclusions, since the exception for j.patel was never removed.

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
| E17 | analyst_notes.txt | line 10 | attacker may also have accessed SharePoint. Not checked yet. |
| E18 | analyst_notes.txt | line 8 | MFA was not enforced for j.patel. |
| E19 | analyst_notes.txt | line 9 | the email gateway rated the phishing message clean |

**Evidence file hashes (SHA-256)**

- `analyst_notes.txt`: `8780237fd87d750f4044110145655aee9007a91df7064dec9ea5b85c25060a3d`
- `auth_logs.csv`: `38e6f9c3142274cda6cfedbfebfcb9b0795bb254d6a40448045446a8e7ecf330`
- `email_gateway.csv`: `ae827d6b29d1798f666e7e0e30fd53767e33c8a7caa59b007a50548983b8c36d`
- `proxy_logs.csv`: `7392fb696c84ccc4c56fbe001c7ea8e7c2315fc48e47bb3dfdf17852b037ef27`
- `siem_alerts.json`: `8d1524bf2fcdf2a4dcc888199117e7c07669bb1429cf07b624c5e84835bdf078`
