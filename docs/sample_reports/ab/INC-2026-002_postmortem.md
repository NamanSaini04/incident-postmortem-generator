# Incident Postmortem: INC-2026-002: Macro document on Finance workstation WS-FIN-022 led to PowerShell, a dropped DLL and outbound contact with an external domain

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-002 |
| Category | malware |
| Severity | SEV2 |
| Classification confidence | 80% |
| Generated | 2026-11-23 20:11 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A macro-enabled document (Invoice_Oct.docm) marked as from the internet was opened on WS-FIN-022. Word then launched hidden, encoded PowerShell. PowerShell downloaded a script from cdn-update.badcdn.test and dropped a DLL. rundll32 ran the DLL and then contacted the same domain several times, probably as command and control. The root cause was probably the Finance OU exclusion from the macro-blocking policy. Detect-only EDR mode meant the PowerShell launch was alerted on but not blocked. The high-severity EDR alert waited in the queue about 2.5 hours (08:47 to 11:15) behind a backlog. The host was isolated at 11:22. The email gateway does not sandbox .docm attachments. Whether this file arrived by email is not confirmed, so this may have contributed. Scoping is incomplete. EDR shows no connections from the host to other internal hosts, but domain controller logs were not reviewed, so lateral movement and credential theft are not ruled out.

**Severity rationale:** A host compromise with attacker activity is confirmed (Word spawned PowerShell, a DLL was dropped and run, and the host contacted an external domain). The host was isolated and later reimaged. No large-scale sensitive data exposure is confirmed. Lateral movement and credential theft are not ruled out, because domain controller logs have not been reviewed.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| **EV001** | **2026-10-21 08:47:10** | **event=file_open; process=WINWORD.EXE; user=m.okafor** | exact | [E1] |
| **EV002** | **2026-10-21 08:47:32** | **rule=Office application spawned PowerShell; event=process_create; action=detected; process=powershell.exe; cmd** | exact | [E2] |
| **EV003** | **2026-10-21 08:47:35** | **event=network_connect; process=powershell.exe; dest=http://cdn-update.badcdn.test/s2.ps1; user=m.okafor (seen ** | exact | [E3][E4] |
| EV004 | 2026-10-21 08:48:02 | event=file_write; process=powershell.exe; user=m.okafor | exact | [E5] |
| **EV005** | **2026-10-21 08:48:10** | **event=process_create; process=rundll32.exe; cmdline=rundll32.exe C:\Users\m.okafor\AppData\Roaming\upd.dll,Sta** | exact | [E6] |
| **EV006** | **2026-10-21 08:49:00** | **process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022** | exact | [E7] |
| EV007 | 2026-10-21 08:50:00 | process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022 | exact | [E8] |
| **EV008** | **2026-10-21 11:15:00** | **11:15 EDR-3301 picked up by soc.analyst2. Alert had been in the queue since 08:47; two analysts on shift, back** | date inferred | [E9] |
| **EV009** | **2026-10-21 11:21:00** | **process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022** | exact | [E10] |
| EV010 | 2026-10-21 11:22:00 | 11:22 Isolated WS-FIN-022 from the network via EDR console. | date inferred | [E11] |
| **EV011** | **2026-10-21 11:22:04** | **event=host_isolated; process=edr-console; user=soc.analyst2** | exact | [E12] |
| **EV012** | **2026-10-21 11:40:00** | **11:40 Blocked both file hashes and cdn-update.badcdn.test at EDR and proxy.** | date inferred | [E13] |

## 3. What happened

- **[confirmed]** User m.okafor opened Invoice_Oct.docm in Word on WS-FIN-022. The file carried an internet mark-of-the-web (EV001). [E1]
- **[confirmed]** Within about 20 seconds, WINWORD.EXE spawned hidden, encoded PowerShell. EDR raised high-severity alert EDR-3301 but only 'detected' it, so the launch was not blocked (EV002). [E2]
- **[confirmed]** PowerShell fetched http://cdn-update.badcdn.test/s2.ps1 from 203.0.113.80 and the proxy recorded status 200 (EV003). [E3][E4]
- **[confirmed]** PowerShell wrote upd.dll to the user's AppData\Roaming folder, and rundll32.exe then executed it (EV004, EV005). [E5][E6]
- **[probable]** rundll32.exe contacted https://cdn-update.badcdn.test/api/c repeatedly (EV006, EV007, EV009), including at 11:21, just before isolation. The repeated small requests are probably command-and-control beaconing. The responses' content is not known. [E7][E8][E10]
- **[confirmed]** EDR-3301 sat in the queue from 08:47 until soc.analyst2 picked it up at 11:15, with two analysts on shift and a backlog of 40 alerts (EV008). [E9]
- **[confirmed]** The host was isolated via the EDR console at 11:22. At 11:40 both file hashes and the domain were blocked at EDR and proxy. The host was reimaged the next day (EV010, EV011, EV012). [E12][E13][E14]
- **[confirmed]** EDR showed no connections from WS-FIN-022 to other internal hosts in the last 24 hours. Domain controller logs had not been reviewed. [E15]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `03d4e4ac1e7906c11788372f9a48a2a1b37a8c3a93b19f2a0d79c3a02ac4745c` | sha256 | [E1] |
| `deb8fb893310bbdb9ae77981d7ff5659e376d094078d88a791777e4faeda45a4` | sha256 | [E5] |
| `203.0.113.80` | ip | [E4] |
| `cdn-update.badcdn.test` | domain | [E3] |
| `http://cdn-update.badcdn.test/s2.ps1` | url | [E3] |
| `https://cdn-update.badcdn.test/api/c` | url | [E7] |

## 5. Root cause

**[probable]** The Finance OU is excluded from the policy that blocks macros in internet-sourced files. This probably let the internet-marked .docm run code (spawning PowerShell) on WS-FIN-022. The macro itself is not directly shown in the evidence. [E1][E2][E16]

### Contributing factors

- **[confirmed]** EDR on Finance workstations is in detect-only mode, so the Office-to-PowerShell launch was alerted on but not blocked. [E17][E18]
- **[confirmed]** SOC capacity and queueing: two analysts on shift and a backlog of 40 alerts left a high-severity alert unattended for about 2.5 hours. [E9]
- **[possible]** The email gateway does not sandbox .docm attachments. This may have let the file through if it arrived by email, but the delivery route is not recorded. [E19][E20]

## 6. Detection gaps

- **[confirmed]** A high-severity alert (Office application spawned PowerShell) was not triaged for about 2.5 hours, and the C2-like beaconing continued until isolation. [E9][E10]
- **[confirmed]** EDR on Finance hosts only detected and did not block, so no automatic response happened at the time of the alert. [E2][E17]
- **[confirmed]** Scoping is incomplete because domain controller and authentication logs have not been reviewed. [E15]

## 7. Lessons learned

**Process**
- High-severity alerts can still wait behind a backlog. The delay pattern from PIR-2025-014 recurred, and triage prioritisation needs to be enforced. [E9] [P1]
- The incident should not be closed until scoping covers domain controller and authentication logs, even when EDR shows no lateral connections. [E15] [P2]

**Technology**
- Detect-only EDR on a high-risk team turned a high-severity detection into a 2.5-hour compromise window. Prevent mode is the standard. [E17] [P3]

**Governance**
- A broad OU-level macro exclusion, added for a legacy add-in, left the whole Finance OU exposed. Exclusions should be narrow and time-boxed. [E16] [P4]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Remove the Finance OU exclusion from the macro-blocking policy. Replace it with an exclusion limited to signed macros or trusted locations for the legacy Excel add-in. | The exclusion is the probable root cause and conflicts with the macro standard. [E16] | [P4] | Endpoint / IT Operations | 1 week | Internet-sourced macros are blocked on Finance workstations. |
| critical | Switch EDR on Finance workstations to prevent (block) mode, at minimum for Office-spawned PowerShell. | Detect-only mode let the PowerShell launch proceed. [E17] | [P3] | Security Engineering | 1 week | The attack chain is stopped automatically at the Office-to-PowerShell step. |
| high | Review domain controller and authentication logs for m.okafor and WS-FIN-022 since 08:47 on 2026-10-21. Check for lateral movement and credential theft, and reset credentials if indicated. | Scoping is incomplete and the host was in contact with an external domain for about 2.5 hours. [E15] | [P2] | SOC / Incident Response | 24-48 hours | Confirms or rules out wider compromise before the incident is closed. |
| high | Search all endpoints and proxy logs for the two file hashes and for cdn-update.badcdn.test / 203.0.113.80, and confirm the blocks cover firewall and proxy. | Blocks were applied at EDR and proxy, but no fleet-wide search is recorded. [E13] | [P5] | SOC / Incident Response | 48 hours | Finds any other affected hosts. |
| high | Detonate .docm and other macro-enabled attachments in a sandbox, or quarantine them, at the email gateway. | The gateway does not sandbox .docm attachments, and the user believed the file was a real supplier invoice. [E19] | [P6] | Messaging / Security Engineering | 30 days | Fewer malicious macro documents reach users by email. |
| high | Add a paging or fast-track rule for high-severity EDR alerts such as Office application spawning PowerShell. Triage alerts for the same user or host together, and review SOC staffing against alert volume. | A high-severity alert waited about 2.5 hours behind a backlog. [E9] | [P1] | SOC Management | 30 days | Shorter time from detection to containment. |

## 9. Open questions and remaining risks

- **Open:** How did Invoice_Oct.docm reach the user (email, web download or other)? No email delivery is recorded; only the user's statement that it looked like a supplier invoice (ticket.txt line 11) and a file in the Downloads folder (edr_events.json events[0]).
- **Open:** Did the macro run via the document itself? The Word-to-PowerShell chain strongly suggests it, but macro execution is not directly recorded.
- **Open:** What did the s2.ps1 script and the /api/c responses contain or do? The PowerShell command line is redacted and the content of the responses is not in the evidence.
- **Open:** Were credentials, files or other data accessed or exfiltrated from WS-FIN-022 between 08:47 and 11:22? This is not determinable from the evidence.
- **Open:** Do domain controller and authentication logs show lateral movement or credential misuse?
- **Open:** Were the file hashes and domain searched for on other endpoints, and did any other host receive the same document?
- **Risk:** Lateral movement or credential theft is not ruled out until domain controller logs are reviewed.
- **Risk:** The Finance OU macro exclusion and detect-only EDR remain in place on other Finance workstations until they are changed.
- **Risk:** Other users may have received the same document, because no fleet-wide search is recorded.

## 10. Validation log

- attempt 1: 0 validation problem(s)

## Evidence index

| Ref | File | Location | Quote |
|---|---|---|---|
| E1 | edr_events.json | events[0] | 2026-10-21T08:47:10Z |
| E2 | edr_events.json | events[1] | 2026-10-21T08:47:32Z |
| E3 | edr_events.json | events[2] | 2026-10-21T08:47:35Z |
| E4 | proxy_logs.csv | row 1 | 2026-10-21T08:47:35Z |
| E5 | edr_events.json | events[3] | 2026-10-21T08:48:02Z |
| E6 | edr_events.json | events[4] | 2026-10-21T08:48:10Z |
| E7 | proxy_logs.csv | row 2 | 2026-10-21T08:49:00Z |
| E8 | proxy_logs.csv | row 3 | 2026-10-21T08:50:00Z |
| E9 | ticket.txt | line 3 | 11:15 |
| E10 | proxy_logs.csv | row 4 | 2026-10-21T11:21:00Z |
| E11 | ticket.txt | line 4 | 11:22 |
| E12 | edr_events.json | events[5] | 2026-10-21T11:22:04Z |
| E13 | ticket.txt | line 5 | 11:40 |
| E14 | ticket.txt | line 6 | WS-FIN-022 reimaged and returned to m.okafor |
| E15 | ticket.txt | line 10 | EDR shows no connections from WS-FIN-022 to other internal hosts in the last 24h |
| E16 | ticket.txt | line 7 | the Finance OU is excluded from the policy that blocks macros in files from the internet |
| E17 | ticket.txt | line 8 | EDR policy on Finance workstations is detect-only |
| E18 | edr_events.json | meta | "policy_mode": "detect_only" |
| E19 | ticket.txt | line 9 | the email gateway does not sandbox .docm attachments |
| E20 | ticket.txt | line 11 | the attachment looked like a real supplier invoice |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | PIR-2025-014 §2 Lessons | waited behind higher alerts for 40 minutes |
| P2 | PB-03 §4 Scoping | check for lateral movement and credential theft before closing the incident |
| P3 | STD-03 §2 EDR mode | Detect-only mode is allowed only during a rollout of at most 14 days |
| P4 | STD-03 §1 Office macros | never a whole organisational unit |
| P5 | PB-03 §3 Blocking | search all endpoints for the same indicators |
| P6 | STD-03 §3 Email attachments | are detonated in a sandbox before delivery or quarantined |

_Knowledge-base sections given to the model: STD-03#1, STD-03#3, STD-03#2, PB-03#3, PB-03#4, PB-03#2, PIR-2025-014#1, PIR-2025-014#2_

**Evidence file hashes (SHA-256)**

- `edr_events.json`: `3c98dbcd93fedb673da4f059464562227c07d68b385c67ffcc45c45774419de2`
- `proxy_logs.csv`: `33f0750263e250b5533d3d380e051eb78a4109742926ebd5d3f28cbe3d5ec98c`
- `ticket.txt`: `bc94ce0f3adccc76467de6e56ce222889fd0676d375ba5e2f216de06b47a8e0b`
