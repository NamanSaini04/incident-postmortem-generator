# Incident Postmortem: INC-2026-002: Macro-enabled document leads to PowerShell payload and C2 traffic on finance workstation WS-FIN-022

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-002 |
| Category | malware |
| Severity | SEV2 |
| Classification confidence | 80% |
| Generated | 2026-11-23 20:41 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A user on WS-FIN-022 opened an internet-sourced macro-enabled document, and Word then launched hidden, encoded PowerShell. PowerShell downloaded a script and dropped a DLL that was run with rundll32. The host then made repeated connections to the same external domain, which is consistent with command-and-control. The most likely root cause is that the Finance OU is exempt from macro blocking, so the document's macro probably ran. The record does not directly state that a macro executed. EDR detected the PowerShell launch but, in detect-only mode, did not block it. The high-severity alert then waited about 2.5 hours in the queue before the host was isolated. The host was isolated, the hashes and domain were blocked, and the host was reimaged. EDR showed no internal connections, but domain controller logs were not reviewed, so lateral movement is not ruled out.

**Severity rationale:** A host compromise with attacker activity is confirmed: a downloaded DLL was run and the host made repeated connections to the malicious domain. The host was isolated and reimaged. No data exposure is confirmed, and EDR saw no internal connections from the host. Domain controller logs had not been reviewed, so the scope is not fully closed.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| **EV001** | **2026-10-21 08:47:10** | **event=file_open; process=WINWORD.EXE; user=m.okafor** | exact | [E1] |
| **EV002** | **2026-10-21 08:47:32** | **rule=Office application spawned PowerShell; event=process_create; action=detected; process=powershell.exe; cmd** | exact | [E2] |
| **EV003** | **2026-10-21 08:47:35** | **event=network_connect; process=powershell.exe; dest=http://cdn-update.badcdn.test/s2.ps1; user=m.okafor (seen ** | exact | [E3][E4] |
| EV004 | 2026-10-21 08:48:02 | event=file_write; process=powershell.exe; user=m.okafor | exact | [E5] |
| **EV005** | **2026-10-21 08:48:10** | **event=process_create; process=rundll32.exe; cmdline=rundll32.exe C:\Users\m.okafor\AppData\Roaming\upd.dll,Sta** | exact | [E6] |
| EV006 | 2026-10-21 08:49:00 | process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022 | exact | [E7] |
| **EV007** | **2026-10-21 08:50:00** | **process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022** | exact | [E8] |
| **EV008** | **2026-10-21 11:15:00** | **11:15 EDR-3301 picked up by soc.analyst2. Alert had been in the queue since 08:47; two analysts on shift, back** | date inferred | [E9] |
| EV009 | 2026-10-21 11:21:00 | process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022 | exact | [E10] |
| **EV010** | **2026-10-21 11:22:00** | **11:22 Isolated WS-FIN-022 from the network via EDR console.** | date inferred | [E11] |
| EV011 | 2026-10-21 11:22:04 | event=host_isolated; process=edr-console; user=soc.analyst2 | exact | [E12] |
| **EV012** | **2026-10-21 11:40:00** | **11:40 Blocked both file hashes and cdn-update.badcdn.test at EDR and proxy.** | date inferred | [E13] |

## 3. What happened

- **[confirmed]** User m.okafor opened Invoice_Oct.docm in Word on WS-FIN-022. The file carried an internet mark-of-the-web. [E1]
- **[confirmed]** About 22 seconds later, WINWORD.EXE spawned a hidden PowerShell process with an encoded command. EDR raised a high-severity alert but only detected it, so it did not block the launch. [E2]
- **[confirmed]** PowerShell fetched a script from cdn-update.badcdn.test. The proxy logged HTTP 200 with about 18 KB received. [E3][E4]
- **[confirmed]** PowerShell wrote upd.dll to the user's AppData\Roaming folder, and rundll32.exe then ran it with the Start export. [E5][E6]
- **[probable]** rundll32.exe made repeated HTTPS requests to cdn-update.badcdn.test/api/c at 08:49, 08:50 and 11:21, which is probably command-and-control traffic. Only these proxy rows are available. The gaps between them are not explained. [E7][E8][E10]
- **[confirmed]** A SOC analyst picked up the alert at 11:15, after it had waited in the queue since 08:47. The host was isolated at 11:22. [E9][E11]
- **[confirmed]** Both file hashes and the domain were blocked at EDR and proxy. The workstation was reimaged the next day. [E13][E14]
- **[confirmed]** EDR showed no connections from the host to other internal hosts in the last 24 hours. Domain controller logs had not been reviewed. [E15]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `03d4e4ac1e7906c11788372f9a48a2a1b37a8c3a93b19f2a0d79c3a02ac4745c` | sha256 | [E1] |
| `deb8fb893310bbdb9ae77981d7ff5659e376d094078d88a791777e4faeda45a4` | sha256 | [E5] |
| `203.0.113.80` | ip | [E4] |
| `cdn-update.badcdn.test` | domain | [E3] |
| `http://cdn-update.badcdn.test/s2.ps1` | url | [E3] |
| `https://cdn-update.badcdn.test/api/c` | url | [E7] |

## 5. MITRE ATT&CK mapping

| Tactic | Technique | ID | Certainty | Behaviour | Evidence |
|---|---|---|---|---|---|
| execution | User Execution: Malicious File | T1204.002 | probable | The user opened a macro-enabled document from the internet, and Word then launched PowerShell. | [E1][E2] |
| execution | Command and Scripting Interpreter: PowerShell | T1059.001 | confirmed | Hidden PowerShell was run with an encoded command. | [E2] |
| command-and-control | Ingress Tool Transfer | T1105 | probable | PowerShell downloaded a remote script and then wrote a DLL to disk. | [E3][E5] |
| stealth | System Binary Proxy Execution: Rundll32 | T1218.011 | confirmed | rundll32.exe was used to run the dropped DLL. | [E6] |
| command-and-control | Application Layer Protocol: Web Protocols | T1071.001 | probable | rundll32 made repeated small HTTPS requests to the attacker domain. | [E7][E10] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**[probable]** A macro-enabled document from the internet was opened on a Finance workstation, and the macro probably ran because the Finance OU is excluded from the macro-blocking policy. EDR on Finance hosts only detected, and the email gateway does not sandbox .docm files, so nothing stopped the chain. The records do not directly show the macro executing or how the file was delivered. [E1][E2][E16]

### Contributing factors

- **[confirmed]** The Finance OU is excluded from macro blocking for internet files. The exclusion was added in 2024 for a legacy Excel add-in and covers the whole OU. [E16]
- **[confirmed]** EDR on Finance workstations is in detect-only mode, so the PowerShell launch was not blocked. [E17][E18]
- **[confirmed]** The email gateway does not sandbox .docm attachments. [E19]
- **[confirmed]** SOC capacity was strained: two analysts were on shift with a backlog of 40 alerts. The high-severity alert waited from 08:47 to 11:15. [E9]
- **[confirmed]** The user believed the attachment was a genuine supplier invoice. This was a lure, not a user failing. [E20]

## 7. Detection gaps

- **[confirmed]** The high-severity alert (Office application spawned PowerShell) went unactioned for about 2.5 hours. Beaconing continued during that time and was seen again at 11:21, just before isolation. [E9][E10]
- **[confirmed]** EDR only alerted and did not prevent execution on Finance hosts. [E17]
- **[confirmed]** Scoping is incomplete. Domain controller logs were not reviewed, so lateral movement and credential theft cannot be ruled out. [E15]

## 8. Lessons learned

**Process**
- A high-severity alert for a classic malware pattern waited behind a backlog. Triage must prioritise by severity and technique. The same queue-delay lesson was already recorded in an earlier incident review. [E9] [P1]
- The incident was contained before scoping was finished. Authentication and domain controller review must be completed before the incident is closed. [E15] [P2]

**Technology**
- Detect-only EDR on Finance workstations turned a high-confidence detection into a successful compromise. Prevent mode would have blocked the PowerShell launch. [E17] [P3]
- Not sandboxing macro-enabled attachments removed an upstream control that could have stopped the document reaching the user, though delivery is not confirmed. [E19] [P4]

**Governance**
- A blanket OU-wide exclusion from macro blocking, made for a legacy add-in, left a high-value team exposed for about two years. Exclusions should be narrow and reviewed. [E16] [P5]

## 9. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Remove the Finance OU exclusion from the macro-blocking policy. Where the legacy Excel add-in still needs macros, allow only signed macros or trusted locations. | The OU-wide exclusion allowed an internet-sourced macro document to run on a Finance host. [E16] | [P5] | Endpoint / Identity engineering | Within 7 days | Internet-sourced macros are blocked again for Finance users. |
| critical | Move EDR on Finance workstations from detect-only to prevent mode. | The Office-to-PowerShell chain was detected but not blocked. [E17] | [P3] | Security engineering | Within 7 days | Malicious process chains are blocked at execution. |
| high | Enable sandbox detonation or quarantine for .docm and other macro-enabled attachments at the email gateway. | The gateway does not sandbox .docm attachments. [E19] | [P4] | Messaging / Security engineering | Within 30 days | Fewer malicious macro documents reach users. |
| high | Complete scoping: review domain controller and authentication logs for m.okafor and WS-FIN-022 for lateral movement and credential theft before closing the incident. | Domain controller logs were not reviewed, and the attacker's C2 channel was live for about 2.5 hours. [E15] | [P2] | SOC / Incident response | Within 2 days | Confirms or rules out spread beyond the single host. |
| high | Search all endpoints and proxy logs for the two file hashes and for cdn-update.badcdn.test and 203.0.113.80. Block the IP at the proxy and firewall if it is not already blocked. | Blocks were applied to the hashes and the domain, but no record shows an endpoint-wide search or a block of the IP. [E13] | [P6] | SOC / Threat hunting | Within 2 days | Finds any other affected hosts and closes the IOC blocking gap. |
| high | Add a triage rule that places high-severity EDR alerts such as Office application spawned PowerShell at the top of the queue with a short response target. Review SOC staffing against the alert backlog. | The alert waited about 2.5 hours behind a backlog while the attacker's channel was active. [E9] | [P1] | SOC management | Within 14 days | Faster containment of high-confidence detections. |

## 10. Open questions and remaining risks

- **Open:** How was Invoice_Oct.docm delivered (email or another route)? No email delivery record is in the evidence, so phishing is not confirmed.
- **Open:** Did a macro in the document actually launch PowerShell? EDR records Word as the parent process, but the record does not state macro execution.
- **Open:** What did the downloaded script s2.ps1 and the DLL upd.dll do beyond beaconing? Was any data accessed or sent out? The evidence does not show.
- **Open:** What happened on the host between 08:50 and 11:21? Only four proxy rows are provided.
- **Open:** Do domain controller and authentication logs show lateral movement or credential theft for m.okafor or WS-FIN-022?
- **Open:** Are other endpoints or users affected by the same document, hashes or domain? No endpoint-wide search is recorded.
- **Risk:** Lateral movement or credential theft is not ruled out until domain controller logs are reviewed.
- **Risk:** The Finance OU macro exclusion and detect-only EDR remain in place for other Finance users until they are corrected.
- **Risk:** The email gateway still does not sandbox .docm attachments, so a similar document could reach users again.
- **Risk:** Other endpoints may have received the same file or contacted the malicious domain. This has not been checked.

## 11. Validation log

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
| E17 | ticket.txt | line 8 | EDR policy on Finance workstations is detect-only, so the PowerShell launch was not blocked. |
| E18 | edr_events.json | meta | "policy_mode": "detect_only" |
| E19 | ticket.txt | line 9 | the email gateway does not sandbox .docm attachments. |
| E20 | ticket.txt | line 11 | the attachment looked like a real supplier invoice. |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | PIR-2025-014 §2 Lessons | waited behind higher alerts for 40 minutes |
| P2 | PB-03 §4 Scoping | Review domain controller and authentication logs for the user and host |
| P3 | STD-03 §2 EDR mode | EDR runs in prevent (block) mode on all workstations and servers |
| P4 | STD-03 §3 Email attachments | are detonated in a sandbox before delivery or quarantined |
| P5 | STD-03 §1 Office macros | never a whole organisational unit |
| P6 | PB-03 §3 Blocking | search all endpoints for the same indicators |

_Knowledge-base sections given to the model: STD-03#1, STD-03#3, STD-03#2, PB-03#3, PB-03#4, PB-03#2, PIR-2025-014#1, PIR-2025-014#2_

**Evidence file hashes (SHA-256)**

- `edr_events.json`: `3c98dbcd93fedb673da4f059464562227c07d68b385c67ffcc45c45774419de2`
- `proxy_logs.csv`: `33f0750263e250b5533d3d380e051eb78a4109742926ebd5d3f28cbe3d5ec98c`
- `ticket.txt`: `bc94ce0f3adccc76467de6e56ce222889fd0676d375ba5e2f216de06b47a8e0b`
