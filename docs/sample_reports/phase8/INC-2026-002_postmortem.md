# Incident Postmortem: INC-2026-002: Macro-enabled document leads to PowerShell loader and DLL beaconing on Finance workstation WS-FIN-022

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-002 |
| Category | malware |
| Severity | SEV2 |
| Classification confidence | 80% |
| Generated | 2026-11-24 09:01 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A macro-enabled document from the internet was opened on WS-FIN-022 by m.okafor, and Word then launched hidden, encoded PowerShell. PowerShell fetched a script from cdn-update.badcdn.test, dropped upd.dll and ran it with rundll32. That process then contacted the same domain repeatedly, which probably indicates command-and-control. The Finance OU was exempt from the macro-blocking policy, which is the root cause. The attachment's delivery path (for example email) is not confirmed. EDR on Finance workstations was detect-only and the email gateway does not sandbox .docm files, so nothing stopped the chain. The high-severity EDR alert sat in the queue from 08:47 until 11:15 because of analyst backlog. The host was isolated at 11:22. The host was reimaged and the hashes and domain were blocked. Data impact and lateral movement are not confirmed because domain controller logs have not been reviewed.

**Severity rationale:** Host compromise with attacker code execution and repeated outbound contact to an attacker domain is confirmed on WS-FIN-022 (user m.okafor). The host was isolated and reimaged. No confirmed exposure of sensitive data at scale: EDR shows no internal connections in 24h, but domain controller logs were not reviewed and data impact is unknown.

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
| EV007 | 2026-10-21 08:50:00 | process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022 | exact | [E8] |
| **EV008** | **2026-10-21 11:15:00** | **11:15 EDR-3301 picked up by soc.analyst2. Alert had been in the queue since 08:47; two analysts on shift, back** | date inferred | [E9] |
| **EV009** | **2026-10-21 11:21:00** | **process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022** | exact | [E10] |
| **EV010** | **2026-10-21 11:22:00** | **11:22 Isolated WS-FIN-022 from the network via EDR console.** | date inferred | [E11] |
| EV011 | 2026-10-21 11:22:04 | event=host_isolated; process=edr-console; user=soc.analyst2 | exact | [E12] |
| **EV012** | **2026-10-21 11:40:00** | **11:40 Blocked both file hashes and cdn-update.badcdn.test at EDR and proxy.** | date inferred | [E13] |

## 3. What happened

- **[confirmed]** User m.okafor opened Invoice_Oct.docm in Word on WS-FIN-022. The file carried an internet mark-of-the-web. [E1]
- **[confirmed]** About 20 seconds later WINWORD.EXE spawned PowerShell with hidden-window, no-profile, encoded-command arguments. EDR raised high-severity alert EDR-3301 but only detected, not blocked. [E2]
- **[confirmed]** PowerShell connected to cdn-update.badcdn.test and retrieved s2.ps1 (HTTP 200, about 18 KB inbound). [E4]
- **[confirmed]** PowerShell wrote upd.dll to the user's AppData\Roaming folder, then launched it via rundll32.exe. [E5][E6]
- **[probable]** rundll32.exe made repeated small HTTPS requests to cdn-update.badcdn.test/api/c at 08:49 and 08:50, and again at 11:21, just before isolation. This pattern is consistent with command-and-control beaconing, but the proxy logs do not show what the traffic contained. [E7][E8][E10]
- **[confirmed]** A SOC analyst picked up EDR-3301 at 11:15. The alert had waited in the queue since 08:47 amid a backlog of 40 alerts and two analysts on shift. [E9]
- **[confirmed]** WS-FIN-022 was isolated via the EDR console at 11:22. Both file hashes and the domain were blocked at EDR and proxy at 11:40. The host was reimaged and returned to the user the next day. [E11][E13][E14]
- **[confirmed]** EDR shows no connections from WS-FIN-022 to other internal hosts in the last 24h. Domain controller logs had not been reviewed at the time of the ticket. [E15]

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
| execution | User Execution: Malicious File | T1204.002 | confirmed | The user opened a macro-enabled Office document from the internet, and Word then spawned PowerShell. | [E1][E2] |
| execution | Command and Scripting Interpreter: PowerShell | T1059.001 | confirmed | PowerShell was launched with an encoded command and fetched a remote script. | [E2] |
| stealth | Hide Artifacts: Hidden Window | T1564.003 | confirmed | PowerShell was run with a hidden window. | [E2] |
| command-and-control | Ingress Tool Transfer | T1105 | confirmed | A script was pulled from an external host, and a DLL was then written to disk by PowerShell. | [E4][E5] |
| stealth | System Binary Proxy Execution: Rundll32 | T1218.011 | confirmed | The dropped DLL was executed via rundll32.exe. | [E6] |
| command-and-control | Application Layer Protocol: Web Protocols | T1071.001 | probable | rundll32 made repeated small HTTPS requests to an attacker domain, consistent with web-protocol C2 beaconing. | [E7][E10] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**Immediate cause [probable]:** The user opened an internet-sourced macro-enabled document (Invoice_Oct.docm), after which Word launched PowerShell. The macro executing is inferred from the Word-to-PowerShell process chain. [E1][E2][E16]

**[confirmed]** The whole Finance OU was excluded from the policy that blocks macros in files from the internet (added in 2024 for a legacy Excel add-in), so the macro document could run. [E17]

### Contributing factors

- **[confirmed]** EDR on Finance workstations is in detect-only mode, so the Office-to-PowerShell launch was not blocked. [E18][E19]
- **[confirmed]** The email gateway does not sandbox .docm attachments. Whether this document arrived by email is not confirmed. [E20]
- **[confirmed]** The lure looked like a genuine supplier invoice, which made it more likely to be opened. [E16]

## 7. Impact assessment

- **Systems involved:** `WS-FIN-022`
- **Accounts involved:** `m.okafor`
- **Data affected:** [unknown] Not determined. Outbound byte counts in the proxy rows are small, but the evidence does not state what data, if any, was accessed or taken from the workstation.
- **Operational impact:** [confirmed] WS-FIN-022 was isolated, then reimaged and returned to the user the next day. [E14]
- **Business impact:** [unknown] Financial or business cost is not stated in the evidence.

## 8. Response analysis

Milestones chosen by the model from the timeline; durations computed by code from timestamps.

| Milestone | Event | Time (UTC) | Time basis |
|---|---|---|---|
| attack start | EV001 | 2026-10-21 08:47:10 | exact |
| first detection | EV002 | 2026-10-21 08:47:32 | exact |
| response start | EV008 | 2026-10-21 11:15:00 | date inferred |
| containment | EV010 | 2026-10-21 11:22:00 | date inferred |

| Measure | From → to | Duration |
|---|---|---|
| time to detect | attack start → first detection | 22s |
| time to respond | first detection → response start | 2h 27m 28s (approximate: inferred time) |
| time to contain | first detection → containment | 2h 34m 28s (approximate: inferred time) |
| dwell time | attack start → containment | 2h 34m 50s (approximate: inferred time) |

## 9. Detection gaps

- **[confirmed]** The high-severity alert EDR-3301 waited in the queue from 08:47 until 11:15 because of a 40-alert backlog and two analysts on shift. Beaconing continued to 11:21. [E9][E10]
- **[confirmed]** EDR was detect-only on Finance workstations, so the alert had no automatic blocking effect. [E2][E18]
- **[confirmed]** Scoping is incomplete: domain controller logs were not reviewed. [E15]

## 10. Lessons learned

**Process**
- A high-severity alert waited in the queue for hours behind a backlog. The 2025 post-incident review already recorded that alerts waiting behind higher-severity ones delay response, so queue prioritisation and capacity remain a recurring weakness. [E9] [P1]
- Scoping must include authentication and domain controller review before closure, as the playbook requires. It was still open at the time of the ticket. [E15] [P2]

**Technology**
- Detect-only EDR on high-value Finance endpoints turned a blockable Office-to-PowerShell chain into a multi-hour compromise. [E18] [P3]
- Macro-enabled attachments should be sandboxed or quarantined before reaching users. [E20] [P4]

**Governance**
- Exclusions to the macro-blocking policy must be narrow (signed macros or trusted locations). Excluding a whole OU for a legacy add-in left a standing gap for 2024 onwards. [E17] [P5]

## 11. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Remove the Finance OU exclusion from the macro-blocking policy. If the legacy Excel add-in is still needed, allow only signed macros or specific trusted locations. | The OU-wide exclusion is the root cause; it allowed an internet-sourced macro document to run. [E17] | [P5] | Endpoint / Desktop Engineering | 1 week | Macro-based initial execution is blocked on Finance workstations. |
| critical | Switch EDR on Finance workstations to prevent (block) mode, and audit all other hosts for detect-only configurations beyond the 14-day rollout allowance. | Detect-only mode meant the PowerShell launch was alerted on but not stopped. [E18] | [P3] | Security Engineering | 1 week | The Office-to-PowerShell chain is blocked at execution instead of only alerted on. |
| high | Enable sandbox detonation or quarantine of .docm/.xlsm attachments at the email gateway. | The gateway does not sandbox .docm attachments, and this document looked like a legitimate invoice. [E20] | [P4] | Messaging / Email Security | 30 days | Malicious macro documents are stopped or flagged before reaching users. |
| high | Complete scoping: review domain controller and authentication logs for m.okafor and WS-FIN-022 and check for credential theft and lateral movement. Search all endpoints for the two hashes and the domain. | Domain controller logs were not reviewed, and EDR evidence alone shows no internal connections. The ticket does not record an enterprise-wide search for the indicators. [E15] | [P2][P6] | SOC / Incident Response | immediate (before closure) | Confirms or rules out spread and credential exposure before the incident is closed. |
| high | Raise the priority of alerts for Office applications spawning PowerShell or other process-chain alerts, and add queue-age escalation so high-severity alerts are not left for hours. Review SOC staffing against alert volume. | A high-severity alert sat for over two hours during a backlog while beaconing continued. The earlier agreed action on alert triage and prioritisation was not enough to prevent this. [E9] | [P1] | SOC Management | 30 days | Shorter time from alert to analyst action and containment. |

## 12. Open questions and remaining risks

- **Open:** How did Invoice_Oct.docm reach the user (email, web download or other)? No email delivery is recorded, so phishing is not confirmed.
- **Open:** Did the macro itself run? This is inferred from the Word-to-PowerShell process chain and is not directly shown.
- **Open:** What did the beaconing and the downloaded script do, and was any data accessed or taken from WS-FIN-022? The EDR export does not say.
- **Open:** Do domain controller and authentication logs show credential use or lateral movement from WS-FIN-022 or m.okafor?
- **Open:** Do other endpoints, especially in the Finance OU, show the same hashes or contact with cdn-update.badcdn.test? The ticket does not record an enterprise-wide search.
- **Open:** Were other Finance users sent the same document?
- **Risk:** Other Finance OU hosts remain exempt from macro blocking and in detect-only mode until the policies are changed.
- **Risk:** Possible credential exposure or lateral movement cannot be ruled out until domain controller logs are reviewed.
- **Risk:** Other recipients of the same lure, if any, are not accounted for.

## 13. Validation log

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
| E16 | ticket.txt | line 11 | the attachment looked like a real supplier invoice |
| E17 | ticket.txt | line 7 | the Finance OU is excluded from the policy that blocks macros in files from the internet |
| E18 | ticket.txt | line 8 | EDR policy on Finance workstations is detect-only |
| E19 | edr_events.json | meta | "policy_mode": "detect_only" |
| E20 | ticket.txt | line 9 | the email gateway does not sandbox .docm attachments |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | PIR-2025-014 §2 Lessons | waited behind higher alerts for 40 minutes |
| P2 | PB-03 §4 Scoping | Review domain controller and authentication logs for the user and host |
| P3 | STD-03 §2 EDR mode | Detect-only mode is allowed only during a rollout of at most 14 days. |
| P4 | STD-03 §3 Email attachments | are detonated in a sandbox before delivery or quarantined |
| P5 | STD-03 §1 Office macros | never a whole organisational unit |
| P6 | PB-03 §3 Blocking | search all endpoints for the same indicators |

_Knowledge-base sections given to the model: STD-03#1, STD-03#3, STD-03#2, PB-03#3, PB-03#4, PB-03#2, PIR-2025-014#1, PIR-2025-014#2_

**Evidence file hashes (SHA-256)**

- `edr_events.json`: `3c98dbcd93fedb673da4f059464562227c07d68b385c67ffcc45c45774419de2`
- `proxy_logs.csv`: `33f0750263e250b5533d3d380e051eb78a4109742926ebd5d3f28cbe3d5ec98c`
- `ticket.txt`: `bc94ce0f3adccc76467de6e56ce222889fd0676d375ba5e2f216de06b47a8e0b`
