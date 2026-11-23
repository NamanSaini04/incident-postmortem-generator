# Incident Postmortem: INC-2026-002: Malicious macro document leads to PowerShell, DLL execution and C2 contact on Finance workstation WS-FIN-022

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

A macro-enabled document was opened in Word on WS-FIN-022. Word then spawned a hidden, encoded PowerShell process, and EDR only detected it. PowerShell wrote a DLL that was run with rundll32. rundll32 then connected repeatedly to cdn-update.badcdn.test until the host was isolated. The root cause was probably a macro-enabled document from the internet being opened on a Finance workstation. The Finance OU is excluded from the macro-blocking policy. How the document arrived is not confirmed. EDR on Finance workstations is detect-only, so the PowerShell launch was not blocked. The high-severity alert waited in the queue until it was picked up (EV008) because of analyst backlog, and the host was isolated minutes later. EDR shows no connections to other internal hosts, but domain controller logs are not yet reviewed. Data exposure and lateral movement are therefore not ruled out.

**Severity rationale:** Host compromise with attacker activity is confirmed on WS-FIN-022. The host was isolated, the indicators blocked and the machine reimaged. No large-scale sensitive data exposure is confirmed, but data access and exfiltration are not ruled out because domain controller logs have not been reviewed.

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
| **EV009** | **2026-10-21 11:21:00** | **process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022** | exact | [E10] |
| EV010 | 2026-10-21 11:22:00 | 11:22 Isolated WS-FIN-022 from the network via EDR console. | date inferred | [E11] |
| **EV011** | **2026-10-21 11:22:04** | **event=host_isolated; process=edr-console; user=soc.analyst2** | exact | [E12] |
| **EV012** | **2026-10-21 11:40:00** | **11:40 Blocked both file hashes and cdn-update.badcdn.test at EDR and proxy.** | date inferred | [E13] |

## 3. What happened

- **[confirmed]** User m.okafor opened Invoice_Oct.docm in Word on WS-FIN-022 (EV001). [E1]
- **[confirmed]** Word spawned a hidden, encoded PowerShell process (EV002). EDR raised high-severity alert EDR-3301 but only detected it and did not block it. [E2]
- **[probable]** PowerShell contacted cdn-update.badcdn.test and probably downloaded the script s2.ps1 (EV003). The proxy shows a 200 response with about 18 KB inbound. The script content is not in the evidence. [E4]
- **[confirmed]** PowerShell wrote upd.dll to the user's AppData\Roaming folder (EV004), and rundll32.exe was then launched with that DLL as its target (EV005). [E5][E6]
- **[confirmed]** rundll32.exe connected to https://cdn-update.badcdn.test/api/c at 08:49 and 08:50 (EV006, EV007), and again shortly before isolation (EV009). Each request was small, with about 390 bytes out and 96 bytes in. What the traffic carried is not determined. [E7][E8][E10]
- **[confirmed]** The alert sat in the queue from the time it fired until soc.analyst2 picked it up (EV008). The ticket cites analyst backlog. [E9]
- **[confirmed]** The host was isolated via the EDR console (EV011). The file hashes and the domain were then blocked at EDR and proxy (EV012). The workstation was reimaged the next day. [E12][E13][E14]
- **[confirmed]** EDR shows no connections from WS-FIN-022 to other internal hosts in the 24 hours before the scope check. Domain controller logs have not been reviewed. [E15]

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

**[probable]** A macro-enabled document from the internet was opened on a Finance workstation and probably ran a macro that launched PowerShell. Macro blocking did not apply because the Finance OU is excluded from the policy, and EDR was detect-only, so nothing stopped the chain. How the document reached the user is not confirmed. [E1][E2][E16]

### Contributing factors

- **[confirmed]** The Finance OU is excluded from the macro-blocking policy for internet-sourced files. The exclusion was added in 2024 for a legacy Excel add-in. [E16]
- **[confirmed]** EDR on Finance workstations is in detect-only mode, so the PowerShell launch was not blocked. [E17][E18]
- **[confirmed]** The email gateway does not sandbox .docm attachments. Whether this document arrived by email is not confirmed. [E19]
- **[probable]** The document looked like a genuine supplier invoice to the user, which probably made opening it more likely. [E20]

## 6. Detection gaps

- **[confirmed]** A high-severity alert for Office spawning PowerShell was not triaged until it had waited in the queue (EV008). The attacker's host stayed connected to the C2 domain throughout, including shortly before isolation (EV009). [E9][E10]
- **[confirmed]** The EDR alert was detection-only with no automated response such as host isolation, so the chain continued after the alert fired. [E2][E17]

## 7. Lessons learned

**Process**
- Alert triage capacity did not match volume. A high-severity alert waited in a queue of 40 with two analysts on shift. [E9]
- Scoping was incomplete at the time of the ticket. Domain controller logs were not reviewed, so lateral movement and credential exposure cannot be ruled out from EDR alone. [E15]

**Technology**
- A policy exclusion made for a legacy tool removed macro protection for a whole high-risk department and stayed in place for about two years. [E16]
- Detect-only EDR on the most targeted workstations gave visibility but no protection. The high-confidence rule 'Office application spawned PowerShell' fired but did not stop execution. [E2][E17]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Remove the Finance OU exclusion from the macro-blocking policy. Replace the legacy Excel add-in dependency with a narrowly scoped, signed or trusted-location approach. | The exclusion allowed a macro-enabled internet document to run on a Finance workstation. [E16] | - | Endpoint / IT Administration | within 14 days | Macro-enabled files from the internet no longer run on Finance workstations. |
| critical | Move EDR on Finance workstations from detect-only to prevent/block mode. At minimum, block Office applications spawning script interpreters. | The PowerShell launch was only detected, so the attacker's chain continued to DLL execution and C2. [E6][E17] | - | Security Engineering | within 14 days | The attack chain is stopped at the first malicious process launch. |
| high | Sandbox or block .docm attachments at the email gateway. Confirm the delivery path of Invoice_Oct.docm. | The gateway does not sandbox .docm attachments, and the user described the file as an attachment. [E19][E20] | - | Messaging / Email Security | within 30 days | Fewer macro-enabled malicious documents reach users. |
| high | Add a fast-path for high-severity EDR alerts. Options are automatic paging, a triage time target, or automatic host isolation for the Office-spawns-PowerShell rule. Review queue staffing. | The alert waited in the queue until it was picked up (EV008) because of backlog, and C2 contact continued until isolation. [E9][E10] | - | SOC | within 30 days | Shorter time from detection to containment. |
| high | Review domain controller logs and the account activity of m.okafor for the incident window. Search proxy and DNS logs for other hosts contacting cdn-update.badcdn.test or 203.0.113.80. | The scope check is incomplete. The attacker code ran in the user's session, and the C2 connection stayed open until isolation. [E10][E15] | - | SOC / Incident Response | within 3 days | Confirms or rules out lateral movement, credential exposure and other affected hosts. |

## 9. Open questions and remaining risks

- **Open:** How did Invoice_Oct.docm reach the user (email, web download or other)? The evidence records only a file in Downloads with an internet mark. No email delivery is recorded, so phishing is not confirmed.
- **Open:** Did a macro in the document launch PowerShell? This is inferred from the sequence of events, and no macro content is recorded.
- **Open:** What did the traffic to /api/c carry, and was any data exfiltrated? Payload content is not in the evidence.
- **Open:** Were domain controllers or other systems accessed? Domain controller logs have not been reviewed.
- **Open:** Were any credentials, or any Finance data accessible to m.okafor, exposed? This is not determinable from the evidence.
- **Open:** Did other users receive or open the same document?
- **Risk:** Lateral movement and credential theft are not ruled out until domain controller logs are reviewed.
- **Risk:** Other Finance workstations still have detect-only EDR and the macro-blocking exclusion until the corrective actions are applied.
- **Risk:** Variants of the malicious document that use different hashes or domains would not be covered by the current blocks.

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

**Evidence file hashes (SHA-256)**

- `edr_events.json`: `3c98dbcd93fedb673da4f059464562227c07d68b385c67ffcc45c45774419de2`
- `proxy_logs.csv`: `33f0750263e250b5533d3d380e051eb78a4109742926ebd5d3f28cbe3d5ec98c`
- `ticket.txt`: `bc94ce0f3adccc76467de6e56ce222889fd0676d375ba5e2f216de06b47a8e0b`
