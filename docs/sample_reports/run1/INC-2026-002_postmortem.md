# Incident Postmortem: INC-2026-002: INC-2026-002: Macro-enabled invoice document led to PowerShell payload and C2 beaconing on WS-FIN-022

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-002 |
| Category | phishing |
| Severity | SEV2 |
| Classification confidence | 70% |
| Generated | 2026-11-23 19:08 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

A macro-enabled document (Invoice_Oct.docm) was opened on WS-FIN-022. Word then launched hidden PowerShell, which fetched a script and wrote a DLL that was run via rundll32. The host kept contacting the same external server until it was isolated. EDR detected the PowerShell launch immediately but only alerted, because Finance workstations run detect-only. The alert sat in the queue for over two hours. Finance is also exempt from the policy that blocks internet-origin macros, and the email gateway does not sandbox .docm files. The host was isolated, the indicators were blocked, and the host was reimaged. Scope checks are incomplete: domain controller logs have not been reviewed, and whether data or credentials were taken is unknown.

**Severity rationale:** Malicious code ran on a Finance workstation and made repeated outbound connections to an attacker-controlled host for about 2.5 hours before isolation. Preventive controls did not stop it. Lateral movement was not seen in EDR, but domain controller logs were not reviewed, so scope is not fully established. No evidence of data loss or wider spread was found, so SEV1 is not supported.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| **EV001** | **2026-10-21 08:47:10** | **event=file_open; process=WINWORD.EXE; user=m.okafor** | exact | [E1] |
| **EV002** | **2026-10-21 08:47:32** | **rule=Office application spawned PowerShell; event=process_create; action=detected; process=powershell.exe; cmd** | exact | [E2] |
| **EV003** | **2026-10-21 08:47:35** | **event=network_connect; process=powershell.exe; dest=http://cdn-update.badcdn.test/s2.ps1; user=m.okafor (seen ** | exact | [E3][E4] |
| **EV004** | **2026-10-21 08:48:02** | **event=file_write; process=powershell.exe; user=m.okafor** | exact | [E5] |
| **EV005** | **2026-10-21 08:48:10** | **event=process_create; process=rundll32.exe; cmdline=rundll32.exe C:\Users\m.okafor\AppData\Roaming\upd.dll,Sta** | exact | [E6] |
| **EV006** | **2026-10-21 08:49:00** | **process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022** | exact | [E7] |
| EV007 | 2026-10-21 08:50:00 | process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022 | exact | [E8] |
| **EV008** | **2026-10-21 11:15:00** | **11:15 EDR-3301 picked up by soc.analyst2. Alert had been in the queue since 08:47; two analysts on shift, back** | date inferred | [E9] |
| **EV009** | **2026-10-21 11:21:00** | **process=rundll32.exe; url=https://cdn-update.badcdn.test/api/c; src_host=WS-FIN-022** | exact | [E10] |
| EV010 | 2026-10-21 11:22:00 | 11:22 Isolated WS-FIN-022 from the network via EDR console. | date inferred | [E11] |
| **EV011** | **2026-10-21 11:22:04** | **event=host_isolated; process=edr-console; user=soc.analyst2** | exact | [E12] |
| **EV012** | **2026-10-21 11:40:00** | **11:40 Blocked both file hashes and cdn-update.badcdn.test at EDR and proxy.** | date inferred | [E13] |

## 3. What happened

- **[confirmed]** User m.okafor opened Invoice_Oct.docm in Word from the Downloads folder; the file was flagged as coming from the internet. The user said it looked like a real supplier invoice. [E1][E14]
- **[confirmed]** Word spawned a hidden, encoded PowerShell process. EDR raised a high-severity alert (EDR-3301) but only detected it and took no blocking action. [E2]
- **[probable]** The document's embedded macro was probably what launched PowerShell. This is inferred from the .docm file type and the Word-to-PowerShell parent/child relationship; no record states the macro executed. [E1][E2]
- **[confirmed]** PowerShell downloaded a script (s2.ps1) from cdn-update.badcdn.test. The proxy recorded a successful response. [E3][E4]
- **[confirmed]** PowerShell wrote upd.dll to the user's Roaming profile, then started it through rundll32. [E5][E6]
- **[probable]** rundll32.exe repeatedly made small HTTPS requests to cdn-update.badcdn.test/api/c, including one just before isolation. This is probably command-and-control beaconing. The proxy log shows only three such requests, so continuity between them is not established. [E7][E8][E10]
- **[confirmed]** The EDR alert waited in the queue from 08:47 until soc.analyst2 picked it up at 11:15. The analyst isolated the host at 11:22. [E9][E12]
- **[confirmed]** After isolation, both file hashes and the domain were blocked at EDR and proxy. The host was reimaged the next day and returned to the user. [E13][E15]
- **[confirmed]** EDR shows no connections from WS-FIN-022 to other internal hosts in the last 24 hours. Domain controller logs have not been reviewed, so lateral movement is not ruled out. [E16]

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

**[probable]** A malicious macro-enabled document ran on a Finance workstation because Finance is exempt from the policy that blocks macros in internet-origin files. Detect-only EDR on Finance hosts then let the resulting PowerShell launch proceed. That the exemption was the direct enabler is an inference from the findings. [E17][E18]

### Contributing factors

- **[confirmed]** The macro-blocking exclusion for the Finance OU was added in 2024 for a legacy Excel add-in and was still in place. [E17]
- **[confirmed]** EDR on Finance workstations is detect-only, so a high-severity alert did not stop the process. [E18][E19]
- **[probable]** The email gateway does not sandbox .docm attachments. Delivery of this file by email is not directly confirmed, so this factor is probable rather than confirmed. [E1][E20]
- **[confirmed]** The lure was convincing: the user said it looked like a real supplier invoice. [E14]
- **[confirmed]** SOC capacity: two analysts on shift and a backlog of 40 alerts delayed triage of the high-severity alert. [E9]

## 6. Detection gaps

- **[confirmed]** A high-severity Office-spawned-PowerShell alert was not triaged for over two hours. This allowed continued external communication from the host until isolation. [E9][E10]
- **[confirmed]** No automated containment or blocking occurred for the high-severity alert. The EDR action was detection only. [E18]
- **[confirmed]** Attachment sandboxing did not cover .docm files at the email gateway. [E20]
- **[possible]** Repeated beaconing to a newly seen external host was not flagged by the proxy during the period. The evidence shows no proxy alert, but its absence is not proof that no rule exists. [E8]

## 7. Lessons learned

**Process**
- Queue-based triage without priority handling let a high-severity alert wait while the attacker's tooling kept communicating. [E9]

**Technology**
- Detect-only mode on Finance endpoints means detections do not translate into prevention. High-confidence behaviours such as Office spawning PowerShell should be blocked. [E18]
- Email-layer controls need to cover macro-enabled Office attachments, because the user could not tell the lure from a real invoice. [E14][E20]

**Governance**
- A long-standing policy exception for a legacy add-in removed a key macro control from a high-value department. Exceptions need an owner and periodic review. [E17]

## 8. Corrective actions

| Priority | Action | Why | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|
| critical | Review the Finance OU exclusion from the internet-macro blocking policy. Remove it, or narrow it to the specific signed add-in or trusted locations required, and replace the legacy Excel add-in dependency if feasible. | The exclusion let an internet-origin macro document run on a Finance workstation. [E17] | Endpoint / IT Security Engineering | Within 2 weeks | Internet-origin macro documents are blocked on Finance endpoints. |
| critical | Switch EDR on Finance workstations from detect-only to prevent mode, at least for the rule 'Office application spawned PowerShell'. Test against the legacy add-in first. | The PowerShell launch was detected but not blocked. [E18] | Endpoint Security | Within 2 weeks | The attack chain is stopped at the first malicious process rather than only logged. |
| high | Enable sandboxing or detonation, or quarantine, for .docm and other macro-enabled attachments at the email gateway. | The gateway does not sandbox .docm attachments. [E20] | Messaging Security | Within 30 days | Malicious macro documents are caught before reaching users. |
| high | Define a fast-track path for high-severity EDR alerts, such as paging the on-call analyst or auto-isolating the host for specific rules. Review SOC staffing against alert volume. | A high-severity alert waited in the queue with two analysts on shift and a backlog of 40 alerts. [E9] | SOC | Within 30 days | Shorter time from alert to containment. |
| high | Complete the scope check: review domain controller and authentication logs for m.okafor and WS-FIN-022. Determine whether credentials need resetting. | Domain controller logs have not been reviewed, so lateral movement and credential misuse are not ruled out. [E16] | SOC / Identity | Within 3 days | Confirms or rules out spread beyond the single host. |
| medium | Search mail and proxy logs for other recipients or hosts that handled the same document hashes or contacted the blocked domain and IP. | The lure was convincing and may have reached other users. The proxy and EDR evidence covers only WS-FIN-022. [E13][E14] | SOC / Threat Hunting | Within 1 week | Identifies any other affected users or hosts. |

## 9. Open questions and remaining risks

- **Open:** How was Invoice_Oct.docm delivered to the user (email or another route)? The records do not state this.
- **Open:** Did a macro in the document launch PowerShell? No record confirms macro execution.
- **Open:** What did s2.ps1 and upd.dll do beyond the logged actions? The command line was redacted and no content analysis is in the evidence.
- **Open:** Was any data or were any credentials accessed or sent out? The evidence does not show this; request sizes are small but not conclusive.
- **Open:** Did the beaconing run continuously between 08:50 and 11:21? The proxy log shows only three rundll32 requests.
- **Open:** Do domain controller logs show any activity from WS-FIN-022 or m.okafor's account? They have not been reviewed.
- **Open:** Did other users receive or open the same document?
- **Risk:** Lateral movement or credential compromise is not ruled out until domain controller logs are reviewed.
- **Risk:** Other Finance workstations remain exposed to the same attack path while the macro exclusion and detect-only EDR policy are in place.
- **Risk:** Other recipients of the lure may exist and have not been identified.

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
| E14 | ticket.txt | line 11 | the attachment looked like a real supplier invoice |
| E15 | ticket.txt | line 6 | WS-FIN-022 reimaged and returned to m.okafor |
| E16 | ticket.txt | line 10 | EDR shows no connections from WS-FIN-022 to other internal hosts in the last 24h |
| E17 | ticket.txt | line 7 | the Finance OU is excluded from the policy that blocks macros in files from the internet |
| E18 | ticket.txt | line 8 | EDR policy on Finance workstations is detect-only, so the PowerShell launch was not blocked. |
| E19 | edr_events.json | meta | detect_only |
| E20 | ticket.txt | line 9 | the email gateway does not sandbox .docm attachments |

**Evidence file hashes (SHA-256)**

- `edr_events.json`: `3c98dbcd93fedb673da4f059464562227c07d68b385c67ffcc45c45774419de2`
- `proxy_logs.csv`: `33f0750263e250b5533d3d380e051eb78a4109742926ebd5d3f28cbe3d5ec98c`
- `ticket.txt`: `bc94ce0f3adccc76467de6e56ce222889fd0676d375ba5e2f216de06b47a8e0b`
