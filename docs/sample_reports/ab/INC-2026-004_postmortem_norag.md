# Incident Postmortem: INC-2026-004: Ransomware on file server FS-02 via internet-exposed RDP on JMP-01 and a weak service account

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-004 |
| Category | ransomware |
| Severity | SEV1 |
| Classification confidence | 90% |
| Generated | 2026-11-23 20:14 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

Ransomware (locker.exe) ran on file server FS-02 after shadow copies were deleted, and files were renamed with a .lockd extension. The attacker probably got in through RDP on JMP-01, which was exposed to the internet. Hundreds of failed logons for svc.backup were followed by a successful one. The exposure came from a temporary vendor firewall exception that was never closed. The svc.backup account had a 2022 password, no MFA on RDP, and admin rights on FS-02. The high-severity shadow-copy deletion alert went to a queue and did not page anyone. On-call was paged only by the later mass-rename alert. The ransom note claims 200 GB was stolen. This is not confirmed: egress for FS-02 and JMP-01 shows no large transfers, and other hosts are not yet reviewed. FS-02 and JMP-01 were isolated, svc.backup was disabled, the attacker IP was blocked, and FS-02 was restored from offline backup. About 2 days of file changes were lost.

**Severity rationale:** Ransomware encryption on FS-02 is confirmed (edr_alerts.csv row 2, windows_security.json events[5]). Restoring from backup lost about 2 days of file changes (ir_notes.txt line 6). The ransom note claims 200 GB was stolen (ir_notes.txt line 10), but this is unverified: egress for FS-02 and JMP-01 shows no large transfers and other hosts are not yet reviewed (ir_notes.txt line 11). Severity rests on the confirmed ransomware impact, not on the exfiltration claim.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| EV001 | 2026-11-10 22:41:07 | action=allow; src_ip=203.0.113.66 | exact | [E1] |
| **EV002** | **2026-11-10 22:41:10** | **event_id=4625; detail=312 failed RDP logons for svc.backup between 22:41 and 22:58; user=svc.backup; host=JMP-** | exact | [E2] |
| **EV003** | **2026-11-10 22:58:51** | **action=allow; src_ip=203.0.113.66 (seen in 2 sources)** | exact | [E3][E4] |
| EV004 | 2026-11-10 23:04:15 | event_id=4672; detail=special privileges assigned; user=svc.backup; host=JMP-01 | exact | [E5] |
| **EV005** | **2026-11-10 23:31:40** | **event_id=7045; detail=service installed remotely from JMP-01; process=PSEXESVC.exe; user=svc.backup; host=FS-0** | exact | [E6] |
| **EV006** | **2026-11-10 23:33:02** | **event_id=4688; process=vssadmin.exe; cmdline=vssadmin.exe delete shadows /all /quiet; user=svc.backup; host=FS** | exact | [E7] |
| EV007 | 2026-11-10 23:33:05 | alert=Shadow copy deletion; action=detected; host=FS-02; severity=high | exact | [E8] |
| **EV008** | **2026-11-10 23:34:10** | **event_id=4688; process=locker.exe; user=svc.backup; host=FS-02** | exact | [E9] |
| **EV009** | **2026-11-10 23:36:40** | **alert=Mass file rename (.lockd extension); action=detected; host=FS-02; severity=critical** | exact | [E10] |
| EV010 | 2026-11-10 23:40:12 | action=allow; src_ip=FS-02 | exact | [E11] |
| **EV011** | **2026-11-10 23:52:00** | **23:52 On-call paged by the EDR mass-rename alert. The shadow-copy alert at 23:33 had not paged anyone.** | date inferred | [E12] |
| **EV012** | **2026-11-10 23:58:00** | **23:58 Isolated FS-02 and JMP-01 from the network.** | date inferred | [E13] |
| **EV013** | **2026-11-11 01:20:00** | **2026-11-11 01:20 Disabled svc.backup and blocked 203.0.113.66 at the firewall.** | timezone assumed | [E14] |
| EV014 | 2026-11-11 09:40:00 | 2026-11-11 09:40 Restore of FS-02 from the offline backup started. About 2 days of file changes were lost. | timezone assumed | [E15] |

## 3. What happened

- **[confirmed]** From the external IP 203.0.113.66, 312 failed RDP logons against svc.backup on JMP-01 were followed by a successful remote interactive logon for that account. [E2][E4]
- **[confirmed]** The svc.backup session on JMP-01 was assigned special privileges. The account then installed a PsExec service remotely on FS-02 from JMP-01 (lateral movement). [E5][E6]
- **[confirmed]** On FS-02, svc.backup ran a command that deletes all shadow copies. EDR detected it as a high-severity alert. [E7][E8]
- **[confirmed]** locker.exe ran on FS-02 as svc.backup. EDR then raised a critical mass-rename alert for the .lockd extension. [E9][E10]
- **[possible]** A ransom note on FS-02 claims 200 GB was stolen. Theft is not confirmed: egress for FS-02 and JMP-01 shows no large transfers, and other hosts are not yet reviewed. [E16][E17]
- **[confirmed]** The responders isolated FS-02 and JMP-01. Later they disabled svc.backup and blocked the attacker IP at the firewall. [E13][E14]
- **[confirmed]** FS-02 was restored from offline backup, and about 2 days of file changes were lost. [E15]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `203.0.113.66` | ip | [E1] |
| `e48f58a29d9e57c5e23d873afcd37bb3487369ff1ace9ee00dd2dd1401f820a2` | sha256 | [E9] |
| `decrypt-desk@lockd-support.test` | email | [E16] |
| `lockd-support.test` | domain | [E16] |

## 5. Root cause

**[probable]** Probably, the attacker guessed the svc.backup password over RDP on JMP-01, which was exposed to the internet through a vendor exception that was never closed. The account's old password, lack of MFA and admin rights on FS-02 let it reach and encrypt FS-02. The guessing method is inferred from the failed-then-successful logon pattern and is not stated directly. [E2][E4][E18][E19]

### Contributing factors

- **[confirmed]** RDP (3389) on JMP-01 was opened to the internet as a temporary vendor exception in 2025 and never closed. [E18]
- **[confirmed]** svc.backup had a password last changed in 2022, no MFA on RDP, and admin rights on FS-02. A single compromised credential therefore gave access to the file server. [E19]

## 6. Detection gaps

- **[confirmed]** The high-severity shadow-copy deletion alert was routed to a queue and not to paging. On-call was paged only by the later mass-rename alert, after the locker had started (EV007 to EV011). [E12][E20]
- **[unknown]** The evidence records no alert or response to the 312 failed external RDP logons or to the successful logon from the external IP. Whether any detection existed is not determinable from the evidence.

## 7. Lessons learned

**Process**
- Alerts for ransomware precursors, such as shadow-copy deletion, must page on-call. A high-severity alert in a queue cost response time. [E12][E20]

**Technology**
- Service accounts need strong rotated credentials, MFA or no interactive RDP, and least privilege. svc.backup had none of these. [E19]
- Offline backups made recovery possible despite the shadow-copy deletion. [E7][E15]

**Governance**
- Temporary firewall exceptions need an owner and an expiry date. This one stayed open for a long time and became the entry point. [E18]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Remove direct internet exposure of RDP on JMP-01 and audit all other internet-facing rules for stale exceptions. Provide remote access only through a VPN or gateway with MFA. | RDP on JMP-01 was open to the internet and was the attacker's entry point. [E1][E18] | - | Network Security | Immediately, with the audit within 1 week | Removes the internet-facing path that was used to attack JMP-01. |
| critical | Rotate the svc.backup credentials (the account is already disabled). Redesign backup service accounts with long unique secrets, no interactive RDP, MFA where interactive logon is needed, and least privilege instead of admin on FS-02. Review other service accounts for the same weaknesses. | The compromised account had a 2022 password, no MFA on RDP and admin rights, which allowed lateral movement to FS-02. [E6][E19] | - | Identity and Access Management | 1 week | A stolen service-account credential no longer gives remote admin access to servers. |
| high | Route high-severity ransomware-precursor alerts (shadow-copy deletion) to paging. Add alerting on bursts of failed RDP logons and on successful external RDP logons. | The shadow-copy alert did not page anyone, and the evidence records no alert for the 312 failed logons. [E2][E20] | - | Security Operations | 2 weeks | Earlier human response, before encryption starts. |
| high | Finish the scoping work. Review JMP-01 activity and logons for lateral movement to servers other than FS-02, and review firewall egress for all other hosts to test the 200 GB theft claim. | The scope of attacker access and any data theft are unresolved. [E17][E21] | - | Incident Response | 1 week | Confirms or rules out other compromised hosts and data exfiltration, and informs any notification decision. |
| medium | Keep and regularly test offline backups. Consider a tighter backup cadence for file servers. | The restore worked, but about 2 days of file changes were lost. [E15] | - | IT Infrastructure | 1 month | Less data loss when a restore is needed. |

## 9. Open questions and remaining risks

- **Open:** Did the attacker reach servers other than FS-02 from JMP-01? (ir_notes.txt line 13)
- **Open:** Was any data actually exfiltrated? Egress for FS-02 and JMP-01 shows no large transfers, but other hosts are not reviewed. (ir_notes.txt line 10, ir_notes.txt line 11)
- **Open:** How was the svc.backup password obtained? The evidence shows 312 failed logons followed by success but does not state the method.
- **Open:** Why did the 312 failed RDP logons from an external IP raise no alert or response? The evidence is silent.
- **Open:** What was the purpose of the allowed 443 connection from FS-02 to 198.51.100.10? It is not shown to be malicious. (firewall.csv row 3)
- **Open:** Was there any attacker activity before the first logged connection from 203.0.113.66? The evidence does not show earlier activity.
- **Risk:** Other hosts may be compromised, because lateral movement from JMP-01 has not been ruled out (ir_notes.txt line 13).
- **Risk:** Data theft is neither confirmed nor ruled out until egress for all hosts is reviewed (ir_notes.txt line 11).
- **Risk:** Any other service accounts or firewall exceptions with the same weaknesses remain exposed until audited (ir_notes.txt line 7, ir_notes.txt line 8).

## 10. Validation log

- attempt 1: 0 validation problem(s)

## Evidence index

| Ref | File | Location | Quote |
|---|---|---|---|
| E1 | firewall.csv | row 1 | 2026-11-10T22:41:07Z |
| E2 | windows_security.json | events[0] | 2026-11-10T22:41:10Z |
| E3 | firewall.csv | row 2 | 2026-11-10T22:58:51Z |
| E4 | windows_security.json | events[1] | 2026-11-10T22:58:53Z |
| E5 | windows_security.json | events[2] | 2026-11-10T23:04:15Z |
| E6 | windows_security.json | events[3] | 2026-11-10T23:31:40Z |
| E7 | windows_security.json | events[4] | 2026-11-10T23:33:02Z |
| E8 | edr_alerts.csv | row 1 | 2026-11-10T23:33:05Z |
| E9 | windows_security.json | events[5] | 2026-11-10T23:34:10Z |
| E10 | edr_alerts.csv | row 2 | 2026-11-10T23:36:40Z |
| E11 | firewall.csv | row 3 | 2026-11-10T23:40:12Z |
| E12 | ir_notes.txt | line 3 | 23:52 |
| E13 | ir_notes.txt | line 4 | 23:58 |
| E14 | ir_notes.txt | line 5 | 2026-11-11 01:20 |
| E15 | ir_notes.txt | line 6 | 2026-11-11 09:40 |
| E16 | ir_notes.txt | line 10 | claims 200 GB was stolen |
| E17 | ir_notes.txt | line 11 | shows no large outbound transfers |
| E18 | ir_notes.txt | line 7 | was opened to the internet in 2025 as a temporary vendor exception and never closed |
| E19 | ir_notes.txt | line 8 | password last changed in 2022, no MFA on RDP, and admin rights on FS-02 |
| E20 | ir_notes.txt | line 9 | routed to a queue, not to paging |
| E21 | ir_notes.txt | line 13 | unclear whether the attacker reached other servers from JMP-01 |

**Evidence file hashes (SHA-256)**

- `edr_alerts.csv`: `d1eb9ee53fb9bbd1fd93c051de22f0b773da0e294eb8f5d98a9a0e26f09b30bd`
- `firewall.csv`: `ecf764454e27397bf66a732dcefba5f95349476f8d0c0bf45377385817c6372a`
- `ir_notes.txt`: `7df2cec315cc26243c2e2262b239fe551e07af9c2d603dea3811cea998560f96`
- `windows_security.json`: `bb1692a9700508c594abb3c26686592d7a1d3a2923d2c3583aaf8ed69d0db85c`
