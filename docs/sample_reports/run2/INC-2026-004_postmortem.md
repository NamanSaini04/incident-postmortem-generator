# Incident Postmortem: INC-2026-004: Ransomware on FS-02 after internet-exposed RDP on JMP-01 and use of the svc.backup account

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-004 |
| Category | ransomware |
| Severity | SEV1 |
| Classification confidence | 85% |
| Generated | 2026-11-23 19:46 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

An external IP reached RDP on JMP-01 and, after 312 failed logons for svc.backup, logged on successfully as svc.backup. The svc.backup account was then used to install a service remotely on FS-02, delete shadow copies and run locker.exe. Mass .lockd file renaming was detected on FS-02 and a ransom note was found. locker.exe was probably the encryptor. The probable root cause was an RDP exposure left open since 2025 combined with a weakly protected svc.backup account. How the password was obtained is not confirmed, and password guessing is the likely method. The high-severity shadow-copy alert went to a queue and paged no one. On-call was paged only for the later mass-rename alert. FS-02 and JMP-01 were isolated and FS-02 was restored from offline backup, with about 2 days of file changes lost. No ransom will be paid. Data theft is not confirmed. The ransom note claims 200 GB was stolen, but egress from FS-02 and JMP-01 showed no large transfers and other hosts are not yet reviewed.

**Severity rationale:** Ransomware activity on FS-02 is confirmed: shadow copies were deleted, files were renamed with a .lockd extension, and a ransom note was found. The recovery required a restore from offline backup, and about 2 days of file changes were lost (ir_notes.txt line 6). The ransom note's claim of 200 GB stolen is unverified, and the egress review so far is incomplete. Severity rests on the confirmed ransomware impact, not on confirmed data theft.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| **EV001** | **2026-11-10 22:41:07** | **action=allow; src_ip=203.0.113.66** | exact | [E1] |
| **EV002** | **2026-11-10 22:41:10** | **user=svc.backup; src_ip=203.0.113.66** | exact | [E2] |
| **EV003** | **2026-11-10 22:58:51** | **action=allow; src_ip=203.0.113.66 (seen in 2 sources)** | exact | [E3][E4] |
| EV004 | 2026-11-10 23:04:15 | user=svc.backup | exact | [E5] |
| **EV005** | **2026-11-10 23:31:40** | **process=PSEXESVC.exe; user=svc.backup** | exact | [E6] |
| **EV006** | **2026-11-10 23:33:02** | **process=vssadmin.exe; cmdline=vssadmin.exe delete shadows /all /quiet; user=svc.backup** | exact | [E7] |
| EV007 | 2026-11-10 23:33:05 | action=detected; severity=high | exact | [E8] |
| **EV008** | **2026-11-10 23:34:10** | **process=locker.exe; user=svc.backup** | exact | [E9] |
| **EV009** | **2026-11-10 23:36:40** | **action=detected; severity=critical** | exact | [E10] |
| EV010 | 2026-11-10 23:40:12 | action=allow; src_ip=FS-02 | exact | [E11] |
| **EV011** | **2026-11-10 23:52:00** | **23:52 On-call paged by the EDR mass-rename alert. The shadow-copy alert at 23:33 had not paged anyone.** | date inferred | [E12] |
| **EV012** | **2026-11-10 23:58:00** | **23:58 Isolated FS-02 and JMP-01 from the network.** | date inferred | [E13] |
| **EV013** | **2026-11-11 01:20:00** | **2026-11-11 01:20 Disabled svc.backup and blocked 203.0.113.66 at the firewall.** | timezone assumed | [E14] |
| EV014 | 2026-11-11 09:40:00 | 2026-11-11 09:40 Restore of FS-02 from the offline backup started. About 2 days of file changes were lost. | timezone assumed | [E15] |

## 3. What happened

- **[confirmed]** The firewall allowed external IP 203.0.113.66 to connect to JMP-01 on RDP port 3389 starting at EV001. [E1]
- **[confirmed]** From the same IP there were 312 failed RDP logons for svc.backup on JMP-01, followed by a successful remote interactive logon as svc.backup. [E2][E4]
- **[confirmed]** Special privileges were assigned to svc.backup on JMP-01 after the logon. [E5]
- **[confirmed]** A service (PSEXESVC.exe) was installed on FS-02 remotely from JMP-01 under svc.backup, which indicates lateral movement from JMP-01 to FS-02. [E6]
- **[confirmed]** On FS-02, svc.backup ran a command that deleted all shadow copies. EDR detected it as high severity. [E7][E8]
- **[confirmed]** locker.exe was executed on FS-02 under svc.backup. [E9]
- **[confirmed]** EDR detected a mass file rename with a .lockd extension on FS-02 at critical severity, and a ransom note, README_RESTORE.txt, was found on FS-02. [E10][E16]
- **[probable]** locker.exe was probably the ransomware payload that caused the .lockd renaming. It ran about 2.5 minutes before the rename alert (EV008, EV009), but no record states the link directly. [E9][E10]
- **[unknown]** The ransom note claims 200 GB was stolen. Firewall egress for FS-02 and JMP-01 shows no large outbound transfers, and egress for other hosts has not been reviewed. Data theft is therefore unconfirmed. [E16][E17]
- **[confirmed]** On-call was paged by the mass-rename alert (EV011) and FS-02 and JMP-01 were isolated (EV012). svc.backup was disabled and 203.0.113.66 blocked later, at EV013. The 01:20 time is timezone-assumed. [E12][E13][E14]
- **[confirmed]** FS-02 was restored from offline backup (EV014) and about 2 days of file changes were lost. The decision was not to pay the ransom. [E15][E18]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `203.0.113.66` | ip | [E1] |
| `e48f58a29d9e57c5e23d873afcd37bb3487369ff1ace9ee00dd2dd1401f820a2` | sha256 | [E9] |
| `decrypt-desk@lockd-support.test` | email | [E16] |
| `lockd-support.test` | domain | [E16] |

## 5. Root cause

**[probable]** RDP on JMP-01 was exposed to the internet through a temporary vendor exception that was never closed. The attacker authenticated as svc.backup, which had a 2022 password, no MFA on RDP and admin rights on FS-02. Password guessing is the probable method, given 312 failed logons before the first success, but the evidence does not state how the password was obtained. [E2][E4][E19][E20]

### Contributing factors

- **[confirmed]** A temporary vendor exception exposing RDP (3389) on JMP-01 to the internet was opened in 2025 and never closed. [E19]
- **[confirmed]** svc.backup had an old password, no MFA on RDP and admin rights on FS-02. One compromised service account therefore gave access to the file server. [E6][E20]
- **[probable]** The recovery point was probably old: restoring from offline backup lost about 2 days of file changes. [E15]

## 6. Detection gaps

- **[confirmed]** The high-severity shadow-copy deletion alert was routed to a queue, not to paging, so no one was paged until the mass-rename alert about 19 minutes later (EV007, EV011). [E12][E21]

## 7. Lessons learned

**Process**
- Alerts that indicate ransomware preparation, such as shadow-copy deletion, must page on-call. Queue routing cost response time before encryption was noticed. [E12][E21]
- Offline backups were what made recovery possible without paying. Their recovery point should be tightened to reduce data loss. [E15]

**Technology**
- Service accounts need strong rotated credentials, MFA or no interactive RDP, and least privilege. One weak account gave access to both the jump host and the file server. [E20]

**Governance**
- Temporary firewall exceptions need an owner and an expiry date. This one stayed open to the internet for about a year. [E19]

## 8. Corrective actions

| Priority | Action | Why | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|
| critical | Close internet exposure of RDP on JMP-01 and audit all other internet-facing rules for expired temporary exceptions. Require remote access through a VPN or gateway with MFA. | RDP was open to the internet and was the confirmed entry path. [E1][E19] | Network Security | Immediately | Removes the internet-reachable attack surface used in this incident. |
| critical | Reset and vault svc.backup credentials, and enforce MFA or deny interactive RDP for service accounts. Reduce svc.backup's admin rights to what backups require. Review other service accounts for old passwords. | The account was used for the intrusion and had a 2022 password, no MFA and admin rights on FS-02. [E20] | Identity and Access Management | Within 1 week | Limits impact if a service credential is guessed or stolen again. |
| high | Route shadow-copy deletion alerts, and other high-severity ransomware precursor alerts, to paging. | The shadow-copy alert at 23:33 paged no one and on-call was paged only for the later mass-rename alert. [E12][E21] | Security Operations | Within 1 week | Earlier response, before encryption starts. |
| high | Review firewall egress for all hosts, and review JMP-01 and FS-02 authentication and remote execution logs to scope lateral movement and any data theft. | The 200 GB theft claim is unverified, egress for other hosts is unreviewed, and it is unclear whether other servers were reached. [E17][E22] | Incident Response | Within 3 days | Establishes whether data was exfiltrated and whether other systems are compromised. |
| medium | Add an expiry and an owner to every temporary firewall exception, with periodic review. | A temporary exception stayed open for about a year. [E19] | IT Governance | Within 1 month | Prevents forgotten exceptions from persisting. |
| medium | Review offline backup frequency for file servers to shorten the recovery point. | Restoring from offline backup lost about 2 days of file changes. [E15] | Infrastructure | Within 1 month | Less data loss in a future recovery. |

## 9. Open questions and remaining risks

- **Open:** Was any data exfiltrated? The ransom note claims 200 GB, but egress for FS-02 and JMP-01 shows no large transfers and other hosts are unreviewed.
- **Open:** Did the attacker reach other servers from JMP-01?
- **Open:** How was the svc.backup password obtained? 312 failed logons suggest guessing, but this is not confirmed.
- **Open:** Is locker.exe the binary that renamed the files? The link is inferred from timing.
- **Open:** What was the outbound connection from FS-02 to 198.51.100.10 on port 443 (EV010)? Its purpose and whether it is malicious are undetermined.
- **Open:** Was any alert generated for the 312 failed RDP logons? No such alert appears in the evidence.
- **Open:** Why did svc.backup stay enabled until EV013, well after isolation (EV012), and was it used in that period? The 01:20 entry is timezone-assumed.
- **Risk:** Possible compromise of other servers reachable from JMP-01 is not ruled out.
- **Risk:** Possible data theft is not ruled out. Egress for other hosts is unreviewed.
- **Risk:** Other service accounts may have similarly old passwords and no MFA. This is not checked in the evidence.

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
| E16 | ir_notes.txt | line 10 | README_RESTORE.txt on FS-02 |
| E17 | ir_notes.txt | line 11 | shows no large outbound transfers |
| E18 | ir_notes.txt | line 12 | no ransom will be paid |
| E19 | ir_notes.txt | line 7 | opened to the internet in 2025 as a temporary vendor exception and never closed |
| E20 | ir_notes.txt | line 8 | password last changed in 2022, no MFA on RDP, and admin rights on FS-02 |
| E21 | ir_notes.txt | line 9 | routed to a queue, not to paging |
| E22 | ir_notes.txt | line 13 | unclear whether the attacker reached other servers from JMP-01 |

**Evidence file hashes (SHA-256)**

- `edr_alerts.csv`: `d1eb9ee53fb9bbd1fd93c051de22f0b773da0e294eb8f5d98a9a0e26f09b30bd`
- `firewall.csv`: `ecf764454e27397bf66a732dcefba5f95349476f8d0c0bf45377385817c6372a`
- `ir_notes.txt`: `7df2cec315cc26243c2e2262b239fe551e07af9c2d603dea3811cea998560f96`
- `windows_security.json`: `bb1692a9700508c594abb3c26686592d7a1d3a2923d2c3583aaf8ed69d0db85c`
