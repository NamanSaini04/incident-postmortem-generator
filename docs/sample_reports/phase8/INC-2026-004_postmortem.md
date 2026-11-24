# Incident Postmortem: INC-2026-004: Ransomware on FS-02 via internet-exposed RDP on JMP-01 and the svc.backup service account

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-004 |
| Category | ransomware |
| Severity | SEV1 |
| Classification confidence | 90% |
| Generated | 2026-11-24 09:04 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

An external IP reached RDP on JMP-01, made 312 failed logons for svc.backup, then logged on successfully. Using svc.backup, the attacker installed a remote service on FS-02, deleted shadow copies and ran locker.exe, which mass-renamed files. A ransom note was left. The root cause was RDP on JMP-01 left open to the internet since 2025 as a temporary vendor exception, and never closed. svc.backup had a 2022 password, no MFA on RDP and admin rights on FS-02, which let one stolen or guessed credential reach the file server. The high-severity shadow-copy alert went to a queue and paged no one. On-call was paged only for the later mass-rename alert. FS-02 and JMP-01 were isolated, svc.backup was disabled and the attacker IP blocked. FS-02 was restored from offline backup with about 2 days of changes lost. The attacker's claim of 200 GB stolen is not confirmed. Egress for FS-02 and JMP-01 showed no large transfers, but other hosts are not yet reviewed, so possible data theft and lateral movement remain open.

**Severity rationale:** Ransomware activity is confirmed on FS-02: shadow copies were deleted, files were mass-renamed with a .lockd extension, a ransom note was left, and the server had to be restored from offline backup with about 2 days of file changes lost. The 200 GB data-theft claim is not confirmed; egress for FS-02 and JMP-01 showed no large transfers, and other hosts have not been reviewed.

## 2. Timeline (UTC)

Built by code from the evidence. **Bold** = key event.

| ID | Time | Event | Time basis | Sources |
|---|---|---|---|---|
| **EV001** | **2026-11-10 22:41:07** | **action=allow; src_ip=203.0.113.66** | exact | [E1] |
| **EV002** | **2026-11-10 22:41:10** | **event_id=4625; detail=312 failed RDP logons for svc.backup between 22:41 and 22:58; user=svc.backup; host=JMP-** | exact | [E2] |
| **EV003** | **2026-11-10 22:58:51** | **action=allow; src_ip=203.0.113.66 (seen in 2 sources)** | exact | [E3][E4] |
| EV004 | 2026-11-10 23:04:15 | event_id=4672; detail=special privileges assigned; user=svc.backup; host=JMP-01 | exact | [E5] |
| **EV005** | **2026-11-10 23:31:40** | **event_id=7045; detail=service installed remotely from JMP-01; process=PSEXESVC.exe; user=svc.backup; host=FS-0** | exact | [E6] |
| **EV006** | **2026-11-10 23:33:02** | **event_id=4688; process=vssadmin.exe; cmdline=vssadmin.exe delete shadows /all /quiet; user=svc.backup; host=FS** | exact | [E7] |
| **EV007** | **2026-11-10 23:33:05** | **alert=Shadow copy deletion; action=detected; host=FS-02; severity=high** | exact | [E8] |
| **EV008** | **2026-11-10 23:34:10** | **event_id=4688; process=locker.exe; user=svc.backup; host=FS-02** | exact | [E9] |
| **EV009** | **2026-11-10 23:36:40** | **alert=Mass file rename (.lockd extension); action=detected; host=FS-02; severity=critical** | exact | [E10] |
| EV010 | 2026-11-10 23:40:12 | action=allow; src_ip=FS-02 | exact | [E11] |
| **EV011** | **2026-11-10 23:52:00** | **23:52 On-call paged by the EDR mass-rename alert. The shadow-copy alert at 23:33 had not paged anyone.** | date inferred | [E12] |
| **EV012** | **2026-11-10 23:58:00** | **23:58 Isolated FS-02 and JMP-01 from the network.** | date inferred | [E13] |
| **EV013** | **2026-11-11 01:20:00** | **2026-11-11 01:20 Disabled svc.backup and blocked 203.0.113.66 at the firewall.** | timezone assumed | [E14] |
| **EV014** | **2026-11-11 09:40:00** | **2026-11-11 09:40 Restore of FS-02 from the offline backup started. About 2 days of file changes were lost.** | timezone assumed | [E15] |

## 3. What happened

- **[confirmed]** The firewall allowed connections from external IP 203.0.113.66 to JMP-01 on RDP port 3389. [E1][E3]
- **[confirmed]** There were 312 failed RDP logons for svc.backup on JMP-01 from that IP between 22:41 and 22:58, followed by a successful remote interactive logon. [E2][E4]
- **[confirmed]** Special privileges were assigned to svc.backup's session on JMP-01. [E5]
- **[confirmed]** A service (PSEXESVC.exe) was installed remotely on FS-02 from JMP-01 using svc.backup. [E6]
- **[confirmed]** svc.backup ran a command to delete all shadow copies on FS-02, and EDR detected it. [E7][E8]
- **[confirmed]** locker.exe ran on FS-02 as svc.backup, and EDR detected a critical mass file rename with a .lockd extension. [E9][E10]
- **[confirmed]** A ransom note, README_RESTORE.txt, was left on FS-02. It asks victims to contact an attacker email address and claims data was stolen. [E16]
- **[confirmed]** On-call was paged only by the mass-rename alert at 23:52. The earlier shadow-copy alert had paged no one. [E12]
- **[confirmed]** Responders isolated FS-02 and JMP-01, then disabled svc.backup and blocked the attacker IP at the firewall. [E13][E14]
- **[confirmed]** FS-02 was restored from offline backup, with about 2 days of file changes lost. The decision was not to pay the ransom. [E15][E17]
- **[possible]** The attacker's claim that 200 GB was stolen is not confirmed. Egress for FS-02 and JMP-01 showed no large outbound transfers, but other hosts have not been reviewed. [E16][E18]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `203.0.113.66` | ip | [E1] |
| `e48f58a29d9e57c5e23d873afcd37bb3487369ff1ace9ee00dd2dd1401f820a2` | sha256 | [E9] |
| `decrypt-desk@lockd-support.test` | email | [E16] |
| `lockd-support.test` | domain | [E16] |

## 5. MITRE ATT&CK mapping

| Tactic | Technique | ID | Certainty | Behaviour | Evidence |
|---|---|---|---|---|---|
| credential-access | Brute Force | T1110 | confirmed | 312 failed RDP logons for svc.backup from one external IP preceded a successful logon. | [E2] |
| initial-access, persistence | External Remote Services | T1133 | probable | The attacker used RDP on JMP-01 that was exposed to the internet as the entry point. | [E3][E19] |
| initial-access, persistence, privilege-escalation, stealth | Valid Accounts | T1078 | confirmed | The attacker logged on with the legitimate service account svc.backup. | [E4] |
| lateral-movement | Remote Services: Remote Desktop Protocol | T1021.001 | confirmed | The attacker made a remote interactive (RDP) logon to JMP-01. | [E4] |
| execution | System Services: Service Execution | T1569.002 | confirmed | A PSEXESVC service was installed remotely on FS-02 from JMP-01 under svc.backup. | [E6] |
| impact | Inhibit System Recovery | T1490 | confirmed | Shadow copies on FS-02 were deleted before encryption to prevent recovery. | [E7] |
| impact | Data Encrypted for Impact | T1486 | probable | locker.exe ran, files were mass-renamed with a .lockd extension, and a ransom note was left. | [E9][E10][E16] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**Immediate cause [probable]:** After 312 failed attempts, the attacker logged on to JMP-01 over RDP as svc.backup from 203.0.113.66. The evidence does not say how the credential was obtained. Password guessing is probable given the failed-logon burst. [E2][E4]

**[confirmed]** RDP on JMP-01 was opened to the internet in 2025 as a temporary vendor exception and never closed. This allowed direct internet attack on a service account that RDP never needed to accept. [E19]

### Contributing factors

- **[confirmed]** svc.backup had a password last changed in 2022, no MFA on RDP, and admin rights on FS-02. A single credential therefore gave access to the jump host and the file server. [E20]
- **[confirmed]** The shadow-copy deletion alert was routed to a queue instead of paging, which delayed response. [E21]

## 7. Impact assessment

- **Systems involved:** `JMP-01`, `FS-02`
- **Accounts involved:** `svc.backup`
- **Data affected:** [confirmed] Files on FS-02 were mass-renamed with a .lockd extension, and the server was restored from offline backup with about 2 days of file changes lost. Data exfiltration is not confirmed. [E10][E15]
- **Operational impact:** [confirmed] FS-02 and JMP-01 were isolated from the network, and FS-02 was restored from offline backup. [E13][E15]
- **Business impact:** [unknown] Financial cost and the duration of user-facing disruption are not stated in the evidence.

## 8. Response analysis

Milestones chosen by the model from the timeline; durations computed by code from timestamps.

| Milestone | Event | Time (UTC) | Time basis |
|---|---|---|---|
| attack start | EV001 | 2026-11-10 22:41:07 | exact |
| first detection | EV007 | 2026-11-10 23:33:05 | exact |
| response start | EV011 | 2026-11-10 23:52:00 | date inferred |
| containment | EV012 | 2026-11-10 23:58:00 | date inferred |

| Measure | From → to | Duration |
|---|---|---|
| time to detect | attack start → first detection | 51m 58s |
| time to respond | first detection → response start | 18m 55s (approximate: inferred time) |
| time to contain | first detection → containment | 24m 55s (approximate: inferred time) |
| dwell time | attack start → containment | 1h 16m 53s (approximate: inferred time) |

## 9. Detection gaps

- **[confirmed]** The high-severity shadow-copy deletion alert at 23:33 paged no one. Paging happened only for the mass-rename alert at 23:52, after encryption had started. [E12][E21]
- **[confirmed]** Egress review is incomplete: only FS-02 and JMP-01 have been checked, so data theft cannot yet be confirmed or ruled out. [E18]

## 10. Lessons learned

**Process**
- Alerts that signal ransomware preparation must page immediately. Queue routing cost about 19 minutes between the shadow-copy alert and the page. [E12][E21] [P1]
- Ransom-note theft claims need a scoped egress review across all hosts before conclusions are drawn. [E18] [P2]

**Technology**
- Service accounts must not be usable for RDP and must hold least privilege. An old password and admin rights on FS-02 let one account reach the file server. [E20] [P3]

**Governance**
- Temporary firewall exceptions without an owner and expiry become permanent exposure. A vendor exception stayed open for about a year and was the entry point. Prior guidance on expiring exceptions was not applied here. [E19] [P4][P5]

## 11. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Confirm RDP 3389 on JMP-01 is no longer reachable from the internet. Allow remote access only through a bastion or VPN with MFA, and verify this before reconnecting restored systems. | RDP exposed to the internet was the entry point, and the evidence does not record the exposure being closed. [E19] | [P6][P7] | Network Security | Immediately | Removes the direct internet attack path to JMP-01. |
| critical | Rebuild svc.backup as least-privilege. Deny interactive and RDP logon, remove local admin on FS-02, and use a long rotated password or a managed identity. | svc.backup had an old password, no MFA on RDP and admin rights, and was the account used throughout the attack. [E20] | [P3] | Identity and Access Management | Within 1 week | A stolen service credential no longer yields remote logon or admin access. |
| high | Audit all existing temporary firewall exceptions. Require a named owner and an automatic expiry of at most 30 days for each, and close those without one. | The vendor exception had no expiry and stayed open about a year. [E19] | [P4][P5] | Network Security | Within 2 weeks | Prevents other stale exposures from becoming entry points. |
| high | Route all high and critical EDR alerts to paging within 5 minutes, and classify shadow-copy deletion as critical. | The high-severity shadow-copy alert went to a queue and paged no one. [E12][E21] | [P1] | Security Operations | Within 1 week | Earlier on-call response, before encryption begins. |
| high | Complete the egress review for all in-scope hosts, not only FS-02 and JMP-01, to decide whether the data-theft claim has support. | The attacker claims 200 GB was stolen, and only two hosts have been reviewed. [E16][E18] | [P2] | Incident Response | Within 3 days | Determines whether data left the network and whether notification duties apply. |
| high | Investigate whether the attacker reached other servers from JMP-01 (logons, remote service installs), and review all hosts reachable from it. | Lateral movement beyond FS-02 is unresolved, and the attacker held admin-level access from JMP-01. [E6][E22] | - | Incident Response | Within 3 days | Finds any other compromised systems before they are reused. |

## 12. Open questions and remaining risks

- **Open:** How did the attacker obtain the svc.backup password? Password guessing after the 312 failures is probable but not confirmed.
- **Open:** Was data actually exfiltrated? Egress for FS-02 and JMP-01 shows no large transfers, but other hosts are not reviewed.
- **Open:** Did the attacker reach other servers from JMP-01?
- **Open:** Is RDP exposure on JMP-01 now closed? The notes record only that svc.backup was disabled and the attacker IP blocked.
- **Open:** Did any alerting fire on the 312 failed RDP logons? The evidence records none.
- **Open:** What is the nature of the 5,320-byte outbound HTTPS connection from FS-02 to 198.51.100.10 at 23:40? Its destination is not identified as malicious in the evidence.
- **Risk:** Possible data theft that has not been ruled out, since egress for other hosts is unreviewed.
- **Risk:** Other servers may be compromised via JMP-01.
- **Risk:** Other stale temporary exceptions or weak service accounts may exist.

## 13. Validation log

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
| E16 | ir_notes.txt | line 10 | Ransom note README_RESTORE.txt on FS-02 |
| E17 | ir_notes.txt | line 12 | no ransom will be paid |
| E18 | ir_notes.txt | line 11 | shows no large outbound transfers |
| E19 | ir_notes.txt | line 7 | opened to the internet in 2025 as a temporary vendor exception and never closed |
| E20 | ir_notes.txt | line 8 | svc.backup had a password last changed in 2022, no MFA on RDP, and admin rights on FS-02 |
| E21 | ir_notes.txt | line 9 | routed to a queue, not to paging |
| E22 | ir_notes.txt | line 13 | unclear whether the attacker reached other servers from JMP-01 |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | POL-12 §2 Alert routing | High and critical alerts must page the on-call analyst within 5 minutes. |
| P2 | PB-02 §4 Data theft claims | Review egress traffic for all hosts in scope |
| P3 | POL-07 §4 Service accounts | Service accounts must not be allowed interactive or remote desktop logon. |
| P4 | PIR-2025-031 §2 Lessons | every temporary exception gets an owner and an automatic expiry |
| P5 | POL-15 §2 Temporary exceptions | need a named owner and an expiry of at most 30 days |
| P6 | POL-15 §4 Remote administration | Remote administration protocols (RDP, SSH) must never be exposed directly to the internet. |
| P7 | PB-02 §5 Recovery | Restore from offline or immutable backups after confirming the entry point is closed |

_Knowledge-base sections given to the model: PB-02#4, PIR-2025-031#1, POL-07#4, PB-02#5, POL-15#2, PIR-2025-031#2, POL-12#2, POL-15#4_

**Evidence file hashes (SHA-256)**

- `edr_alerts.csv`: `d1eb9ee53fb9bbd1fd93c051de22f0b773da0e294eb8f5d98a9a0e26f09b30bd`
- `firewall.csv`: `ecf764454e27397bf66a732dcefba5f95349476f8d0c0bf45377385817c6372a`
- `ir_notes.txt`: `7df2cec315cc26243c2e2262b239fe551e07af9c2d603dea3811cea998560f96`
- `windows_security.json`: `bb1692a9700508c594abb3c26686592d7a1d3a2923d2c3583aaf8ed69d0db85c`
