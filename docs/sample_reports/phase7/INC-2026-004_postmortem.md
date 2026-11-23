# Incident Postmortem: INC-2026-004: Ransomware on FS-02 via internet-exposed RDP on JMP-01 and a weak service account

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-004 |
| Category | ransomware |
| Severity | SEV1 |
| Classification confidence | 90% |
| Generated | 2026-11-23 20:43 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

Ransomware activity hit file server FS-02: locker.exe ran and files were mass-renamed with a .lockd extension. The attacker connected from an external IP to JMP-01 over RDP, which was open to the internet. A successful svc.backup logon followed 312 failed ones. From JMP-01 the attacker used svc.backup to install a remote service on FS-02, then deleted its shadow copies before running the locker. The high-severity shadow-copy alert went to a queue and paged no one. On-call was paged only 19 minutes later by the mass-rename alert. The ransom note's claim of 200 GB stolen is not confirmed. Egress for FS-02 and JMP-01 showed no large transfers, but other hosts have not been reviewed. FS-02 is being restored from offline backup, with about 2 days of file changes lost. No ransom will be paid.

**Severity rationale:** Ransomware activity on FS-02 is confirmed: shadow copies were deleted, locker.exe ran, files were mass-renamed with a .lockd extension, and a ransom note was left (windows_security.json events[4], windows_security.json events[5], edr_alerts.csv row 2, ir_notes.txt line 10). The restore lost about 2 days of file changes (ir_notes.txt line 6). This meets the SEV1 ransomware criterion. The ransom note's data theft claim is not confirmed, and the severity does not rely on it.

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
| EV007 | 2026-11-10 23:33:05 | alert=Shadow copy deletion; action=detected; host=FS-02; severity=high | exact | [E8] |
| **EV008** | **2026-11-10 23:34:10** | **event_id=4688; process=locker.exe; user=svc.backup; host=FS-02** | exact | [E9] |
| **EV009** | **2026-11-10 23:36:40** | **alert=Mass file rename (.lockd extension); action=detected; host=FS-02; severity=critical** | exact | [E10] |
| EV010 | 2026-11-10 23:40:12 | action=allow; src_ip=FS-02 | exact | [E11] |
| **EV011** | **2026-11-10 23:52:00** | **23:52 On-call paged by the EDR mass-rename alert. The shadow-copy alert at 23:33 had not paged anyone.** | date inferred | [E12] |
| EV012 | 2026-11-10 23:58:00 | 23:58 Isolated FS-02 and JMP-01 from the network. | date inferred | [E13] |
| **EV013** | **2026-11-11 01:20:00** | **2026-11-11 01:20 Disabled svc.backup and blocked 203.0.113.66 at the firewall.** | timezone assumed | [E14] |
| EV014 | 2026-11-11 09:40:00 | 2026-11-11 09:40 Restore of FS-02 from the offline backup started. About 2 days of file changes were lost. | timezone assumed | [E15] |

## 3. What happened

- **[confirmed]** An external IP connected to JMP-01 on RDP (3389) and the firewall allowed it. [E1][E3]
- **[confirmed]** JMP-01 logged 312 failed RDP logons for svc.backup from the external IP over about 17 minutes. A successful remote interactive logon for svc.backup from the same IP followed. The failure pattern suggests password guessing, but the evidence does not say how the credential was obtained. [E2][E4]
- **[confirmed]** Special privileges were assigned to svc.backup on JMP-01. A service (PSEXESVC.exe) was then installed remotely on FS-02 from JMP-01 under svc.backup. [E5][E6]
- **[confirmed]** On FS-02, svc.backup ran a command deleting all shadow copies, and EDR detected it as a high-severity alert. [E7][E8]
- **[confirmed]** locker.exe ran on FS-02 under svc.backup. EDR then raised a critical mass-rename alert (.lockd extension), and a ransom note was left on FS-02. [E9][E10][E16]
- **[unknown]** Whether data was stolen is not determined. The ransom note claims 200 GB was stolen. Egress for FS-02 and JMP-01 shows no large outbound transfers, and other hosts are not yet reviewed. [E16][E17]
- **[confirmed]** On-call was paged by the mass-rename alert, not by the earlier shadow-copy alert. FS-02 and JMP-01 were then isolated. Later svc.backup was disabled and the attacker IP was blocked at the firewall. [E12][E13][E14]
- **[confirmed]** Restore of FS-02 from the offline backup started, with about 2 days of file changes lost. The decision was not to pay the ransom. [E15][E18]

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
| credential-access | Brute Force | T1110 | probable | 312 failed RDP logons for svc.backup from one external IP were followed by a success, consistent with password guessing. | [E2][E4] |
| initial-access, persistence, privilege-escalation, stealth | Valid Accounts | T1078 | confirmed | The attacker logged on with the valid svc.backup service account. | [E4] |
| lateral-movement | Remote Services: Remote Desktop Protocol | T1021.001 | confirmed | The attacker used RDP (logon type 10) to reach JMP-01 from the internet. | [E1][E4] |
| execution | System Services: Service Execution | T1569.002 | probable | A PSEXESVC.exe service was installed remotely on FS-02 from JMP-01, consistent with remote service execution. | [E6] |
| impact | Inhibit System Recovery | T1490 | confirmed | All shadow copies on FS-02 were deleted to inhibit recovery. | [E7] |
| impact | Data Encrypted for Impact | T1486 | probable | locker.exe ran, files were mass-renamed with a .lockd extension, and a ransom note was left, consistent with data encrypted for impact. | [E9][E10][E16] |

_Technique IDs checked against Enterprise ATT&CK matrix modified 2026-07-31 (ATT&CK spec 3.3.0). ATT&CK® is a registered trademark of The MITRE Corporation._

## 6. Root cause

**[confirmed]** RDP on JMP-01 was exposed directly to the internet. svc.backup, with a 2022 password, no MFA on RDP and admin rights on FS-02, could be used for a remote logon, which gave the attacker a path to FS-02. How the attacker got the credential is not established. [E4][E19][E20]

### Contributing factors

- **[confirmed]** A temporary vendor firewall exception opened RDP to the internet in 2025 and was never closed, so no owner or expiry removed it. [E19]
- **[confirmed]** The svc.backup service account had a stale password, no MFA on RDP, and administrative rights on the file server. That let one stolen or guessed credential run services and delete shadow copies on FS-02. [E6][E20]

## 7. Detection gaps

- **[confirmed]** The high-severity shadow-copy deletion alert was routed to a queue and paged no one. On-call was engaged only by the mass-rename alert, 19 minutes later and after encryption had started. [E12][E21]
- **[confirmed]** Egress review for the data theft claim is incomplete: only FS-02 and JMP-01 have been reviewed. [E17]

## 8. Lessons learned

**Process**
- Service accounts need no remote desktop logon, rotated passwords, and least privilege. svc.backup had none of these. [E20] [P1]
- Do not accept or dismiss data theft claims. Egress review must cover all hosts in scope. [E17] [P2]

**Technology**
- Remote administration must never be reachable directly from the internet. RDP on JMP-01 allowed the attacker's logon. [E1] [P3]
- Ransomware-preparation alerts such as shadow copy deletion must page on-call. A queue-routed alert cost about 19 minutes of response time. [E21] [P4]

**Governance**
- Temporary vendor exceptions need an owner and an automatic expiry. This one stayed open for roughly a year and became the entry point. [E19] [P5]

## 9. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Confirm the RDP exposure on JMP-01 is closed. Allow remote access only through a bastion or VPN with MFA, and audit the firewall for other direct RDP/SSH exposure. | RDP on JMP-01 was open to the internet and was the attacker's way in. [E19] | [P3] | Network Security | Immediately, before restored systems return to service | Removes the confirmed internet-facing entry point. |
| critical | Rotate or replace the svc.backup credentials, deny it interactive and RDP logon, and reduce it to backup-operator rights. Review other service accounts for the same weaknesses. | svc.backup had a 2022 password, no MFA on RDP and admin rights on FS-02, and the attacker used it for remote logon, service install, and the locker. [E20] | [P1] | Identity and Access Management | Within 1 week | Limits the damage if a service credential is stolen again. |
| high | Make every temporary security exception carry a named owner and an automatic expiry of at most 30 days, with review on expiry. Review all existing exceptions now. | The vendor exception stayed open for about a year with no review. [E19] | [P5][P6] | Security Governance | Within 30 days | Stops forgotten exceptions from becoming permanent exposure. |
| high | Re-route high and critical EDR alerts to paging, and classify shadow copy deletion as critical. | The shadow-copy alert at 23:33 reached only a queue, and on-call was paged only at 23:52 by the mass-rename alert. [E12][E21] | [P4] | Security Operations | Within 1 week | Responders can act before encryption starts. |
| high | Review egress for all hosts in scope, not only FS-02 and JMP-01, to settle the 200 GB theft claim. Also review whether the attacker reached other servers from JMP-01. | Egress for other hosts is unreviewed and lateral movement from JMP-01 is an open question. [E17][E22] | [P2] | Incident Response | Within 3 days | Gives an evidence-based answer on data exposure and scope, including any notification duty. |
| medium | Complete the FS-02 restore only after the entry point is confirmed closed, and record the data lost since the last backup (about 2 days of file changes). | The restore started on 2026-11-11 and file changes were lost. [E15] | [P7] | IT Operations | During recovery | Prevents re-compromise and documents the business impact. |

## 10. Open questions and remaining risks

- **Open:** How did the attacker obtain the svc.backup password? The 312 failed logons suggest guessing, but this is not confirmed.
- **Open:** Was any data exfiltrated? The ransom note claims 200 GB, and only FS-02 and JMP-01 egress has been reviewed.
- **Open:** Did the attacker reach other servers from JMP-01?
- **Open:** What was the FS-02 connection to 198.51.100.10 on port 443 (5,320 bytes out)? The evidence does not classify it as malicious or benign.
- **Open:** Did the 312 failed RDP logons or the successful external logon on JMP-01 raise any alert? The evidence does not say.
- **Risk:** Data theft is not ruled out. The ransom note claims 200 GB was stolen and egress for hosts other than FS-02 and JMP-01 is unreviewed.
- **Risk:** Other servers may have been accessed from JMP-01. This is an open question.
- **Risk:** Other internet-exposed remote administration services or other weak service accounts may exist, because the same controls failed here.

## 11. Validation log

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
| E17 | ir_notes.txt | line 11 | Firewall egress for FS-02 and JMP-01 shows no large outbound transfers. |
| E18 | ir_notes.txt | line 12 | Decision: no ransom will be paid. |
| E19 | ir_notes.txt | line 7 | RDP (3389) on JMP-01 was opened to the internet in 2025 as a temporary vendor exception and never closed. |
| E20 | ir_notes.txt | line 8 | svc.backup had a password last changed in 2022, no MFA on RDP, and admin rights on FS-02 |
| E21 | ir_notes.txt | line 9 | the shadow-copy deletion alert was high severity but routed to a queue, not to paging |
| E22 | ir_notes.txt | line 13 | unclear whether the attacker reached other servers from JMP-01 |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | POL-07 §4 Service accounts | Service accounts must not be allowed interactive or remote desktop logon. |
| P2 | PB-02 §4 Data theft claims | Review egress traffic for all hosts in scope, not only the encrypted ones |
| P3 | POL-15 §4 Remote administration | must never be exposed directly to the internet |
| P4 | POL-12 §2 Alert routing | High and critical alerts must page the on-call analyst within 5 minutes. |
| P5 | POL-15 §2 Temporary exceptions | need a named owner and an expiry of at most 30 days |
| P6 | PIR-2025-031 §2 Lessons | every temporary exception gets an owner and an automatic expiry |
| P7 | PB-02 §5 Recovery | Restore from offline or immutable backups after confirming the entry point is closed. |

_Knowledge-base sections given to the model: PB-02#4, PIR-2025-031#1, POL-07#4, PB-02#5, POL-15#2, PIR-2025-031#2, POL-12#2, POL-15#4_

**Evidence file hashes (SHA-256)**

- `edr_alerts.csv`: `d1eb9ee53fb9bbd1fd93c051de22f0b773da0e294eb8f5d98a9a0e26f09b30bd`
- `firewall.csv`: `ecf764454e27397bf66a732dcefba5f95349476f8d0c0bf45377385817c6372a`
- `ir_notes.txt`: `7df2cec315cc26243c2e2262b239fe551e07af9c2d603dea3811cea998560f96`
- `windows_security.json`: `bb1692a9700508c594abb3c26686592d7a1d3a2923d2c3583aaf8ed69d0db85c`
