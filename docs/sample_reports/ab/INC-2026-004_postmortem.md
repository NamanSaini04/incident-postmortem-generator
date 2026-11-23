# Incident Postmortem: INC-2026-004: Ransomware on file server FS-02 via internet-exposed RDP on JMP-01 and a weak service account

> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. Every claim below cites its source record; claims that failed validation were removed (see Validation log).

| Field | Value |
|---|---|
| Incident ID | INC-2026-004 |
| Category | ransomware |
| Severity | SEV1 |
| Classification confidence | 90% |
| Generated | 2026-11-23 20:15 UTC |
| Model | claude-sonnet-5-5 |

## 1. Executive summary

An external IP probably brute-forced the svc.backup account over RDP exposed on JMP-01, then logged on successfully. Using svc.backup, the attacker installed a remote service on FS-02 from JMP-01, deleted shadow copies and ran a locker binary, which encrypted files. The RDP exposure was a temporary vendor exception that was never closed. The service account had an old password, no MFA and admin rights on FS-02. The high-severity shadow-copy alert went to a queue and paged no one. On-call was paged only by the later mass-rename alert. Responders isolated FS-02 and JMP-01, disabled the account, blocked the source IP and restored FS-02 from offline backup. About 2 days of file changes were lost. The attacker's claim of 200 GB stolen is not confirmed. Egress for other hosts and possible lateral movement from JMP-01 remain unreviewed.

**Severity rationale:** Ransomware is confirmed on FS-02: shadow copies were deleted, locker.exe ran, mass file renaming was detected, and a ransom note was left. FS-02 had to be restored from offline backup with about 2 days of file changes lost. Data theft is only claimed by the attacker and is not confirmed. Egress for FS-02 and JMP-01 shows no large transfers, and other hosts have not been reviewed.

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

- **[confirmed]** External IP 203.0.113.66 reached RDP on JMP-01 (firewall allowed). It produced 312 failed RDP logons for svc.backup within about 17 minutes (EV001, EV002). [E1][E2]
- **[confirmed]** The same IP then logged on to JMP-01 as svc.backup through a successful remote interactive logon, and the account was assigned special privileges (EV003, EV004). [E4][E5]
- **[confirmed]** A service (PSEXESVC.exe) was installed remotely on FS-02 from JMP-01 under svc.backup, indicating lateral movement (EV005). [E6]
- **[confirmed]** On FS-02, svc.backup deleted all shadow copies, then ran locker.exe. EDR detected the shadow copy deletion and then mass file renaming with the .lockd extension (EV006 to EV009). [E7][E9][E10]
- **[confirmed]** On-call was paged by the mass-rename alert. FS-02 and JMP-01 were isolated, svc.backup was disabled, the attacker IP was blocked, and FS-02 restore from offline backup began with about 2 days of file changes lost (EV011 to EV014). [E12][E13][E14][E15]
- **[unknown]** Whether data was exfiltrated is not determined. The ransom note claims 200 GB was stolen. Egress for FS-02 and JMP-01 shows no large outbound transfers, but other hosts have not been reviewed. [E16][E17]
- **[unknown]** It is unclear whether the attacker reached other servers from JMP-01. [E18]

## 4. Indicators of compromise

| Indicator | Type | First seen |
|---|---|---|
| `203.0.113.66` | ip | [E1] |
| `e48f58a29d9e57c5e23d873afcd37bb3487369ff1ace9ee00dd2dd1401f820a2` | sha256 | [E9] |
| `decrypt-desk@lockd-support.test` | email | [E16] |
| `lockd-support.test` | domain | [E16] |

## 5. Root cause

**[probable]** RDP on JMP-01 was reachable from the internet through a vendor exception that was never closed. The attacker probably used it to obtain svc.backup, which had a stale password, no MFA and admin rights on FS-02, and used it to reach and encrypt FS-02. The records show many failed logons followed by a success from the same IP. They do not record how the password was obtained. [E2][E19][E20]

### Contributing factors

- **[confirmed]** The temporary vendor firewall exception for RDP had no effective expiry or review and stayed open for about a year. [E19]
- **[confirmed]** The svc.backup service account had an old password, no MFA on RDP and admin rights on FS-02. This let one stolen credential give full control of the file server. [E20]

## 6. Detection gaps

- **[confirmed]** The high-severity shadow-copy deletion alert was routed to a queue and paged no one. On-call was alerted only by the later mass-rename alert, after encryption had started. [E12][E21]

## 7. Lessons learned

**Process**
- Service accounts need hardening and rotation. A 2022 password, no MFA and local admin on the file server turned one login into full compromise. [E20] [P1]
- Do not accept or dismiss the data theft claim. Egress review must cover all hosts in scope, and it is still incomplete. [E17] [P2]

**Technology**
- Ransomware-preparation alerts such as shadow copy deletion must page on-call. Queue routing cost the responders time before the mass-rename alert paged. [E21] [P3]

**Governance**
- Temporary exceptions need an owner and an automatic expiry. A prior postmortem agreed this action, yet the same pattern (a temporary RDP opening with no expiry) recurred. [E19] [P4][P5]

## 8. Corrective actions

| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |
|---|---|---|---|---|---|---|
| critical | Remove direct internet exposure of RDP on JMP-01 and any other host. Allow remote administration only through a bastion or VPN with MFA, and audit the firewall for other open management ports. | RDP on JMP-01 was internet-reachable for about a year and was the attacker's entry point. [E19] | [P6] | Network Security | Immediately (before any production reconnect) | Removes the internet-facing entry path. |
| critical | Rotate svc.backup and all credentials used on JMP-01 and FS-02. Deny service accounts interactive and RDP logon. Reduce backup account rights to backup-operator only, with a long password or a managed identity. | svc.backup had a 2022 password, no MFA and admin rights on FS-02, and was used for the whole attack chain. [E20] | [P1] | Identity and Access Management | Within 1 week | Limits the impact of a single stolen service credential. |
| high | Route shadow-copy deletion and other ransomware-preparation alerts as critical, paging on-call within 5 minutes. Review all high and critical alert routes for queue-only delivery. | The shadow-copy alert was queued and paged no one, so response began only after the mass-rename alert. [E21] | [P3] | Security Operations | Within 1 week | Earlier response, before encryption. |
| high | Enforce an owner and automatic expiry (30 days maximum) on every temporary firewall or policy exception. Review all existing exceptions now. | A temporary vendor exception stayed open for about a year, and a previous postmortem had already agreed this action. [E19] | [P4][P5] | Security Governance | Within 30 days | Prevents forgotten exposures. |
| high | Review egress traffic for all in-scope hosts, not only FS-02 and JMP-01, and use the result to assess the 200 GB theft claim before concluding on data exposure. Also scope whether the attacker reached other servers from JMP-01. | Egress for other hosts has not been reviewed, and lateral movement from JMP-01 is an open question. [E17][E18] | [P2] | Incident Response | Within 3 days | Establishes whether data left the network and whether other hosts are affected. |
| medium | Complete the FS-02 restore only once the entry point is confirmed closed, and record the data lost since the last backup (about 2 days so far). | The restore from offline backup is under way and the data loss must be documented. [E15] | [P7] | IT Operations | During recovery | Prevents reinfection and documents the business impact. |

## 9. Open questions and remaining risks

- **Open:** Was data exfiltrated? The ransom note claims 200 GB, but egress for hosts other than FS-02 and JMP-01 is unreviewed.
- **Open:** Did the attacker reach other servers from JMP-01?
- **Open:** How exactly was the svc.backup password obtained? The records show 312 failed logons and then a success, but not the method.
- **Open:** What is the FS-02 connection to 198.51.100.10 on port 443 (EV010)? The evidence does not show whether it is malicious.
- **Open:** Did the 312 failed RDP logons trigger any alert or review?
- **Open:** Who owned the vendor RDP exception, and was it ever reviewed?
- **Risk:** Other servers may have been accessed from JMP-01 (not confirmed).
- **Risk:** Stolen data may be published or misused if the theft claim is true (unconfirmed).
- **Risk:** Until credentials are rotated and exposure is audited, the same weaknesses may exist on other hosts or accounts.

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
| E17 | ir_notes.txt | line 11 | shows no large outbound transfers. Egress for other hosts not yet reviewed. |
| E18 | ir_notes.txt | line 13 | unclear whether the attacker reached other servers from JMP-01 |
| E19 | ir_notes.txt | line 7 | RDP (3389) on JMP-01 was opened to the internet in 2025 as a temporary vendor exception and never closed |
| E20 | ir_notes.txt | line 8 | password last changed in 2022, no MFA on RDP, and admin rights on FS-02 |
| E21 | ir_notes.txt | line 9 | the shadow-copy deletion alert was high severity but routed to a queue, not to paging |

## Policy and playbook references

Company knowledge base (synthetic). These support recommendations, not facts about the incident.

| Ref | Section | Quote |
|---|---|---|
| P1 | POL-07 §4 Service accounts | Service accounts must not be allowed interactive or remote desktop logon. |
| P2 | PB-02 §4 Data theft claims | Review egress traffic for all hosts in scope, not only the encrypted ones |
| P3 | POL-12 §2 Alert routing | High and critical alerts must page the on-call analyst within 5 minutes. |
| P4 | PIR-2025-031 §2 Lessons | every temporary exception gets an owner and an automatic expiry |
| P5 | POL-15 §2 Temporary exceptions | need a named owner and an expiry of at most 30 days |
| P6 | POL-15 §4 Remote administration | Remote administration protocols (RDP, SSH) must never be exposed directly to the internet. |
| P7 | PB-02 §5 Recovery | Restore from offline or immutable backups after confirming the entry point is closed. |

_Knowledge-base sections given to the model: PB-02#4, PIR-2025-031#1, POL-07#4, PB-02#5, POL-15#2, PIR-2025-031#2, POL-12#2, POL-15#4_

**Evidence file hashes (SHA-256)**

- `edr_alerts.csv`: `d1eb9ee53fb9bbd1fd93c051de22f0b773da0e294eb8f5d98a9a0e26f09b30bd`
- `firewall.csv`: `ecf764454e27397bf66a732dcefba5f95349476f8d0c0bf45377385817c6372a`
- `ir_notes.txt`: `7df2cec315cc26243c2e2262b239fe551e07af9c2d603dea3811cea998560f96`
- `windows_security.json`: `bb1692a9700508c594abb3c26686592d7a1d3a2923d2c3583aaf8ed69d0db85c`
