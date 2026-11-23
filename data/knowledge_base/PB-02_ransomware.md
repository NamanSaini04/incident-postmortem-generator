# PB-02 Ransomware Playbook
(Synthetic internal playbook for testing.)

## §1 Isolation
Isolate affected hosts immediately through EDR or the network. Do not power them off before memory and disk evidence is preserved where possible.

## §2 Entry point and accounts
Identify the entry point and the accounts used. Disable compromised accounts at once, including service accounts, even outside business hours.

## §3 Spread
Check every host reachable from the entry point for remote service creation, remote execution and new logons by the compromised accounts.

## §4 Data theft claims
Do not accept ransom note claims of data theft at face value, and do not dismiss them either. Review egress traffic for all hosts in scope, not only the encrypted ones, before concluding whether data left the network.

## §5 Recovery
Restore from offline or immutable backups after confirming the entry point is closed. Record the data lost between the last backup and the attack.

## §6 Ransom decisions
Paying a ransom requires an executive and legal decision and is not the default.
