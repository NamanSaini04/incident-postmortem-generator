# PB-01 Account Compromise Playbook
(Synthetic internal playbook for testing.)

## §1 Triggers
Impossible travel, sign-in from a new country with a scripted user agent, new inbox forwarding rules, or a user reporting a credential phishing page.

## §2 Containment
Revoke all sessions and refresh tokens, reset the password, confirm MFA is enforced and registered to the real user, and block the attacker IPs.

## §3 Scoping
Review mailbox audit logs, inbox rules and forwarded messages, and file access in collaboration platforms (for example SharePoint and OneDrive) for the whole period the attacker had access. Identify every recipient of the phishing message and check proxy logs for clicks.

## §4 Eradication and recovery
Remove malicious rules and app consents, purge the phishing message from all mailboxes, and block the phishing domains at email and proxy layers.
