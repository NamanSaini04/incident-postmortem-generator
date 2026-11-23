# PB-04 Cloud Credential Compromise Playbook
(Synthetic internal playbook for testing.)

## §1 Containment
Deactivate the exposed access keys and revoke active sessions for the affected identity.

## §2 Persistence review
Review cloud management events for every action by the identity: new users, new access keys for other identities, role and policy changes. Remove anything the attacker created, including keys created for other users.

## §3 Rogue resources
Terminate resources launched by the attacker and check billing for unexpected usage.

## §4 Data access
Determine whether data was read. If storage data-access logging was off, state that reads cannot be ruled out and treat the data as potentially exposed.

## §5 Leaked secrets
Remove leaked secrets from code repository history, rotate every credential found there, and enable push-time secret scanning.
