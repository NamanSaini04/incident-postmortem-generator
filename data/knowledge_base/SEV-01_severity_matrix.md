# SEV-01 Incident Severity Matrix
(Synthetic internal standard for testing.)

## §1 Levels
SEV1 critical: confirmed access to or exposure of restricted data at scale, ransomware, or widespread business disruption. SEV2 high: confirmed compromise of an account or host with attacker activity, contained, without confirmed large-scale restricted data exposure. SEV3 medium: attempted or minor compromise, quickly contained. SEV4 low: suspicious activity, no confirmed compromise.

## §2 Rules
Severity follows the worst confirmed impact. Fast containment after detection does not lower severity if data was already taken. Severity is raised if later evidence confirms more impact.
