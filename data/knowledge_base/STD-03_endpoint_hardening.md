# STD-03 Endpoint and Email Hardening Standard
(Synthetic internal standard for testing.)

## §1 Office macros
Macros in Office files from the internet are blocked on all workstations. Exclusions follow POL-15 §2 and must be limited to signed macros or trusted locations, never a whole organisational unit.

## §2 EDR mode
EDR runs in prevent (block) mode on all workstations and servers. Detect-only mode is allowed only during a rollout of at most 14 days.

## §3 Email attachments
Macro-enabled Office attachments (.docm, .xlsm) are detonated in a sandbox before delivery or quarantined.
