# PIR-2025-031 Past Incident Review: Exposed RDP on a Test Server
(Synthetic historical record for testing.)

## §1 Summary
A test server had RDP open to the internet after a vendor support session. Thousands of failed logons were seen; no logon succeeded.

## §2 Lessons
Temporary firewall openings had no expiry. Agreed action: every temporary exception gets an owner and an automatic expiry, and RDP is only reachable through the bastion.
