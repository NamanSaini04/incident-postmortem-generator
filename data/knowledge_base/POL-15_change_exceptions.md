# POL-15 Change and Exception Management Policy
(Synthetic internal policy for testing.)

## §1 Change tickets
Every change to production systems, network rules, cloud permissions or storage access needs an approved change ticket.

## §2 Temporary exceptions
Temporary security exceptions (firewall openings, policy exclusions, relaxed controls for vendors) need a named owner and an expiry of at most 30 days, and are reviewed automatically on expiry.

## §3 Public exposure of storage
Making any storage bucket or file share public requires security approval. An account-level public access block must be enabled in every cloud account. Vendor access must use scoped, time-limited credentials and test data, never public access to production data.

## §4 Remote administration
Remote administration protocols (RDP, SSH) must never be exposed directly to the internet. Remote access goes through a bastion or VPN with MFA.
