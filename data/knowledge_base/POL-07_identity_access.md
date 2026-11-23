# POL-07 Identity and Access Policy
(Synthetic internal policy for testing.)

## §1 Scope
Applies to all workforce, contractor and service identities in on-premises directories and cloud accounts.

## §2 Multi-factor authentication
MFA is required for every interactive sign-in, including email, VPN, remote desktop gateways and cloud consoles. A password alone must never be enough to sign in from outside the corporate network.

## §3 Exceptions to MFA and conditional access
An exception must have a named owner, a documented business reason and an expiry date no more than 90 days away. The IAM team reviews all exceptions monthly and removes expired ones. Exceptions created during migrations must be removed when the migration ends.

## §4 Service accounts
Service accounts must not be allowed interactive or remote desktop logon. Passwords must be at least 25 characters and rotated every 90 days, or replaced by a managed identity. Service accounts get least privilege: backup accounts hold backup-operator rights only, never local administrator on file servers.

## §5 Joiners, movers and leavers
When an employee gives notice, HR informs IT within one business day. IT reviews the leaver's access and removes bulk-export, admin and sensitive-data rights for the notice period unless the manager approves otherwise in writing.

## §6 Cloud credentials
Long-lived access keys are prohibited for human and contractor users; use short-lived credentials through single sign-on. Where a key is unavoidable it must be rotated within 90 days. The iam:* permission and policy-attachment rights are granted only to the cloud administrators group, and permission boundaries must stop users attaching administrative policies to themselves.
