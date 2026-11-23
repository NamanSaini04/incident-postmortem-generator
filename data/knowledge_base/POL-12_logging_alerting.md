# POL-12 Logging, Monitoring and Alerting Standard
(Synthetic internal standard for testing.)

## §1 Scope
Applies to all security monitoring tools, including SIEM, EDR, DLP, email gateway and cloud alerting.

## §2 Alert routing
High and critical alerts must page the on-call analyst within 5 minutes. Email-only or queue-only routing is not allowed for high or critical alerts. Alerts that indicate ransomware preparation, such as shadow copy deletion, are always critical.

## §3 Triage targets and correlation
Target time to start triage: critical 15 minutes, high 30 minutes, medium 4 hours. When several alerts concern the same user or host, they are triaged together at the severity of the highest alert. Impossible-travel alerts on accounts without MFA are raised to high.

## §4 Required log sources
Authentication logs, EDR telemetry, web proxy logs, email gateway logs and cloud management events are mandatory. Storage data-access events (object reads) must be enabled for any bucket holding confidential or restricted data. Logs are kept for at least one year.

## §5 Data loss prevention
DLP rules may run in audit mode for at most 30 days of tuning. After that, rules covering uploads of confidential or restricted data to personal cloud storage must block. DLP alerts for personal cloud uploads are triaged as high, not only in periodic reports.
