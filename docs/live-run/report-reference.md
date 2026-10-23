# Report Reference

This document defines the metrics used in the CipherPost daily health and quality reports.

## Session Metrics
- **Sessions per day**: Total number of unique mail sessions detected.
- **Protocol Breakdown**: Count of sessions by SMTP, IMAP, and POP3.
- **Encrypted vs. Plaintext**: Ratio of sessions using encryption.
- **TLS Version**: Distribution of TLS versions used.

## Finding Metrics
- **New Flows**: Number of new connection flows detected.
- **New Fingerprints**: New JA3/JA4 fingerprints.
- **Findings by Rule**: Count categorized by severity (Info, Medium, High, Critical).
- **False Positive**: Count of suppressed findings.

## Pipeline Health
- **Consumer Lag**: Delay between capture and analysis.
- **Dead-letter**: Number of messages in the dead-letter own.
- **Capture Drops**: Number of sessions lost due to buffer overflows.
- **Alert Failures**: Count of failed alert deliveries.
