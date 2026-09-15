# KQL-Query

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A personal library of KQL threat hunting queries and custom detection rules for **Microsoft Defender for Endpoint (MDE)** / Microsoft Defender XDR, built around **Advanced Hunting** and mapped to **MITRE ATT&CK**.

Each rule is documented end-to-end: the query itself, alert configuration, entity mapping, analyst response steps, and a tuning log — the same format used to take a hunting query from Advanced Hunting into a production custom detection rule.

## Detections

| Rule | Tactic | Technique | Severity |
|---|---|---|---|
| [Svchost Execution from Unusual Location](detections/defense-evasion/svchost-masquerading.md) | Defense Evasion | Masquerading ([T1036](https://attack.mitre.org/techniques/T1036/)) | High |
| [PowerShell DownloadString Remote Execution](detections/execution/powershell-downloadstring.md) | Execution | Command and Scripting Interpreter ([T1059](https://attack.mitre.org/techniques/T1059/)) | High |
| [Local Administrators Group Modification via Command Line](detections/privilege-escalation/local-admin-group-modification.md) | Privilege Escalation | Account Manipulation ([T1098](https://attack.mitre.org/techniques/T1098/)) | High |
| [User Account Creation via Command Line](detections/privilege-escalation/net-user-add.md) | Persistence, Privilege Escalation | Valid Accounts ([T1078](https://attack.mitre.org/techniques/T1078/)) | Medium |

## Repository structure

- `detections/` — Detection rules, organized by ATT&CK tactic (one subfolder per tactic; only tactics with a published rule are present).
- `tuning/` — Tuning notes and exclusion history for reducing false positives without losing coverage.
- `RULE_TEMPLATE.md` — The standard format used to document every rule in this repo: description, MITRE mapping, severity, KQL query, alert settings, entity mapping, recommended actions, and a tuning log.

## How to use a rule

1. Copy the query from a rule's `KQL Query` section into Microsoft Defender XDR **Advanced Hunting**.
2. Run it against your own tenant and validate the results and false-positive rate.
3. Tune the query for your environment (see `tuning/`) and log the change.
4. Promote it to a custom detection rule using the documented `Alert Settings` and `Entity Mapping`.

## Disclaimer

These queries are starting points, not drop-in production rules. Detection quality depends on your environment, telemetry coverage, and operational context — tuning is expected before deployment.

## License

MIT — see [LICENSE](LICENSE).
