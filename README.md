# KQL-Query

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A personal library of KQL threat hunting queries and custom detection rules for **Microsoft Defender for Endpoint (MDE)** / Microsoft Defender XDR, built around **Advanced Hunting** and mapped to **MITRE ATT&CK v20** (October 2026), including each technique's Detection Strategy (DET) and Analytic (AN) IDs.

Each rule is documented end-to-end: the query itself, alert configuration, entity mapping, analyst response steps, and a tuning log — the same format used to take a hunting query from Advanced Hunting into a production custom detection rule.

Each rule also follows Palantir's [Alerting and Detection Strategy](https://github.com/palantir/alerting-detection-strategy-framework) (ADS) framework: its goal, how the logic works, what the telemetry looks like, its blind spots and assumptions, known false positives, and a validation log showing how it was proven to fire. Every rule links to its triage playbook in [Triage Trees](https://oluwatosinogunjimi.github.io/soc-triage-trees/).

## Detections

| Rule | Tactic | Technique | Severity |
|---|---|---|---|
| [Svchost Execution from Unusual Location](detections/stealth/svchost-masquerading.md) | Stealth | Masquerading: Match Legitimate Resource Name or Location ([T1036.005](https://attack.mitre.org/techniques/T1036/005/)) | High |
| [PowerShell DownloadString Remote Execution](detections/execution/powershell-downloadstring.md) | Execution | Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/)) | High |
| [Suspicious Office Child Process](detections/execution/suspicious-office-child-process.md) | Execution | User Execution ([T1204](https://attack.mitre.org/techniques/T1204/)) | High |
| [Local Administrators Group Modification via Command Line](detections/privilege-escalation/local-admin-group-modification.md) | Privilege Escalation, Persistence | Account Manipulation ([T1098](https://attack.mitre.org/techniques/T1098/)) | High |
| [User Account Creation via Command Line](detections/persistence/net-user-add.md) | Persistence | Create Account: Local Account ([T1136.001](https://attack.mitre.org/techniques/T1136/001/)) | Medium |
| [LSASS Memory Dump via LOLBin or Dump Utility](detections/credential-access/lsass-dump-via-lolbin.md) | Credential Access | OS Credential Dumping: LSASS Memory ([T1003.001](https://attack.mitre.org/techniques/T1003/001/)) | High |
| [Unsanctioned Remote Access Tool Execution](detections/command-and-control/unsanctioned-remote-access-tool.md) | Command and Control | Remote Access Tools ([T1219](https://attack.mitre.org/techniques/T1219/)) | Medium |

## Repository structure

- `detections/` — Detection rules, organized by ATT&CK tactic (one subfolder per tactic; only tactics with a published rule are present).
- `tuning/` — Tuning notes and exclusion history for reducing false positives without losing coverage.
- `RULE_TEMPLATE.md` — The standard format used to document every rule in this repo: goal, description, MITRE mapping, strategy, technical context, blind spots, false positives, severity with rationale, KQL query, alert settings, entity mapping, validation log, recommended actions with the linked triage playbook, and a tuning log.

## How to use a rule

1. Copy the query from a rule's `KQL Query` section into Microsoft Defender XDR **Advanced Hunting**.
2. Run it against your own tenant and validate the results and false-positive rate.
3. Tune the query for your environment (see `tuning/`) and log the change.
4. Promote it to a custom detection rule using the documented `Alert Settings` and `Entity Mapping`.

## Disclaimer

These queries are starting points, not drop-in production rules. Detection quality depends on your environment, telemetry coverage, and operational context — tuning is expected before deployment.

## License

MIT — see [LICENSE](LICENSE).
