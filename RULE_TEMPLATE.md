# Rule Title

<!--
Sections marked (ADS) follow Palantir's Alerting and Detection Strategy framework:
they record why the rule exists, where it is blind, and how it was proven to work.
The other sections record how to deploy it as a Defender XDR custom detection.
-->

## Title

## Goal (ADS)
<!-- One sentence: the attacker behaviour this rule exists to catch. -->

## Description

## MITRE Mapping
- Tactic:
- Technique:
- Technique ID:

## Strategy Abstract (ADS)
<!-- How the logic works, in plain words: which table, which conditions, which exclusions. -->

## Technical Context (ADS)
<!-- What the telemetry looks like and what a real attack leaves behind in it. -->

## Blind Spots and Assumptions (ADS)
<!-- What this rule will miss, and what must be true for it to work (sensor coverage, logging, naming). -->
-

## False Positives (ADS)
<!-- Known benign causes and how to recognise them. -->
-

## Severity
- Informational | Low | Medium | High
- Why:

## Frequency / Lookback
- Run frequency:
- Lookback period:

## KQL Query
```kusto
// Add query here
```

## Alert Settings
- Title (max 3 variables):
- Description (max 3 variables):
- Custom Details:

## Entity Mapping
- Account:
- Host:
- IP:
- File:
- Process:

## Validation (ADS)
<!-- One row per test. A rule is only "validated" once it has fired on a known-bad test in the target environment. -->
| Date | Method | Environment | Result |
|------|--------|-------------|--------|
| YYYY-MM-DD | e.g. Atomic Red Team test, manual replay | Lab / Production tenant | Fired / Did not fire / Partial |

## Recommended Actions
- Triage playbook: [Triage Trees](https://oluwatosinogunjimi.github.io/soc-triage-trees/)
-

## Tuning Notes
| Date | Change | Reason |
|------|--------|--------|
| YYYY-MM-DD | Initial version | Baseline |
