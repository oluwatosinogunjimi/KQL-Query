# Local Administrators Group Modification via Command Line

## Title
Local Administrators Group Modification via Command Line

## Description
Detects attempts to add accounts to the local Administrators group using command-line utilities. This behavior is commonly associated with privilege escalation during post-exploitation.

## MITRE Mapping
- Tactic: Privilege Escalation
- Technique: Account Manipulation
- Technique ID: T1098

## Severity
- High

## Frequency / Lookback
- Run frequency: NRT
- Lookback period: NRT

## KQL Query
```kusto
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessCommandLine matches regex @"(?i)net1?(\.exe)?\s+localgroup"
| where ProcessCommandLine matches regex @"(?i)administrators"
| where ProcessCommandLine matches regex @"(?i)\/add"
| project
    DeviceId,
    Timestamp,
    ReportId,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine
| order by Timestamp desc
```

## Alert Settings
- Title (max 3 variables): Local Admin Group Modified on {{DeviceName}}
- Description (max 3 variables): {{AccountName}} executed {{FileName}} to modify Administrators group on {{DeviceName}}
- Custom Details:
  - ParentProcess: InitiatingProcessFileName
  - CommandLine: ProcessCommandLine

## Entity Mapping
- Account: AccountName
- Host: DeviceName
- IP: N/A
- File: FileName
- Process: ProcessCommandLine

## Recommended Actions
- Validate whether the account addition was authorized by IT administration.
- Investigate the parent process and related command history for suspicious activity.
- Remove unauthorized accounts from the Administrators group and reset credentials as needed.

## Tuning Notes
| Date | Change | Reason |
|------|--------|--------|
| 2026-03-25 | Initial version | Baseline |
