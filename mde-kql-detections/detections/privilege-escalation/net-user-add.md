# User Account Creation via Command Line

## Title
User Account Creation via Command Line

## Description
Detects creation of local user accounts using command-line utilities. This behavior is commonly associated with persistence or unauthorized access.

## MITRE Mapping
- Tactic: Persistence, Privilege Escalation
- Technique: Valid Accounts
- Technique ID: T1078

## Severity
- Medium

## Frequency / Lookback
- Run frequency: Scheduled
- Lookback period: 1 day

## KQL Query
```kusto
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessCommandLine matches regex @"(?i)net(\.exe)?\s+user\s+.*\s+/add"
| project
    DeviceId,
    Timestamp,
    ReportId,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine
| order by Timestamp desc
```

## Alert Settings
- Title (max 3 variables): User account created via command line on {{DeviceName}}
- Description (max 3 variables): {{AccountName}} executed {{FileName}} to create a user on {{DeviceName}}
- Custom Details:
  - CommandLine: ProcessCommandLine
  - ParentProcess: InitiatingProcessFileName

## Entity Mapping
- Account: AccountName
- Host: DeviceName
- IP: N/A
- File: FileName
- Process: ProcessCommandLine

## Recommended Actions
- Confirm whether the account creation was part of an approved administrative action.
- Investigate command history and parent process behavior for potential compromise.
- Disable unauthorized accounts and perform credential hygiene.

## Tuning Notes
| Date | Change | Reason |
|------|--------|--------|
| 2026-03-25 | Initial version | Baseline |
