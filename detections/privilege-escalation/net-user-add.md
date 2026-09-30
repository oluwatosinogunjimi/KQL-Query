# User Account Creation via Command Line

## Title
User Account Creation via Command Line

## Goal (ADS)
Catch a local user account being created from the command line, often a backdoor account for persistence.

## Description
Detects creation of local user accounts using command-line utilities. This behavior is commonly associated with persistence or unauthorized access.

## MITRE Mapping
- Tactic: Persistence, Privilege Escalation
- Technique: Valid Accounts
- Technique ID: T1078

## Strategy Abstract (ADS)
`DeviceProcessEvents` where the command line matches `net user <name> ... /add`.

## Technical Context (ADS)
Attackers create an account with `net user <name> <password> /add`, then usually add it to Administrators or Remote Desktop Users. Account names are often chosen to look like service or support accounts. The parent process and the same session's next commands show intent.

## Blind Spots and Assumptions (ADS)
- The pattern requires text between `net user` and `/add`, so `net user /add <name>` (switch before the name) is not matched.
- net1.exe is not matched (the companion admin-group rule does match it).
- Other creation methods: PowerShell `New-LocalUser`, WMI, direct API calls and attack tools.
- Domain accounts created with `/domain` are matched, but accounts created on a domain controller through AD tools are not.
- The `DeviceEvents` ActionType `UserAccountCreated` records the creation itself whatever tool made it, and would close most of these gaps.

## False Positives (ADS)
- Provisioning and imaging scripts that create local accounts.
- Kiosk, lab and shared-device setup.

## Severity
- Medium
- Why: New local accounts are rarely created by hand on managed estates; it merits review but usually needs a second signal to confirm malice.

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

## Validation (ADS)
| Date | Method | Environment | Result |
|------|--------|-------------|--------|
| — | Atomic Red Team | Windows test device, Defender XDR | Alert raised |

## Recommended Actions
- Triage playbook: [Local Account Created or Added to Administrators](https://oluwatosinogunjimi.github.io/soc-triage-trees/#local-admin-added)
- Confirm whether the account creation was part of an approved administrative action.
- Investigate command history and parent process behavior for potential compromise.
- Disable unauthorized accounts and perform credential hygiene.

## Tuning Notes
| Date | Change | Reason |
|------|--------|--------|
| 2026-03-25 | Initial version | Baseline |
