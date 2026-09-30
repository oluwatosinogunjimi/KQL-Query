# Local Administrators Group Modification via Command Line

## Title
Local Administrators Group Modification via Command Line

## Goal (ADS)
Catch an account being added to the local Administrators group from the command line, a common step after initial access to gain or keep admin rights.

## Description
Detects attempts to add accounts to the local Administrators group using command-line utilities. This behavior is commonly associated with privilege escalation during post-exploitation.

## MITRE Mapping
- Tactic: Privilege Escalation
- Technique: Account Manipulation
- Technique ID: T1098

## Strategy Abstract (ADS)
`DeviceProcessEvents` where the command line contains `net localgroup` (net.exe or net1.exe), the word `administrators` and `/add`.

## Technical Context (ADS)
Attackers and some ransomware operators run `net localgroup administrators <user> /add` to give a new or compromised account admin rights, often right after creating that account. The parent process shows where it came from: a remote shell, PsExec, a script, or an admin's interactive session. A matching account creation on the same host shortly before is a strong sign of attacker persistence.

## Blind Spots and Assumptions (ADS)
- Other ways to add a member: PowerShell `Add-LocalGroupMember`, WMI or ADSI scripts, direct Windows API calls used by attack tools, and Group Policy Restricted Groups.
- Localised group names on non-English systems (for example Administratoren, Administrateurs).
- Command-line obfuscation such as caret insertion (`n^et localgroup`).
- The `DeviceEvents` ActionType `UserAccountAddedToLocalGroup` records the change itself whatever tool made it, and would close most of these gaps as a companion rule.

## False Positives (ADS)
- IT provisioning scripts and helpdesk staff granting temporary admin rights.
- Software installers that add a service account to Administrators.

## Severity
- High
- Why: Unauthorised admin rights give an attacker full control of the host; legitimate changes should be traceable to a ticket or known tooling.

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

## Validation (ADS)
| Date | Method | Environment | Result |
|------|--------|-------------|--------|
| — | Atomic Red Team | Windows test device, Defender XDR | Custom rule fired |

## Recommended Actions
- Triage playbook: [Local Account Created or Added to Administrators](https://oluwatosinogunjimi.github.io/soc-triage-trees/#local-admin-added)
- Validate whether the account addition was authorized by IT administration.
- Investigate the parent process and related command history for suspicious activity.
- Remove unauthorized accounts from the Administrators group and reset credentials as needed.

## Tuning Notes
| Date | Change | Reason |
|------|--------|--------|
| 2026-03-25 | Initial version | Baseline |
