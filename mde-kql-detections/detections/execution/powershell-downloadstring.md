# PowerShell DownloadString Remote Execution

## Title
PowerShell DownloadString Remote Execution

## Description
Detects use of PowerShell DownloadString() to retrieve remote content. This technique is commonly used in fileless execution and staging of malicious payloads.

## MITRE Mapping
- Tactic: Execution
- Technique: Command and Scripting Interpreter
- Technique ID: T1059

## Severity
- High

## Frequency / Lookback
- Run frequency: Scheduled
- Lookback period: 1 day

## KQL Query
```kusto
union
(
    DeviceProcessEvents
    | where ActionType == "ProcessCreated"
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine contains "DownloadString"
    | where ProcessCommandLine contains "http"
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
),
(
    DeviceEvents
    | where ActionType == "PowerShellCommand"
    | where AdditionalFields has "DownloadString"
    | where AdditionalFields has "http"
    | project
        DeviceId,
        Timestamp,
        ReportId,
        DeviceName,
        AccountName = "",
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        FileName = "",
        ProcessCommandLine = tostring(AdditionalFields)
)
| order by Timestamp desc
```

## Alert Settings
- Title (max 3 variables): PowerShell DownloadString detected on {{DeviceName}}
- Description (max 3 variables): {{InitiatingProcessFileName}} executed PowerShell DownloadString on {{DeviceName}}
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
- Review the full PowerShell command content and URL destination for legitimacy.
- Investigate the initiating process lineage and associated user context.
- Isolate and remediate affected endpoints if malicious payload staging is confirmed.

## Tuning Notes
| Date | Change | Reason |
|------|--------|--------|
| 2026-03-25 | Initial version | Baseline |
