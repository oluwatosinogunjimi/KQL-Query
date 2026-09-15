# Svchost Execution from Unusual Location

## Title
Svchost Execution from Unusual Location

## Description
Detects svchost.exe executed or created outside legitimate Windows directories. This is a strong indicator of masquerading.

## MITRE Mapping
- Tactic: Defense Evasion
- Technique: Masquerading
- Technique ID: T1036

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
    | where FileName =~ "svchost.exe"
    | where not (tolower(FolderPath) has_any (dynamic([
        "c:\\windows\\system32\\",
        "c:\\windows\\syswow64\\",
        "c:\\windows\\winsxs\\"
    ])))
    | project
        DeviceId,
        Timestamp,
        ReportId,
        DeviceName,
        AccountName,
        FolderPath,
        FileName,
        ProcessCommandLine,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine
),
(
    DeviceFileEvents
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FileName =~ "svchost.exe"
    | where not (tolower(FolderPath) has_any (dynamic([
        "c:\\windows\\system32\\",
        "c:\\windows\\syswow64\\",
        "c:\\windows\\winsxs\\"
    ])))
    | project
        DeviceId,
        Timestamp,
        ReportId,
        DeviceName,
        AccountName = "",
        FolderPath,
        FileName,
        ProcessCommandLine = "",
        InitiatingProcessFileName,
        InitiatingProcessCommandLine
)
| order by Timestamp desc
```

## Alert Settings
- Title (max 3 variables): Suspicious svchost detected on {{DeviceName}}
- Description (max 3 variables): svchost executed from {{FolderPath}} on {{DeviceName}}
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
- Validate whether svchost.exe in this path is legitimate software activity.
- Review process lineage and file provenance to identify potential masquerading.
- Quarantine suspicious binaries and investigate persistence mechanisms.

## Tuning Notes
| Date | Change | Reason |
|------|--------|--------|
| 2026-03-25 | Initial version | Baseline |
