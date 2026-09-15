# PowerShell DownloadString Remote Execution

## Title
PowerShell DownloadString Remote Execution

## Description
Detects use of PowerShell's `DownloadString()` method to download content from a remote URL directly into memory, bypassing the filesystem entirely. When combined with `Invoke-Expression` (IEX), this creates a fileless execution chain where a remote script is downloaded and executed without ever touching disk — a technique commonly used in initial access, post-exploitation, and C2 stager delivery. Covers both the process command line (where the full command is visible) and PowerShell script block logging (where obfuscated or multi-stage scripts surface their decoded content). Known legitimate automation tools, cloud metadata endpoints, and package managers are excluded.

## MITRE Mapping
- Tactic: Execution
- Technique: Command and Scripting Interpreter (T1059), PowerShell (T1086)
- Technique ID: T1059, T1086

## Severity
- High

## Frequency / Lookback
- Run frequency: Scheduled
- Lookback period: 4 hours

## KQL Query
```kusto
// Detect PowerShell DownloadString() method usage - commonly used to download and execute malicious scripts
// Covers both process creation command line and script block logging
// Excludes known legitimate automation tools and cloud metadata endpoints

union
(
    DeviceProcessEvents
    | where ActionType == "ProcessCreated"
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine contains "DownloadString"
    | where ProcessCommandLine contains "http"
    | where not (ProcessCommandLine has_any (dynamic(["168.63.129.16", "169.254.169.254", "chocolatey"])))
    | project
        DeviceId,
        Timestamp,
        ReportId,
        DeviceName,
        AccountName,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        FileName,
        ProcessCommandLine,
        EventType = "ProcessCreated"
),
(
    DeviceEvents
    | where ActionType == "PowerShellCommand"
    | where AdditionalFields has "DownloadString"
    | where AdditionalFields has "http"
    | where not (AdditionalFields has_any (dynamic(["168.63.129.16", "169.254.169.254"])))
    | project
        DeviceId,
        Timestamp,
        ReportId,
        DeviceName,
        AccountName = "",
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        FileName = "",
        ProcessCommandLine = tostring(AdditionalFields),
        EventType = "ScriptBlockLogging"
)
| order by Timestamp desc
```

## Alert Settings
- Title (max 3 variables): PowerShell DownloadString Detected on {{DeviceName}} via {{InitiatingProcessFileName}}
- Description (max 3 variables): PowerShell's DownloadString() method was detected initiated by {{InitiatingProcessFileName}}. Account: {{AccountName}}. Command: {{ProcessCommandLine}}
- Custom Details:
  - EventType: ProcessCreated / ScriptBlockLogging
  - CommandLine: ProcessCommandLine
  - ParentProcess: InitiatingProcessFileName

## Entity Mapping
- Account: AccountName
- Host: DeviceName
- IP: N/A
- File: FileName
- Process: ProcessCommandLine

## Recommended Actions
- Review `ProcessCommandLine` or script block content immediately — extract the full URL and check it against threat intelligence; the domain and path often identify the malware family or C2 framework.
- Check `InitiatingProcessFileName` — a document reader, browser, or email client parent confirms a phishing-initiated execution chain; `w3wp.exe` confirms web shell execution.
- Search `DeviceNetworkEvents` on the same `DeviceId` around the same `Timestamp` for the outbound connection to determine whether the download succeeded.
- If `EventType` is `ScriptBlockLogging`, correlate with `DeviceProcessEvents` on the same `DeviceId` for the full PowerShell execution context.
- Hunt for `IEX` / `Invoke-Expression` in the same command line or script block — combined with `DownloadString`, this confirms fileless execution and should be treated as a confirmed incident pending further evidence.

## Tuning Notes
| Date | Change | Reason |
|------|--------|--------|
| 2026-03-25 | Initial version | Baseline |
| 2026-09-15 | Added script block logging branch, exclusions for cloud metadata endpoints and package managers, tightened lookback to 4 hours, expanded recommended actions | Validated in Defender XDR; reduce false positives and cover obfuscated/multi-stage execution |
