# Suspicious Office Child Process

## Title
Suspicious Office Child Process

## Description
Detects known attacker-favoured LOLBins and interpreter binaries spawned directly by a Microsoft Office application (Word, Excel, PowerPoint, Outlook, OneNote, Publisher, Visio). Office processes should not spawn command interpreters, scripting hosts, or download utilities under normal operation. This pattern is commonly associated with malicious macros, phishing document execution, and initial access via Office-based payloads.

## MITRE Mapping
- Tactic: Execution
- Technique: Command and Scripting Interpreter (T1059), User Execution (T1204), User Execution: Malicious File (T1204.002)
- Technique ID: T1059, T1204, T1204.002

## Severity
- High

## Frequency / Lookback
- Run frequency: NRT
- Lookback period: NRT

## KQL Query
```kusto
// Detect suspicious child processes spawned by Microsoft Office applications
// Covers common LOLBin / attacker-favoured binaries launched from Office parents

DeviceProcessEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName in~ (
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "onenote.exe", "mspub.exe", "visio.exe"
  )
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "msiexec.exe",
    "schtasks.exe", "at.exe",
    "net.exe", "net1.exe",
    "curl.exe", "wget.exe",
    "odbcconf.exe", "regasm.exe", "regsvcs.exe",
    "installutil.exe", "ieexec.exe", "forfiles.exe",
    "pcalua.exe", "bash.exe", "msbuild.exe"
  )
| project
    Timestamp,
    DeviceId,
    DeviceName,
    ReportId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    FileName,
    ProcessCommandLine,
    AccountName,
    FolderPath,
    SHA256,
    InitiatingProcessParentFileName
```

## Alert Settings
- Title (max 3 variables): Suspicious child process launched by {{InitiatingProcessFileName}} on {{DeviceName}}
- Description (max 3 variables): Office process {{InitiatingProcessFileName}} spawned {{FileName}} with command line: {{ProcessCommandLine}}
- Custom Details:
  - ParentProcess: InitiatingProcessFileName
  - CommandLine: ProcessCommandLine
  - Hash: SHA256

## Entity Mapping
- Account: AccountName
- Host: DeviceName
- IP: N/A
- File: FileName
- Process: ProcessCommandLine

## Recommended Actions
- Review `ProcessCommandLine` for the spawned interpreter/utility and determine whether it references a remote URL, encoded payload, or suspicious arguments.
- Confirm the Office document's origin (email attachment, download, network share) and whether macros were enabled.
- Check `SHA256` and `FolderPath` of the spawned process against threat intelligence.
- Search `DeviceNetworkEvents` and `DeviceFileEvents` on the same `DeviceId` for follow-on downloads or persistence artifacts.
- Isolate the endpoint and treat as a confirmed phishing-initiated compromise if the child process establishes network connections or drops additional payloads.

## Tuning Notes
| Date | Change | Reason |
|------|--------|--------|
| 2026-09-15 | Initial version | Baseline |
