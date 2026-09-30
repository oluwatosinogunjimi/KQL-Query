# Svchost Execution from Unusual Location

## Title
Svchost Execution from Unusual Location

## Goal (ADS)
Catch malware disguised as svchost.exe by running or dropping a copy of it outside the Windows system folders.

## Description
Detects svchost.exe executed or created outside legitimate Windows directories. This is a strong indicator of masquerading.

## MITRE Mapping
- Tactic: Defense Evasion
- Technique: Masquerading: Match Legitimate Name or Location
- Technique ID: T1036.005

## Strategy Abstract (ADS)
Two branches unioned together. `DeviceProcessEvents` catches svchost.exe starting from any folder other than System32, SysWOW64 or WinSxS. `DeviceFileEvents` catches a file named svchost.exe being created or renamed outside those folders, which can fire before the binary ever runs.

## Technical Context (ADS)
Genuine svchost.exe only lives in `C:\Windows\System32` (and `SysWOW64` on 64-bit systems), and is almost always started by services.exe. Masquerading malware copies or names itself svchost.exe in user-writable paths such as `%AppData%`, `%Temp%`, `C:\ProgramData` or `C:\Users\Public`, often with a normal-looking command line to blend in. The file branch also sees the drop itself, so a hit there with no matching process hit can mean the payload was blocked or has not run yet.

## Blind Spots and Assumptions (ADS)
- Only matches the name svchost.exe. Malware named after other system binaries (lsass.exe, csrss.exe, services.exe, explorer.exe) is not covered.
- Misses a malicious svchost.exe placed inside System32 itself (needs admin rights, but possible after privilege escalation).
- Misses malware that runs inside a genuine svchost.exe, for example a malicious service DLL loaded by the real binary.
- Assumes Windows is installed on `C:`; the path check is literal.
- Assumes the Defender for Endpoint sensor is present and reporting on the host.

## False Positives (ADS)
- Windows feature updates and upgrades staging files in `C:\$WINDOWS.~BT\` or leaving copies in `C:\Windows.old\` (file branch).
- Backup, imaging and forensic tools copying system files into their own folders (file branch).
- Hosts where Windows lives on a drive other than `C:`.

## Severity
- High
- Why: A svchost.exe outside the system folders has almost no legitimate explanation once upgrade and backup paths are excluded.

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

## Validation (ADS)
| Date | Method | Environment | Result |
|------|--------|-------------|--------|
| — | Atomic Red Team | Windows test device, Defender XDR | Custom rule fired |

## Recommended Actions
- Triage playbook: [Malware or EDR Detection](https://oluwatosinogunjimi.github.io/soc-triage-trees/#edr-malware-detection)
- Validate whether svchost.exe in this path is legitimate software activity.
- Review process lineage and file provenance to identify potential masquerading.
- Quarantine suspicious binaries and investigate persistence mechanisms.

## Tuning Notes
| Date | Change | Reason |
|------|--------|--------|
| 2026-03-25 | Initial version | Baseline |
