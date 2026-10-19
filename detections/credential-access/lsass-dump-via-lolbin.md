# LSASS Memory Dump via LOLBin or Dump Utility

## Title
LSASS Memory Dump via LOLBin or Dump Utility

## Goal (ADS)
Catch an attacker dumping LSASS memory to steal credentials, with priority on admin and jump hosts where privileged credentials are cached.

## Description
Detects command-line attempts to dump the memory of lsass.exe using the comsvcs.dll MiniDump export through rundll32, common dump utilities (ProcDump, RdrLeakDiag, SQLDumper, createdump, Dumpert) targeting lsass, and Mimikatz-style command strings. A successful dump gives the attacker cleartext passwords, NTLM hashes and Kerberos tickets for every account logged on to the device. On an admin or jump host, that means access to every system managed from it.

## MITRE Mapping
- ATT&CK version: v20 (Enterprise)
- Tactic: Credential Access (TA0006); Stealth (TA0005) for T1218.011
- Technique: OS Credential Dumping: LSASS Memory (T1003.001), System Binary Proxy Execution: Rundll32 (T1218.011)
- Technique ID: T1003.001, T1218.011
- Detection Strategy: [DET0363](https://attack.mitre.org/detectionstrategies/DET0363) (T1003.001), [DET0475](https://attack.mitre.org/detectionstrategies/DET0475) (T1218.011)
- Analytic (Windows): [AN1030](https://attack.mitre.org/detectionstrategies/DET0363#AN1030) (T1003.001), [AN1308](https://attack.mitre.org/detectionstrategies/DET0475#AN1308) (T1218.011)
- Telemetry: DeviceProcessEvents (the MITRE analytics use Sysmon 1, 3, 7, 10, 11, 13–14, 22 and Security 4673)

## Strategy Abstract (ADS)
`DeviceProcessEvents` matched on three branches: rundll32 (including renamed copies via `ProcessVersionInfoOriginalFileName`) calling comsvcs.dll by the MiniDump name or its ordinal (#24), a known dump utility whose command line references lsass, or Mimikatz module strings. The comsvcs branch also covers the ordinal obfuscation patterns used to avoid matching on "MiniDump".

## Technical Context (ADS)
The attacker needs local admin or SYSTEM and SeDebugPrivilege. The most common hands-on-keyboard method is `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass PID> C:\Windows\Temp\x.dmp full`, because it uses only built-in binaries. The ordinal form `#24` and padded variants (`#+0000024`, `#-4294967272`) are used to dodge string matching on "MiniDump". The dump is usually written to `C:\Windows\Temp`, `C:\ProgramData` or `C:\Users\Public`, then compressed and exfiltrated or parsed offline with Mimikatz or pypykatz.

## Blind Spots and Assumptions (ADS)
- Dump utilities that target lsass by PID only (for example `procdump -ma 712 out.dmp`) do not contain the string "lsass" and are missed by branch 2. A process-access rule on `DeviceEvents` covers this gap.
- Task Manager "Create dump file" leaves no useful command line.
- In-memory or custom tooling (nanodump, handle duplication, PssCaptureSnapshot, silent process exit via WerFault) does not go through these binaries.
- Renamed dump utilities other than rundll32 are only caught if their version info survives.
- Assumes command-line capture is intact. If LSA protection (RunAsPPL) or Credential Guard is enabled, the attempt may fail but still fires, which is still worth investigating.

## False Positives (ADS)
- Administrators or vendor support running ProcDump against lsass during a troubleshooting case.
- Security or forensic tooling run by the incident response team.
- comsvcs.dll MiniDump has almost no legitimate use; treat hits on that branch as suspicious by default.

## Severity
- High
- Why: Legitimate LSASS dumping is rare and usually change-controlled, and a successful dump on an admin or jump host exposes every credential used from it.

## Frequency / Lookback
- Run frequency: NRT
- Lookback period: NRT

## KQL Query
```kql
// Detect LSASS memory dumping via LOLBins, dump utilities or Mimikatz strings

DeviceProcessEvents
| where Timestamp > ago(1h)
| where
    // Branch 1: rundll32 calling comsvcs.dll MiniDump by name or ordinal (#24)
    // OriginalFileName catches a renamed rundll32
    (
        (FileName =~ "rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE")
        and ProcessCommandLine contains "comsvcs"
        and (
            ProcessCommandLine contains "minidump"
            // Ordinal obfuscation: #24, #+0000024, #-4294967272
            or ProcessCommandLine matches regex @"#\s*[+-]|#0*24\b|,\s*24\s"
        )
    )
    // Branch 2: known dump utilities with lsass on the command line
    or (
        ProcessCommandLine contains "lsass"
        and (
            FileName in~ ("procdump.exe", "procdump64.exe", "procdump64a.exe",
                          "rdrleakdiag.exe", "sqldumper.exe", "createdump.exe", "dumpert.exe")
            or ProcessVersionInfoOriginalFileName has_any ("procdump", "rdrleakdiag", "sqldumper", "createdump")
        )
    )
    // Branch 3: Mimikatz module strings, renamed binary or not
    or ProcessCommandLine has_any ("sekurlsa::", "lsadump::", "privilege::debug")
| project
    Timestamp,
    DeviceId,
    DeviceName,
    ReportId,
    AccountName,
    AccountDomain,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName
```

## Alert Settings
- Title (max 3 variables): LSASS dump attempt via {{FileName}} on {{DeviceName}}
- Description (max 3 variables): {{AccountName}} ran {{FileName}} with command line: {{ProcessCommandLine}}
- Custom Details:
  - CommandLine: ProcessCommandLine
  - ParentProcess: InitiatingProcessFileName
  - Hash: SHA256

## Entity Mapping
- Account: AccountName
- Host: DeviceName
- IP: N/A
- File: FileName
- Process: ProcessCommandLine

## Validation (ADS)
| Date | Method | Environment | Result |
|------|--------|-------------|--------|
| 2026-10-19 | Atomic Red Team T1003.001 #2 (comsvcs.dll MiniDump) | Windows test device, Defender XDR | Pending |
| 2026-10-19 | Atomic Red Team T1003.001 #1 (ProcDump against lsass by name) | Windows test device, Defender XDR | Pending |

## Recommended Actions
- Triage playbook: [LSASS Credential Dumping](https://oluwatosinogunjimi.github.io/soc-triage-trees/#lsass-credential-dumping)
- Confirm whether the activity was authorised (change ticket, incident response engagement, vendor support case). If not, treat as confirmed credential theft.
- Check `DeviceFileEvents` on the same `DeviceId` for a .dmp file written in the minutes after the alert, and whether it was compressed, moved or uploaded.
- Review the parent chain (`InitiatingProcessFileName`, `InitiatingProcessParentFileName`) to find how the attacker got admin execution.
- If the device is an admin or jump host, isolate it and reset every account that has logged on to it recently, including credentials for systems managed from it.
- Hunt for follow-on use of the stolen credentials: new logons from this device to other hosts, and sign-ins for the affected accounts from unusual sources.

## Tuning Notes
| Date | Change | Reason |
|------|--------|--------|
| 2026-10-19 | Initial version | Baseline |
