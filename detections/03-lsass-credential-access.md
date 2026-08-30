# Detection 03 — LSASS Credential Access

| | |
|---|---|
| MITRE ATT&CK | T1003.001 — OS Credential Dumping: LSASS Memory |
| Tactic | Credential Access |
| Data source | Sysmon Event ID 10 (Process access) — `index=main` |
| Severity | Critical |

## What it detects

`lsass.exe` holds the credentials of everyone logged into a machine, which is why dumping its memory (Mimikatz, comsvcs.dll, procdump, and most C2 frameworks) is the single highest-value move an attacker makes on a Windows host. Sysmon Event ID 10 logs every process that opens a handle to another — the trick is that legitimate access to LSASS is rare and comes from a short, known list of system processes, while credential theft asks for specific memory-read access rights.

This rule keys on two strong signals: the **GrantedAccess** mask matching the rights Mimikatz-style tools request, and a **CallTrace** that contains `UNKNOWN` — meaning the call came from memory not backed by any file on disk, which is exactly what injected/reflectively-loaded attack code looks like. Either one on its own is suspicious; together they're about as close to a smoking gun as detection gets.

## Search

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="*\\lsass.exe"
NOT SourceImage IN (
    "C:\\Windows\\System32\\wininit.exe",
    "C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\System32\\csrss.exe",
    "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    "C:\\Windows\\System32\\MsMpEng.exe",
    "C:\\ProgramData\\Microsoft\\Windows Defender\\*"
)
| eval suspicious_access = if(GrantedAccess IN ("0x1010","0x1410","0x1418","0x1438","0x143a","0x1f0fff","0x1f1fff","0x1fffff"), 1, 0)
| eval injected_caller = if(match(CallTrace, "(?i)UNKNOWN"), 1, 0)
| where suspicious_access=1 OR injected_caller=1
| stats min(_time) as firstTime max(_time) as lastTime count values(GrantedAccess) as GrantedAccess by host, SourceImage, SourceUser, injected_caller
| convert ctime(firstTime) ctime(lastTime)
| sort - injected_caller, - lastTime
```

## Alert configuration

| Setting | Value |
|---|---|
| Type | Scheduled |
| Schedule (cron) | `*/5 * * * *` |
| Time range | Last 5 minutes |
| Trigger | Number of results > 0 |
| Throttle | By `host`, `SourceImage` for 1 hour |

This one should page immediately — legitimate LSASS access from a non-system process is close to nonexistent in a normal environment.

## How to test

The clean way to test without real malware is procdump (Sysinternals), which opens LSASS with the same read rights a dumper uses:

```
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\out.dmp
```

That produces an Event ID 10 from `procdump.exe` with a matching GrantedAccess mask. Delete the dump afterward. (Running actual Mimikatz will also fire it, with `UNKNOWN` in the CallTrace — but procdump is enough to prove the rule.)

## Tuning notes

- Confirm Sysmon Event ID 10 for `lsass.exe` is enabled in your config — the Olaf `sysmon-modular` config logs it by default.
- EDR and some backup/AV products legitimately read LSASS. Watch the first few days of results, and add any confirmed-good `SourceImage` to the exclusion list — but keep exclusions tight, because "our AV does it too" is exactly the cover attackers rely on.
- GrantedAccess masks are tunable: `0x1010` and `0x1410` are the most common dumping rights; the full-access masks (`0x1f0fff` etc.) catch broader tools.
