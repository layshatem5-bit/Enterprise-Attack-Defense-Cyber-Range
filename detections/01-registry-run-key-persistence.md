# Detection 01 — Registry Run Key Persistence

| | |
|---|---|
| MITRE ATT&CK | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| Tactic | Persistence |
| Data source | Sysmon Event ID 13 (Registry value set) — `index=main` |
| Severity | Medium (High when the value points at a suspicious path) |

## What it detects

Attackers keep access across reboots by writing an autorun entry into the registry — most commonly the `Run` / `RunOnce` keys or the Winlogon `Shell` / `Userinit` values. Sysmon records every registry value change as Event ID 13, so instead of alerting on "a registry key changed" (far too noisy), this rule watches only the handful of keys that actually control autostart, and scores the *value* that was written: an entry pointing at a user-writable path (AppData, Temp, Public, ProgramData) or a script interpreter is what a real payload looks like.

This is the exact technique proven end-to-end in the first Caldera test, so it's the natural first detection to stand up.

## Search

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
TargetObject IN (
    "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
    "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
    "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\\*",
    "*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    "*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"
)
| eval risk=if(match(Details, "(?i)(\\\\Users\\\\Public\\\\|\\\\AppData\\\\|\\\\Temp\\\\|\\\\ProgramData\\\\|\.ps1|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|\.vbs|\.bat|\.hta|\.js)"), "HIGH", "REVIEW")
| stats min(_time) as firstTime max(_time) as lastTime count by host, User, Image, TargetObject, Details, risk
| convert ctime(firstTime) ctime(lastTime)
| sort - risk, - lastTime
```

`Details` is the value data that was written (the program that will run at logon). `Image` is the process that made the change, `User` the account it ran as.

## Alert configuration

| Setting | Value |
|---|---|
| Type | Scheduled |
| Schedule (cron) | `*/5 * * * *` |
| Time range | Last 5 minutes |
| Trigger | Number of results > 0 |
| Throttle | By `host`, `TargetObject` for 1 hour (avoid duplicate alerts on the same entry) |

## How to test

Run this on a target through Caldera (Manual Command) or a local PowerShell — it's the same technique as the first Caldera test:

```powershell
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "C:\Users\Public\beacon.exe"
```

The entry pointing at `C:\Users\Public\` should fire with `risk=HIGH`. Clean up afterward:

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater"
```

## Tuning notes

- Legitimate software does write Run keys at install time. If a known-good app shows up repeatedly as `REVIEW`, add its `Details` value to an exclusion so only genuinely new entries surface.
- The `HIGH` tier is the one to page on; `REVIEW` is for daily triage.
