# Detection 01 — Registry Run Key Persistence

| | |
|---|---|
| MITRE ATT&CK | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| Tactic | Persistence |
| Data source | Sysmon Event ID 13 (Registry value set) — `index=main` |
| Severity | High |
| Status | **Deployed and validated end-to-end (2026-08-30)** |

## What it detects

Attackers keep access across reboots by writing an autorun entry into the registry — most commonly the `Run` / `RunOnce` keys or the Winlogon `Shell` / `Userinit` values. Sysmon records every registry value change as Event ID 13, so instead of alerting on "a registry key changed" (far too noisy), this rule watches only the keys that control autostart, then filters on the *value* that was written: an entry pointing at a user-writable path (Public, AppData, Temp, ProgramData) or a script interpreter is what a real payload looks like.

The reason the value filter matters: the Run keys are written constantly by legitimate software (Microsoft Edge auto-launch, updaters, cleanup tasks) whose values point into `Program Files`. Without the filter the rule returns dozens of benign entries. Filtering the value down to user-writable locations and script interpreters removes that noise and leaves only the genuinely suspicious autorun entries.

## Lessons from validating against live data

The first draft of this rule returned zero results. Two things had to be corrected after looking at a real event:

1. **Sourcetype.** The Sysmon data is indexed under the sourcetype `XmlWinEventLog`, not the longer `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`. The rule now keys on `EventCode=13`, which only Sysmon emits, and drops the sourcetype filter.
2. **Case and hive prefix.** Sysmon writes registry paths in uppercase with an `HKU\<SID>\` prefix — e.g. `HKU\S-1-5-21-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater` — not `HKCU\...\Software\...`. All matching is therefore done case-insensitively with `lower()`.

A third issue turned up after the alert had been live for a day: **OneDrive is a false-positive source.** Both `OneDriveSetup.exe` (during install/update) and `OneDrive.exe` itself (registering its own autostart entry with a `/background` flag) write to the `Run`/`RunOnce` keys with a value that lives under `...\AppData\Local\Microsoft\OneDrive\...` — which matches the same `.appdata.` pattern the rule uses to catch attacker payloads, since normal user-installed software legitimately runs from AppData too. Fixed by excluding both OneDrive binaries by image name (matched with a regex so one line covers `OneDrive.exe` and `OneDriveSetup.exe`), while leaving the AppData/Temp/Public pattern match in place for everything else.

## Search (deployed alert)

```spl
index=main EventCode=13
| eval to=lower(TargetObject), dt=lower(Details), img=lower(Image)
| where like(to,"%\\currentversion\\run\\%") OR like(to,"%\\currentversion\\runonce\\%") OR like(to,"%\\currentversion\\runservices\\%") OR like(to,"%\\winlogon\\shell") OR like(to,"%\\winlogon\\userinit")
| where NOT match(img, "\\\\onedrive(setup)?\.exe$")
| where match(dt,"(users.public|.appdata.|.temp.|programdata|.ps1|.vbs|.bat|.hta|mshta|wscript|cscript|rundll32|regsvr32)")
| stats min(_time) as firstTime max(_time) as lastTime count by host, User, Image, TargetObject, Details
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

`Details` is the value that was written (the program that will run at logon); `Image` is the process that made the change; `User` the account it ran as.

### Hunting variant (triage, shows everything with a risk tag)

To review *all* autorun writes rather than only the suspicious ones — useful for baselining — drop the second `where` and tag each row instead:

```spl
index=main EventCode=13
| eval to=lower(TargetObject), dt=lower(Details)
| where like(to,"%\\currentversion\\run\\%") OR like(to,"%\\currentversion\\runonce\\%") OR like(to,"%\\currentversion\\runservices\\%") OR like(to,"%\\winlogon\\shell") OR like(to,"%\\winlogon\\userinit")
| eval risk=if(match(dt,"(users.public|.appdata.|.temp.|programdata|.ps1|.vbs|.bat|.hta|mshta|wscript|cscript|rundll32|regsvr32)"),"HIGH","REVIEW")
| stats min(_time) as firstTime max(_time) as lastTime count by host, User, Image, TargetObject, Details, risk
| convert ctime(firstTime) ctime(lastTime)
| sort risk, - lastTime
```

## Alert configuration (as deployed)

| Setting | Value |
|---|---|
| Permissions | Shared in App |
| Type | Scheduled |
| Schedule (cron) | `*/5 * * * *` (every 5 minutes) |
| Time range | Last 15 minutes (deliberate overlap so no event is missed at a boundary) |
| Trigger | Number of Results > 0, **For each result** |
| Throttle | Suppress by `TargetObject` for 3600 seconds |
| Action | Add to Triggered Alerts, Severity **High** |

## Validation

Tested end-to-end via Caldera Manual Command on 2026-08-30:

```powershell
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Force | Out-Null; Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater2" -Value "C:\Users\Public\evil.exe"
```

The scheduled alert fired (High severity). The triggering event showed `Details=C:\Users\Public\evil.exe`, `Image=...\powershell.exe`, `TargetObject=...\CurrentVersion\Run\Updater2`. Confirmed chain:

**Caldera (Manual Command) → PowerShell on the target → Registry Run key → Sysmon (Event ID 13) → Splunk → Alert.**

## Tuning notes

- Legitimate software writes Run keys at install time, but its values point into `Program Files` and so are filtered out. If a known-good app ever writes into AppData/ProgramData and trips the rule, add its `Image` to the exclusion regex (same pattern used for OneDrive).
- The throttle is keyed on `TargetObject`, so the same autorun entry won't re-alert within the hour, but any new or different entry still fires.
- Watch for more of this same class of false positive: any legitimately-installed user-scope application (not just OneDrive) that writes its own autostart entry from AppData will trip this rule until its binary is added to the exclusion regex. Treat the first few days after deployment as a tuning period.
