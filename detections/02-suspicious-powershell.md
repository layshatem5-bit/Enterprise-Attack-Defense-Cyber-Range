# Detection 02 — Suspicious / Encoded PowerShell

| | |
|---|---|
| MITRE ATT&CK | T1059.001 (PowerShell), T1027 (Obfuscated Files or Information) |
| Tactic | Execution, Defense Evasion |
| Data source | Sysmon Event ID 1 (Process creation) — `index=main` |
| Severity | High |

## What it detects

PowerShell is the single most abused tool on Windows, so alerting on "powershell.exe ran" is useless — it runs constantly. What separates an attack from admin work is *how* it's invoked: a hidden window, an encoded command, a download cradle, an execution-policy bypass, in-memory obfuscation. This rule scores each PowerShell process on how many of those attacker traits appear in the command line and only fires when at least two line up together, which keeps out the day-to-day noise while catching the real thing.

Pulling in `ParentImage` is what makes it strong: `winword.exe` or `excel.exe` spawning an encoded PowerShell is a textbook macro-delivered payload, and this rule surfaces that parent every time.

## Search

> Note: Sysmon data is indexed under the sourcetype `XmlWinEventLog`, and `EventCode=1` is emitted only by Sysmon — so the rule keys on `EventCode=1` and matches the image case-insensitively. (This is the same sourcetype/case fix that rule 01 needed after live testing.)

```spl
index=main EventCode=1
| eval img=lower(Image)
| where like(img,"%\\powershell.exe") OR like(img,"%\\pwsh.exe")
| eval cl=lower(CommandLine)
| eval s_encoded  = if(match(cl, "-enc|-encodedcommand|frombase64string"), 1, 0)
| eval s_hidden   = if(match(cl, "-w hidden|-windowstyle hidden|-nop|-noprofile"), 1, 0)
| eval s_download = if(match(cl, "downloadstring|downloadfile|invoke-webrequest|net\.webclient|invoke-restmethod|start-bitstransfer|certutil"), 1, 0)
| eval s_execute  = if(match(cl, "invoke-expression|iex |-executionpolicy bypass|-ep bypass"), 1, 0)
| eval s_obfusc   = if(match(cl, "\[char\]|-join|reflection\.assembly|\$env:|-bxor"), 1, 0)
| eval score = s_encoded + s_hidden + s_download + s_execute + s_obfusc
| where score >= 2
| stats min(_time) as firstTime max(_time) as lastTime max(score) as score values(CommandLine) as CommandLine by host, User, ParentImage
| convert ctime(firstTime) ctime(lastTime)
| sort - score, - lastTime
```

## Alert configuration

| Setting | Value |
|---|---|
| Type | Scheduled |
| Schedule (cron) | `*/5 * * * *` |
| Time range | Last 5 minutes |
| Trigger | Number of results > 0 |
| Throttle | By `host`, `ParentImage` for 15 minutes |

Treat `score >= 3` as page-worthy; `score = 2` is triage.

## How to test

Run a harmless encoded command through Caldera or local PowerShell — this is `Write-Host "detection test"` base64-encoded, with hidden window and bypass:

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAZABlAHQAZQBjAHQAaQBvAG4AIAB0AGUAcwB0ACIA
```

That hits encoded + hidden + noprofile + bypass, so it fires with a high score.

## Tuning notes

- Some legitimate management tooling (SCCM, backup agents, GPO logon scripts) uses `-nop -w hidden`. If a known job trips the rule, exclude it by `ParentImage` rather than weakening the score threshold.
- `certutil` in the download group is intentional — it's a common living-off-the-land downloader. If your admins use it for real certificate work, split it into its own lower-severity rule.
