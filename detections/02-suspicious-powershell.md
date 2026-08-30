# Detection 02 — Suspicious / Encoded PowerShell

| | |
|---|---|
| MITRE ATT&CK | T1059.001 (PowerShell), T1027 (Obfuscated Files or Information) |
| Tactic | Execution, Defense Evasion |
| Data source | Sysmon Event ID 1 (Process creation) — `index=main` |
| Severity | High |
| Status | **Deployed and validated end-to-end (2026-08-30)** |

## What it detects

PowerShell is the single most abused tool on Windows, so alerting on "powershell.exe ran" is useless — it runs constantly. What separates an attack from admin work is *how* it's invoked: a hidden window, an encoded command, a download cradle, an execution-policy bypass, in-memory obfuscation. This rule scores each PowerShell process on how many of those attacker traits appear in the command line and only fires when at least two line up together, which keeps out the day-to-day noise while catching the real thing.

Pulling in `ParentImage` is what makes it strong: it shows *what launched* the PowerShell. In testing, that field surfaced `sandcat.exe` (the Caldera C2 agent) as the parent — so the rule reveals the C2 origin of the attack, not just the PowerShell process. The same works for a macro-delivered payload, where the parent would be `winword.exe` or `excel.exe`.

> Note: Sysmon data is indexed under the sourcetype `XmlWinEventLog`, and `EventCode=1` is emitted only by Sysmon — so the rule keys on `EventCode=1` and matches the image case-insensitively. (Same sourcetype/case fix that rule 01 needed after live testing.)

## Search (deployed alert)

```spl
index=main EventCode=1
| eval img=lower(Image)
| where like(img,"%\\powershell.exe") OR like(img,"%\\pwsh.exe")
| eval cl=lower(CommandLine)
| eval s_encoded  = if(match(cl,"-enc|-encodedcommand|frombase64string"),1,0)
| eval s_hidden   = if(match(cl,"-w hidden|-windowstyle hidden|-nop|-noprofile"),1,0)
| eval s_download = if(match(cl,"downloadstring|downloadfile|invoke-webrequest|net.webclient|invoke-restmethod|start-bitstransfer|certutil"),1,0)
| eval s_execute  = if(match(cl,"invoke-expression|iex |-executionpolicy bypass|-ep bypass"),1,0)
| eval s_obfusc   = if(match(cl,"-join|reflection.assembly|-bxor|-encodedarguments"),1,0)
| eval score = s_encoded + s_hidden + s_download + s_execute + s_obfusc
| where score >= 2
| stats min(_time) as firstTime max(_time) as lastTime max(score) as score values(CommandLine) as CommandLine by host, User, ParentImage
| convert ctime(firstTime) ctime(lastTime)
| sort - score, - lastTime
```

Each `s_*` field is one category of suspicious behavior; `score` is how many categories the command line hit. The `where score >= 2` is what keeps normal admin PowerShell out.

## Alert configuration (as deployed)

| Setting | Value |
|---|---|
| Permissions | Shared in App |
| Type | Scheduled |
| Schedule (cron) | `*/5 * * * *` (every 5 minutes) |
| Time range | Last 15 minutes |
| Trigger | Number of Results > 0, **For each result** |
| Throttle | Suppress by `host` for 900 seconds |
| Action | Add to Triggered Alerts, Severity **High** |

Treat `score >= 3` as page-worthy; `score = 2` is triage.

## Validation

Tested via Caldera Manual Command on 2026-08-30 — a harmless base64 command (`Write-Host "detection test"`) run with a hidden window, no-profile, and an execution-policy bypass:

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAZABlAHQAZQBjAHQAaQBvAG4AIAB0AGUAcwB0ACIA
```

Result: the event matched with `score = 3` (encoded + hidden/noprofile + bypass). The `ParentImage` chain showed **`C:\Users\Public\sandcat.exe` → `powershell.exe`**, i.e. the Caldera agent spawning the encoded PowerShell — the rule surfaced the C2 origin, not just the PowerShell process.

## Tuning notes

- Some legitimate management tooling (SCCM, backup agents, GPO logon scripts) uses `-nop -w hidden`. A single indicator only scores 1, below the threshold, so those stay quiet. If a real job ever combines two indicators and trips the rule, exclude it by `ParentImage` rather than lowering the threshold.
- `certutil` in the download group is intentional — it's a common living-off-the-land downloader. If admins use it for real certificate work, split it into its own lower-severity rule.
