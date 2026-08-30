# Detection Rules

Detection content for the lab's Splunk SIEM. Each rule targets a specific attacker technique, is tuned to keep false positives down, maps to MITRE ATT&CK, and comes with a safe way to test it. The rules deliberately span four different tactics so the coverage isn't lopsided toward one stage of an attack.

| # | Detection | Tactic | ATT&CK | Data source | Severity | Status |
|---|---|---|---|---|---|---|
| 01 | [Registry Run Key Persistence](01-registry-run-key-persistence.md) | Persistence | T1547.001 | Sysmon EID 13 | High | **Deployed & validated** |
| 02 | [Suspicious / Encoded PowerShell](02-suspicious-powershell.md) | Execution, Defense Evasion | T1059.001, T1027 | Sysmon EID 1 | High | **Deployed & validated** |
| 03 | [LSASS Credential Access](03-lsass-credential-access.md) | Credential Access | T1003.001 | Sysmon EID 10 | Critical | **Deployed & validated** |
| 04 | [Privileged Group Modification](04-privileged-group-modification.md) | Privilege Escalation, Persistence | T1098, T1078.002 | Windows Security 4728/4732/4756 | High | Ready |

## Turning a search into an alert in Splunk

For each rule:

1. Paste the search into **Search & Reporting** and confirm it returns what you expect over a wide time range first.
2. **Save As → Alert.**
3. Set **Alert type: Scheduled** and use the cron schedule and time range from the rule's page.
4. **Trigger condition: Number of Results > 0.**
5. Set **Throttle** with the fields and window listed on the rule's page, so the same event doesn't alert repeatedly.
6. Add an action — for the lab, "Add to Triggered Alerts" (and optionally email) is enough.
7. Set the **Severity** to match the rule.

## The purple-team loop

These rules are meant to be *tested*, not just saved:

1. Stand up the rule as an alert.
2. Run the technique from Caldera (or the manual test on each rule's page).
3. Confirm the alert fires. If it doesn't, you've found a detection gap — fix the logic or the data source and try again.
4. Write the exercise up as an Incident Response report.

## Environment notes learned while deploying

- **Sysmon sourcetype:** Sysmon events land under the sourcetype `XmlWinEventLog` (not the long `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` name that the forwarder input specifies). The Sysmon rules therefore key on the Sysmon-only `EventCode` (13, 1, 10) instead of the sourcetype.
- **Registry paths are uppercase with an `HKU\<SID>\` prefix** (e.g. `HKU\...\SOFTWARE\...\CurrentVersion\Run\...`), so path matching is done case-insensitively with `lower()`.
- **Host naming is currently inconsistent** — the same physical machine appears under two names (its real computer name like `DESKTOP-F6VVVUG`, and a forwarder-set name like `target_2`), and the friendly labels don't line up cleanly with the VMware library labels. This doesn't affect detection logic but makes attribution confusing; standardising each host to one name across the forwarder, Caldera, and VMware is a pending cleanup task.

## Environment notes learned while deploying (continued)

- **GrantedAccess is case-sensitive in Splunk string comparisons.** Sysmon logs it uppercase (e.g. `0x1FFFFF`); a filter list written in lowercase silently drops real matches. Always `lower()` a raw Windows field before comparing it against a literal list — this bit both rule 01 (registry paths) and rule 03 (access masks).
- **PowerShell routinely opens a handle to `lsass.exe`** with a weak access mask (`0x1410`) and an `UNKNOWN` frame in `CallTrace`, purely from resolving a SID to a username. This is confirmed-benign baseline noise on every host — a naive "any access mask + unknown callstack" rule pages constantly. Rule 03 only trusts the weak-mask/unknown-callstack combination when the source process is *not* PowerShell; a genuinely dump-capable access mask still alerts regardless of source.

## Recommended add-ons

For clean, CIM-compliant field names — especially on the Windows Security events in rule 04 — install the **Splunk Add-on for Microsoft Sysmon** and the **Splunk Add-on for Microsoft Windows** on the Splunk server.
