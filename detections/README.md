# Detection Rules

Detection content for the lab's Splunk SIEM. Each rule targets a specific attacker technique, is tuned to keep false positives down, maps to MITRE ATT&CK, and comes with a safe way to test it. The rules deliberately span four different tactics so the coverage isn't lopsided toward one stage of an attack.

| # | Detection | Tactic | ATT&CK | Data source | Severity |
|---|---|---|---|---|---|
| 01 | [Registry Run Key Persistence](01-registry-run-key-persistence.md) | Persistence | T1547.001 | Sysmon EID 13 | Medium–High |
| 02 | [Suspicious / Encoded PowerShell](02-suspicious-powershell.md) | Execution, Defense Evasion | T1059.001, T1027 | Sysmon EID 1 | High |
| 03 | [LSASS Credential Access](03-lsass-credential-access.md) | Credential Access | T1003.001 | Sysmon EID 10 | Critical |
| 04 | [Privileged Group Modification](04-privileged-group-modification.md) | Privilege Escalation, Persistence | T1098, T1078.002 | Windows Security 4728/4732/4756 | High |

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

## Recommended add-ons

Field extraction already works for the Sysmon events (the sourcetype is set explicitly on the forwarder). For clean, CIM-compliant field names — especially on the Windows Security events in rule 04 — install the **Splunk Add-on for Microsoft Sysmon** and the **Splunk Add-on for Microsoft Windows** on the Splunk server.
