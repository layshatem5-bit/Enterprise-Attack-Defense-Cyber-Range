# Detection 04 — Privileged Group Modification

| | |
|---|---|
| MITRE ATT&CK | T1098 (Account Manipulation), T1078.002 (Valid Accounts: Domain Accounts) |
| Tactic | Privilege Escalation, Persistence |
| Data source | Windows Security log — `index=main` (logged on the Domain Controller) |
| Severity | High |
| Status | **Deployed and validated end-to-end (2026-08-31)** |

## What it detects

Once an attacker has a foothold, adding an account they control to **Domain Admins** (or another privileged group) gives them durable, high-level access that blends in with normal admin activity. Active Directory logs every group-membership change on the Domain Controller — Event ID 4728 (global group), 4732 (local group), and 4756 (universal group). This rule watches those events and fires only when the group involved is one of the privileged ones, so routine additions to ordinary groups stay quiet.

In a real environment, someone joining Domain Admins should be a known, ticketed change. Anything that isn't is either a mistake or an intrusion — both worth an alert.

## Lessons from validating against live data

The original draft assumed Splunk would auto-parse this event into clean fields (`Group_Name`, `Member_Name`, `Account_Name`) with a `WinEventLog:Security` sourcetype. Neither held up once tested against a real event:

1. **Sourcetype.** The real sourcetype is just `WinEventLog` (not `WinEventLog:Security`) — the same class of bug rules 01 and 03 hit. `LogName=Security` is used instead to isolate the Security channel, since the generic sourcetype no longer encodes which log it came from.
2. **Field-name collision.** The raw Windows message text uses the label **"Account Name:"** twice — once under `Subject` (who made the change) and once under `Member` (who was added) — so Splunk's automatic key/value extraction produces an unreliable, potentially multivalued field instead of two distinct ones. The fix is to skip automatic extraction and pull each value directly out of `_raw` with `rex`, anchored to the `Subject:` / `Group:` / `Member:` section headers in the message text so each regex only matches within its own section.

## Search (deployed alert)

```spl
index=main sourcetype="WinEventLog" LogName=Security (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| rex field=_raw "(?s)Subject:.*?Account Name:\s+(?<performed_by>\S+)"
| rex field=_raw "(?s)Group:.*?Group Name:\s+(?<group>[^\r\n]+)"
| rex field=_raw "(?s)Member:.*?Account Name:\s+(?<account_added>[^\r\n]+)"
| where group IN ("Domain Admins","Enterprise Admins","Administrators","Schema Admins","Account Operators","Backup Operators","Server Operators")
| stats min(_time) as firstTime max(_time) as lastTime count by host, EventCode, group, account_added, performed_by
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

`account_added` is who was put into the group (as a full distinguished name, e.g. `CN=Ali Ali,OU=Standart Users,DC=laith,DC=local`); `performed_by` is the account that made the change.

## Alert configuration (as deployed)

| Setting | Value |
|---|---|
| Type | Scheduled |
| Schedule (cron) | `*/10 * * * *` |
| Time range | Last 10 minutes |
| Trigger | Number of results > 0 |
| Throttle | By `group`, `account_added` for 1 hour |
| Action | Add to Triggered Alerts, Severity **High** |

## Validation

Tested end-to-end on the Domain Controller on 2026-08-31:

```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members user1
```

Event ID 4728 was logged immediately with `Group Name: Domain Admins`, `Member: Account Name: CN=Ali Ali,OU=Standart Users,DC=laith,DC=local`, and `Subject: Account Name: Administrator`. The alert fired correctly and named the added account. Confirmed chain:

**PowerShell (`Add-ADGroupMember`) on the DC → AD group membership change → Windows Security log (Event ID 4728) → Splunk → Alert.**

The test account was removed immediately after confirming the alert:

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members user1 -Confirm:$false
```

## Tuning notes

- Keep a short allowlist of accounts that are *supposed* to perform these changes (your break-glass admin). An addition performed by anything outside that list is the higher-severity case.
- This rule depends on the DC forwarding its Security log to Splunk via the `[WinEventLog://Security]` input. It also depends on Windows actually auditing this activity — confirm with `auditpol /get /subcategory:"Security Group Management"` and enable it with `auditpol /set /subcategory:"Security Group Management" /success:enable` if it isn't already.
- If the DC's `inputs.conf` `[default]` stanza has a `host` value that differs from what other log sources use (this happened here — one stanza had a stray, inconsistent host name), Security-log events will index under a different host than expected. Keep `host` consistent across all stanzas for the same machine.
