# Detection 04 — Privileged Group Modification

| | |
|---|---|
| MITRE ATT&CK | T1098 (Account Manipulation), T1078.002 (Valid Accounts: Domain Accounts) |
| Tactic | Privilege Escalation, Persistence |
| Data source | Windows Security log — `index=main` (logged on the Domain Controller) |
| Severity | High |

## What it detects

Once an attacker has a foothold, adding an account they control to **Domain Admins** (or another privileged group) gives them durable, high-level access that blends in with normal admin activity. Active Directory logs every group-membership change on the Domain Controller — Event ID 4728 (global group), 4732 (local group), and 4756 (universal group). This rule watches those events and fires only when the group involved is one of the privileged ones, so routine additions to ordinary groups stay quiet.

In a real environment, someone joining Domain Admins should be a known, ticketed change. Anything that isn't is either a mistake or an intrusion — both worth an alert.

## Search

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
Group_Name IN ("Domain Admins","Enterprise Admins","Administrators","Schema Admins","Account Operators","Backup Operators","Server Operators")
| stats min(_time) as firstTime max(_time) as lastTime count by host, EventCode, Group_Name, Member_Name, Account_Name
| rename Group_Name AS group, Member_Name AS account_added, Account_Name AS performed_by
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

`account_added` is who was put into the group; `performed_by` is the account that made the change.

> **Field-name note:** the Windows Security log's field names depend on how the events are parsed. If `Group_Name` / `Member_Name` don't populate, run the base search (`index=main sourcetype="WinEventLog:Security" EventCode=4728`), open one event, and read the exact field names off it. The clean fix is to render these events as XML — add `renderXml=true` under the `[WinEventLog://Security]` stanza in `inputs.conf` on the DC, which gives stable fields (`TargetUserName` = group, `MemberName` = account added, `SubjectUserName` = performed by). Installing the **Splunk Add-on for Microsoft Windows** normalizes them too.

## Alert configuration

| Setting | Value |
|---|---|
| Type | Scheduled |
| Schedule (cron) | `*/10 * * * *` |
| Time range | Last 10 minutes |
| Trigger | Number of results > 0 |
| Throttle | By `group`, `account_added` for 1 hour |

## How to test

On the DC, add a test user to Domain Admins, then remove it:

```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members user1
# verify the alert fired, then clean up:
Remove-ADGroupMember -Identity "Domain Admins" -Members user1 -Confirm:$false
```

Event ID 4728 should appear on the DC and the rule should fire naming `user1` as `account_added`.

## Tuning notes

- Keep a short allowlist of accounts that are *supposed* to perform these changes (your break-glass admin). An addition performed by anything outside that list is the higher-severity case.
- This rule depends on the DC forwarding its Security log to Splunk — which the Universal Forwarder already does via the `[WinEventLog://Security]` input. If it ever goes quiet, confirm the forwarder on the DC is still running.
