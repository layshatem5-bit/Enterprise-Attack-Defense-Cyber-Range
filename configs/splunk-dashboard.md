# Splunk Dashboard — SOC Lab Overview

Classic Dashboard laid out on a grid by editing the XML source directly. Full narrative is in `vmware/05-ubuntu-splunk-siem.md`.

| Panel | Query | Visualization |
|---|---|---|
| Events by Source | `tstats count where index=* by index` | Pie chart |
| Sysmon Event IDs | `index=main sourcetype=…Sysmon… \| stats count by EventCode` | Bar chart |
| Firewall Events Over Time | `index=firewall \| timechart span=1h count` | Area chart |
| Events by Host | `index=main \| stats count by host` | Column chart |
| SSH Activity (Ubuntu) | see `splunk-inputs.md` (sshd-session rex) | Table |

Layout: row 1 is Events by Source next to Sysmon Event IDs, row 2 is Firewall Events next to Events by Host, and the SSH Activity table spans the full width underneath.
