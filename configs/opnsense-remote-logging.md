# OPNsense — Remote Logging (Syslog to Splunk)

Path: **System → Settings → Logging / Targets**

| Setting | Value |
|---|---|
| Transport | UDP(4) |
| Applications / Levels / Facilities | Select All |
| Hostname (Destination) | 192.168.30.48 (Splunk) |
| Port | 514 |
| RFC5424 | Off (RFC3164) |

Note: the first attempt failed (`index=firewall` was empty) because Applications was set to `firewall` only while Levels/Facilities didn't match — the fields combine with AND logic. Selecting **All** on all three fields opens the flow completely.
