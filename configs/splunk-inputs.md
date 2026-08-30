# Splunk — Inputs & Netplan Reference

Quick copy-paste reference for the Splunk-side configuration. Full narrative is in `vmware/05-ubuntu-splunk-siem.md`.

## Universal Forwarder — inputs.conf (all three Windows machines)

Path: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = main
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

[WinEventLog://Security]
disabled = false
index = main

[WinEventLog://System]
disabled = false
index = main

[WinEventLog://Application]
disabled = false
index = main
```

Receiving indexer set at install time: `192.168.30.48:9997`

Restart the service after editing:

```
Restart-Service SplunkUniversalForwarder
```

## Ubuntu file monitoring (local)

| File | Source type | Host | Index |
|---|---|---|---|
| /var/log/syslog | syslog | splunk (constant) | ubuntu |
| /var/log/auth.log | syslog | splunk (constant) | ubuntu |

## Static IP — Netplan

File: `/etc/netplan/00-installer-config.yaml`

```yaml
network:
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.30.48/24
      routes:
        - to: default
          via: 192.168.30.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 1.1.1.1
  version: 2
```

```
sudo netplan apply
```

## SSH activity search (auth.log)

Current OpenSSH logs the process as `sshd-session`, not `sshd`:

```
index=ubuntu source="/var/log/auth.log" "sshd-session"
| rex field=_raw "sshd-session\[\d+\]:\s+(?<result>Accepted|Failed)\s+\S+\s+for\s+(?:invalid user\s+)?(?<user>\S+)\s+from\s+(?<src_ip>[\d\.]+)\s+port\s+(?<src_port>\d+)"
| table _time host result user src_ip src_port
| sort -_time
```
