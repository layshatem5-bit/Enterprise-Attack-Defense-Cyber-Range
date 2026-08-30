# Ubuntu Server — Splunk SIEM

This Ubuntu server runs Splunk Enterprise and is the SIEM for the whole lab. It collects Sysmon and Windows event logs from the three Windows machines, firewall logs from OPNsense, and its own system logs, and it hosts the overview dashboard. This document covers the VM build, the Splunk install and the problems that came with it, the Universal Forwarders on the Windows side, all three log sources, and the dashboard.

## VM specifications

| Setting | Value |
|---|---|
| RAM | 8 GB |
| Disk | 100 GB |
| CPU cores | 2 |
| OS | Ubuntu Server |
| Hostname | splunk |
| Network | VMnet3 — Servers (VLAN30) |
| Interface | ens33 |
| IP address | 192.168.30.48 |
| Splunk version | 10.4.2 |

## Installation and the problems along the way

The base Ubuntu install was straightforward, but getting Splunk running took three separate fixes.

### DNS not working after first boot

Ubuntu took an address from DHCP but couldn't reach the internet (`wget: unable to resolve host address`). It cleared up on its own after I opened the OPNsense web UI directly — most likely a gateway-monitoring / ARP cache refresh on OPNsense. This is the same family of first-boot networking hiccup that showed up on the Caldera VM later.

### dpkg corruption from a power cut

While the Splunk `.deb` was downloading, there was an actual power outage in the middle of a dpkg/apt operation. It corrupted files under `/var/lib/dpkg/updates/` — some reported "Structure needs cleaning", one was a corrupted directory. Because the damage had reached the filesystem level rather than just dpkg's state, I rebuilt the Ubuntu VM from scratch instead of attempting a risky partial repair. There was no important data on it yet, so a clean reinstall was the safe choice.

### Splunk hung on first start (entropy)

After the reinstall, `splunk start` sat at "Waiting for web server" for over an hour with no progress. The cause was entropy starvation on the VM — a common problem on virtual machines — which stalled the SSL certificate generation during first boot. Fixed by installing an entropy daemon:

```
sudo apt install -y haveged
sudo systemctl enable --now haveged
```

### Running Splunk as root

Splunk refuses to run under root without being told explicitly. Since it was installed system-wide and started via `sudo`, the `--run-as-root` flag is required on every start/stop/restart:

```
sudo /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --run-as-root
```

## Installing Splunk Enterprise

Downloaded the official `.deb` from splunk.com and installed it:

```
wget -O splunk-10.4.2-33c3bf42cd73-linux-amd64.deb "https://download.splunk.com/products/splunk/releases/10.4.2/linux/splunk-10.4.2-33c3bf42cd73-linux-amd64.deb"
sudo dpkg -i splunk-10.4.2-33c3bf42cd73-linux-amd64.deb
sudo /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --run-as-root
```

Web UI available at `http://192.168.30.48:8000`.

## Static IP via Netplan

Converted `ens33` from DHCP to a fixed address so the SIEM never moves. File `/etc/netplan/00-installer-config.yaml`:

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

## Splunk Universal Forwarder on the Windows machines

The forwarder was installed manually (direct download from splunk.com) on all three Windows machines: the DC, Target_1, and Target_2. Remote install over WinRM wasn't an option because the full isolation between the Users and Servers networks blocks the management ports — that's by design.

At install time the receiving indexer was set to:

```
192.168.30.48:9997
```

Actual machine names in Active Directory:

| Name in AD | IP | Role |
|---|---|---|
| WIN-IC59S2PCTCD | 192.168.30.59 | Windows Server / DC01 |
| DESKTOP-QBQ5RET | 192.168.20.41 | Target_1 |
| DESKTOP-F6VVVUG | 192.168.20.42 | Target_2 |

### inputs.conf (identical on all three)

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

Restart the service after editing:

```
Restart-Service SplunkUniversalForwarder
```

> Sysmon itself is deployed on all three Windows machines using the Olaf Hartong `sysmon-modular` config rather than the default. It gives broader, more precise coverage than SwiftOnSecurity — DNS query logging, clear-text credential access attempts, and more detail across most event categories — which suits a lab built for detection work.

### Firewall exception for port 9997

After everything was configured, events arrived from the DC (same network as Splunk) but never from Target_1 or Target_2 on the Users network. The isolation between the Users and Servers networks was blocking port 9997 (the Splunk data channel), not just the management ports.

Rather than opening the two networks to each other, I added one narrow exception on OPNsense:

| Field | Value |
|---|---|
| Action | Pass |
| Interface | LAN (Users) |
| Protocol | TCP |
| Source | LAN net |
| Destination | 192.168.30.48 (Splunk) |
| Destination port | 9997 |
| Description | Allow Sysmon forwarders to Splunk indexer |

Placed above any general Block rule, since OPNsense matches top to bottom. Confirmed with:

```
Test-NetConnection -ComputerName 192.168.30.48 -Port 9997   # TcpTestSucceeded: True
```

---

## Log sources

Three sources feed Splunk, each in its own index.

### 1. Firewall logs from OPNsense (Syslog → UDP 514 → index=firewall)

Set up remote logging on OPNsense to send firewall events straight to Splunk.

OPNsense side (**System → Settings → Logging / Targets**):

| Setting | Value |
|---|---|
| Transport | UDP(4) |
| Applications / Levels / Facilities | Select All |
| Hostname | 192.168.30.48 (Splunk) |
| Port | 514 |
| RFC5424 | Off (RFC3164) |

The first attempt came back empty because I'd set Applications to `firewall` only while Levels/Facilities didn't match — the fields combine with AND logic, so nothing got through. Selecting **All** on all three fields opened it up.

Splunk side (**Settings → Data Inputs → UDP → New Local UDP**): port 514, source type `syslog`, into a new `firewall` index. Verified with:

```
index=firewall
```

One thing to know: the `host` field always shows the firewall's own IP (192.168.30.1) rather than the machine the event is about, because `host` represents whoever sent the syslog message. To find events involving a specific machine, search the raw text:

```
index=firewall "192.168.20.41"
```

### 2. Ubuntu system logs (File Monitoring → index=ubuntu)

Since Splunk is installed locally on this same Ubuntu box, I used File & Directory Monitoring instead of Syslog — no need to cross the network.

| File | Source type | Host | Index |
|---|---|---|---|
| /var/log/syslog | syslog | splunk (constant) | ubuntu |
| /var/log/auth.log | syslog | splunk (constant) | ubuntu |

The `ubuntu` index was created once with the first file, then selected from the list for the second.

### 3. SSH activity search (auth.log)

Tested the chain end to end by SSHing from the Windows Server to this box and confirming the event landed in Splunk:

```
ssh splunk@192.168.30.48
```

The first search returned nothing because my regex was built around the old process name `sshd`, while current OpenSSH on Ubuntu logs the process as `sshd-session`. A real raw line looks like:

```
2026-08-28T16:56:00.165936+00:00 splunk sshd-session[28025]: Accepted password for splunk from 192.168.30.59 port 52164 ssh2
```

Corrected search:

```
index=ubuntu source="/var/log/auth.log" "sshd-session"
| rex field=_raw "sshd-session\[\d+\]:\s+(?<result>Accepted|Failed)\s+\S+\s+for\s+(?:invalid user\s+)?(?<user>\S+)\s+from\s+(?<src_ip>[\d\.]+)\s+port\s+(?<src_port>\d+)"
| table _time host result user src_ip src_port
| sort -_time
```

Confirmed the correct `src_ip` (192.168.30.59 — the Windows Server) showed up in the results.

---

## Dashboard: SOC Lab Overview

Built a Classic Dashboard that pulls the key indicators from all three sources onto one page. I laid it out on a grid by editing the XML source directly rather than dragging panels around.

| Panel | Query (short) | Visualization |
|---|---|---|
| Events by Source | `tstats count where index=* by index` | Pie chart |
| Sysmon Event IDs | `index=main sourcetype=…Sysmon… \| stats count by EventCode` | Bar chart |
| Firewall Events Over Time | `index=firewall \| timechart span=1h count` | Area chart |
| Events by Host | `index=main \| stats count by host` | Column chart |
| SSH Activity (Ubuntu) | `index=ubuntu … sshd-session … \| rex …` | Table |

Layout: first row is Events by Source next to Sysmon Event IDs, second row is Firewall Events next to Events by Host, and the SSH Activity table spans the full width underneath.

## Result

- Splunk Enterprise running on a static IP (192.168.30.48:8000).
- Universal Forwarders live on the DC, Target_1, and Target_2, all sending Sysmon plus Security/System/Application logs to `index=main`.
- Firewall logs reaching `index=firewall`, Ubuntu system/auth logs reaching `index=ubuntu`.
- Network isolation preserved — the only holes are the single narrow 9997 exception and the syslog path.
- One dashboard pulling Windows, firewall, and Ubuntu data together.

## Next steps

- Turn the manual `rex` extractions into permanent field extractions.
- Add basic alerts (repeated failed SSH, suspicious Sysmon Event IDs).
