# SOC Home Lab

A segmented security lab built in VMware Workstation for hands-on detection engineering and purple-team practice. It runs a small Active Directory environment behind an OPNsense firewall, monitors the Windows hosts with Sysmon, ships everything into Splunk as the SIEM, and uses MITRE Caldera to generate real attack activity and verify that it gets detected.

Everything here is documented step by step — how each machine was built, how the network is segmented and why, and every problem hit along the way with how it was solved.

## Architecture

### Networks (behind OPNsense)

| Network | VLAN / Subnet | VMware adapter | Purpose |
|---|---|---|---|
| WAN | Home network (DHCP) | Bridged | Internet uplink |
| Users | VLAN20 — 192.168.20.0/24 | VMnet2 | Windows client workstations |
| Servers | VLAN30 — 192.168.30.0/24 | VMnet3 | DC, Splunk, Caldera |
| Attack | VLAN40 — 192.168.40.0/24 | VMnet4 | Offensive box (isolated by default) |

The three internal networks are isolated from each other by default. The only paths that exist are the specific ones Active Directory needs (Users → Servers on the AD ports), the Splunk data channel (TCP 9997), and the Caldera C2 channel (TCP 8888) — each one a single narrow firewall rule.

### Machines

| Machine | Network | IP | Specs | Role |
|---|---|---|---|---|
| OPNsense | all | gateways (.1) | 2 GB / 20 GB / 1 core | Firewall & router |
| Windows Server (DC01) | Servers | 192.168.30.59 | 4 GB / 60 GB / 2 cores | Domain Controller (laith.local), DNS |
| Target_1 | Users | 192.168.20.41 | 3 GB / 30 GB / 1 core | Windows 10 client |
| Target_2 | Users | 192.168.20.42 | 3 GB / 30 GB / 1 core | Windows 10 client |
| Ubuntu (Splunk) | Servers | 192.168.30.48 | 8 GB / 100 GB / 2 cores | Splunk SIEM |
| Caldera | Servers | 192.168.30.35 | 2 GB / 30 GB / 1 core | Adversary emulation |

Host: 32 GB RAM total, VMware Workstation.

## Repository layout

```
vmware/     Step-by-step build guide for every machine
  01-opnsense-firewall.md      Install, networks, all firewall rules + reasoning, DHCP troubleshooting
  02-windows-server-dc.md      Install, DC promotion, OUs, users, groups
  03-target-1.md               Install, domain join
  04-target-2.md               Install, domain join
  05-ubuntu-splunk-siem.md     Splunk install, forwarders, log sources, dashboard
  06-caldera.md                Caldera install, agents, first purple-team test
configs/    Copy-paste config reference (inputs.conf, netplan, dashboard queries, Caldera commands)
```

## Data flow

```
Windows hosts (Sysmon + Windows logs) ─┐
OPNsense (firewall syslog) ────────────┤──▶ Splunk (SIEM) ──▶ SOC Lab Overview dashboard
Ubuntu (system / auth logs) ───────────┘
Caldera ──▶ PowerShell on target ──▶ Registry/behavior ──▶ Sysmon ──▶ Splunk
```

## Status

Base lab complete: AD stood up, network fully segmented, Sysmon on all Windows hosts, Splunk collecting Windows/firewall/Ubuntu logs, dashboard live, and Caldera proven end to end (a Registry persistence technique executed and confirmed as Sysmon Event ID 13 in Splunk).

Next: build out full purple-team scenarios (APT emulation, ransomware, insider threat), each documented as its own Incident Response report, and add permanent field extractions and alerts.

## Security note

This repo is private because it contains internal network layout (IP addressing). It contains no passwords and no VM disk files — see `.gitignore`. If it's ever shared more widely, review the files and mask any real addresses first.
