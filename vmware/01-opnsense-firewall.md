# OPNsense Firewall & Router

OPNsense is the core of the lab. Every other machine sits behind it, and it enforces the segmentation between the three internal networks. This document covers how the VM was built, how the networks are laid out, every firewall rule and the reason it exists, and the problems I hit along the way.

## VM specifications

| Setting | Value |
|---|---|
| RAM | 2 GB |
| Disk | 20 GB |
| CPU cores | 1 |
| OPNsense version | 26.7 |
| Network adapters | 4 (1 WAN + 3 internal) |

## Installation

1. Downloaded the OPNsense `dvd` image (amd64) from the official mirror and unpacked it to an ISO.
2. Created a new VM in VMware Workstation, type "FreeBSD 64-bit", and attached the ISO to the virtual CD drive.
3. Added four network adapters before first boot (see the mapping table below) — the interface order in VMware matches the order OPNsense detects them, so getting this right up front avoids reassigning later.
4. Booted the installer, logged in with the default `installer` / `opnsense` account, and ran the guided install to the 20 GB disk (UFS).
5. Set the root password when prompted and rebooted from disk.

## Network design

The lab is split into four networks. WAN is the only one that touches the real home network; the three internal networks are fully isolated from each other by default and only opened where a real service needs it.

| Network | VLAN / Subnet | VMware adapter | OPNsense interface | Gateway | Purpose |
|---|---|---|---|---|---|
| WAN | Home network (DHCP) | Bridged | le0 | — | Uplink to the home router for internet access. Bridged so the firewall pulls a real DHCP lease from the home router. |
| Users (LAN) | VLAN20 — 192.168.20.0/24 | VMnet2 | le1 | 192.168.20.1 | Regular Windows client machines (Target_1, Target_2). This is the "employee" side of the network. |
| Servers | VLAN30 — 192.168.30.0/24 | VMnet3 | le2 | 192.168.30.1 | Domain Controller, Splunk, and Caldera. The sensitive infrastructure. |
| Attack | VLAN40 — 192.168.40.0/24 | VMnet4 | le3 | 192.168.40.1 | Reserved for an offensive box (Kali). Isolated from everything by default. |

A short explanation of each:

- **Users** holds the machines a normal employee would use. They need to authenticate against the domain and reach the internet, but nothing else.
- **Servers** holds the infrastructure that everyone depends on. It should answer requests that come from Users, but it should never start a connection back into the Users network on its own.
- **Attack** is where an offensive machine lives. It stays completely walled off until an exercise deliberately opens a hole for it.
- **WAN** is bridged straight to the home router, so the whole lab reaches the internet through it while staying invisible from the outside.

### VMware adapter mapping

| Adapter | VMware setting | Becomes |
|---|---|---|
| Network Adapter 1 | Bridged | WAN (le0) |
| Network Adapter 2 | Custom → VMnet2 | Users / LAN (le1) |
| Network Adapter 3 | Custom → VMnet3 | Servers (le2) |
| Network Adapter 4 | Custom → VMnet4 | Attack (le3) |

## Interface configuration

After the install, I assigned the interfaces from the console and gave each internal interface a static gateway address:

- **WAN (le0):** DHCP client — takes its address from the home router.
- **Users (le1):** 192.168.20.1 / 24
- **Servers (le2):** 192.168.30.1 / 24
- **Attack (le3):** 192.168.40.1 / 24

The rest of the configuration was done from the web UI at `https://192.168.20.1` after connecting a client to the Users network.

## DHCP (Dnsmasq)

DHCP and DNS for the internal networks are handled by Dnsmasq. Each internal interface has its own address pool:

| Interface | DHCP range |
|---|---|
| Users (LAN) | 192.168.20.30 – 192.168.20.60 |
| Servers | 192.168.30.30 – 192.168.30.60 |
| Attack | 192.168.40.30 – 192.168.40.60 |

Important: under **Services → Dnsmasq DNS & DHCP → General**, the **Interface** field must list every interface Dnsmasq is allowed to serve. If an interface is missing from that list, Dnsmasq silently ignores DHCP requests on it even though everything else looks fine. This bit me hard — see the troubleshooting section at the end.

---

## Firewall rules

### Design goal

Out of the box, each internal interface only had its auto-generated "allow this network to any" rule, which means the networks were separated in name only — any network could reach any other. The goal here was real segmentation:

- Users cannot reach other Users directly (limit lateral movement).
- Users can reach Servers only on the specific ports Active Directory needs, nothing else.
- Servers never open new connections toward Users (they only answer what Users started).
- The Attack network is fully isolated in both directions, including from the internet, and is only opened deliberately during an exercise.

### Alias: AD_Services_Ports

Built under **Firewall → Aliases** as a Port alias so the AD ports live in one place instead of being repeated across rules.

| Port(s) | Service | Why it's needed |
|---|---|---|
| 53 | DNS | Name resolution for laith.local and the internet |
| 88 | Kerberos | Domain authentication |
| 123 | NTP | Time sync — Kerberos fails if the clocks drift too far apart |
| 135 | RPC Endpoint Mapper | Initial RPC negotiation |
| 389 | LDAP | Directory queries |
| 445 | SMB | Group Policy retrieval, file/print, logon scripts |
| 49152–65535 | RPC dynamic range | The actual RPC calls after port 135 hands them off. Required for domain logon and GPO to finish — see the logon-hang issue below. |

### Users (LAN) interface — rules top to bottom

| # | Action | Source | Destination | Protocol / Port | Purpose |
|---|---|---|---|---|---|
| 1 | Block | LAN net | LAN net | Any | Intended user-to-user isolation. Note: this does not actually work at the firewall level for same-subnet traffic — kept as documented intent (see issue 1). |
| 2 | Pass | LAN net | Servers net | TCP/UDP — AD_Services_Ports | Allow only the AD ports toward Servers |
| 3 | Block | LAN net | Servers net | Any | Deny everything else toward Servers (RDP, random ports, etc.) |
| 4 | Block | LAN net | Attack net | Any | Users must never reach the Attack network |
| 5 | Pass (auto) | LAN net | any (IPv4) | Any | Everything not matched above — effectively internet access |
| 6 | Pass (auto) | LAN net | any (IPv6) | Any | Same, IPv6 |

### Servers interface — rules top to bottom

| # | Action | Source | Destination | Protocol / Port | Purpose |
|---|---|---|---|---|---|
| 1 | Block | Servers net | Attack net | Any | Servers must never reach the Attack network |
| 2 | Block | Servers net | LAN net | Any | Servers must not start new connections toward Users. Replies to sessions Users started still flow — the firewall is stateful. |
| 3 | Pass (auto) | Servers net | any | Any | Everything else — internet access for the DC (Windows Update, etc.) |

The two Block rules were originally added *below* the auto-generated Pass rule, which silently made them do nothing (first match wins). I caught it by comparing all four interface tabs side by side — see issue 2.

### Attack interface

| # | Action | Source | Destination | Protocol / Port | Purpose |
|---|---|---|---|---|---|
| 1 | Block | Attack net | LAN net | Any | Attack cannot reach Users |
| 2 | Block | Attack net | Servers net | Any | Attack cannot reach Servers |

There is no "allow to any" rule on this interface at all — none was auto-generated for it. Combined with OPNsense's default-deny, the Attack network currently has zero access anywhere: not to Users, not to Servers, and not to the internet. That is intentional. A Kali box sitting behind a bridged WAN must never accept unsolicited inbound traffic from the real internet, and it should not have standing outbound internet access either. When it genuinely needs to update tooling, I add a temporary "Allow Attack net → WAN (outbound)" rule and remove it afterward.

### WAN interface

No rules. By default this blocks every inbound connection from the internet, which is exactly what I want — nothing in this lab should be reachable from outside. WAN rules only govern inbound traffic anyway; restricting where internal hosts can go on the internet belongs on the source interface, not on WAN.

---

## Issues hit while building this

### 1. The user-to-user block does nothing (and that's networking, not a mistake)

After adding "Block LAN net → LAN net" and applying it, Target_1 could still ping Target_2.

The reason: both machines sit on the same Layer 2 segment (same VMnet2 switch, same 192.168.20.0/24 subnet). Traffic between two hosts on the same subnet is switched directly between them and never reaches the OPNsense interface, so no firewall rule ever sees it. A router/firewall only filters traffic that crosses between subnets.

Real user-to-user isolation on a flat subnet therefore can't be done with router ACLs. It needs host-based firewalling (Windows Defender Firewall on each machine, ideally pushed through Group Policy now that AD exists), or splitting each client into its own subnet. I left the OPNsense rule in place as documented intent, but the actual enforcement is a separate task on the Windows side.

### 2. Server rules silently ineffective because of order

The two new Block rules on the Servers interface were added after the pre-existing allow-all rule. OPNsense evaluates top to bottom and stops at the first match, so the old allow-all caught everything first and the Block rules never fired — no error, no warning, they just looked correct and did nothing.

Fix: dragged both Block rules above the allow-all rule, then verified by comparing the full rule list on all four interfaces side by side rather than trusting each rule in isolation. The lesson: on any interface that already has a broad allow rule, position matters as much as content, so always check where a rule lands after saving.

### 3. Domain logon hung on "Welcome" after locking down Users → Servers

After enabling the "Block LAN → Servers (anything not in AD_Services_Ports)" rule, signing into Target_1 with a domain account got stuck on the "Welcome" screen during profile load.

I confirmed the block was the cause by temporarily disabling it — logon proceeded immediately. The problem was that the alias was missing a port the logon process needs. Port 135 (RPC Endpoint Mapper) only negotiates which port the real RPC call will use next; that call then happens on a port from the Windows dynamic RPC range (49152–65535 on modern Windows). Allowing only 135 let the negotiation succeed but blocked the follow-up call, which hung the profile load with no clear error.

Fix: added 49152–65535 to the AD_Services_Ports alias, re-enabled the block, and retested — logon completed normally. In production I'd instead pin the DC to a single fixed RPC port with a registry change so only one port needs opening, but for the lab the full range is fine.

### 4. Clients (and later the DC) stopped getting DHCP leases

This one took a while. Target_1 and Target_2 on the Users network stopped getting IP addresses and fell back to APIPA (169.254.x.x). Later the same day the DC on the Servers network started failing the same way, and it survived a full OPNsense reboot.

I ruled out everything obvious first: the DHCP ranges were correct, the firewall was passing the DHCP packets (visible in the live log as "allow access to DHCP server"), `tcpdump` on the interface confirmed the DISCOVER packets were arriving, and the Dnsmasq process was alive and bound to port 67. Two separate root causes turned up:

- **A stale Dnsmasq process** (running as `nobody`) was still holding UDP port 67, so every restart of the service silently failed to bind the socket. Running `dnsmasq --no-daemon` by hand exposed the real error: `failed to bind DHCP server socket: Address already in use`. Fixed by finding the PID with `sockstat -4 -l | grep ':67'`, killing it, and starting the service cleanly with `configctl dnsmasq start`.

- **The real final cause:** under **Services → Dnsmasq → General → Interface**, only "LAN" was selected. "Servers" and "Attack" were not. Dnsmasq only answers DHCP/DNS on interfaces explicitly checked in that list — everything else in the path can be perfectly correct and it still won't respond. That is exactly why the Users network worked all day while the Servers network intermittently failed. Fixed by checking all three internal interfaces (LAN, Servers, Attack — WAN left unchecked) and applying.

Quick recovery procedure for next time:

```
# From the OPNsense console shell:
ps aux | grep dnsmasq                 # if only the grep line shows, the service is dead
sockstat -4 -l | grep ':67'           # find the stale PID holding the socket
kill -9 <PID>
configctl dnsmasq start
ps aux | grep dnsmasq                 # confirm a real process is running
# then on the client: ipconfig /release && ipconfig /renew
```

And check the **Interface** selection list first — that's the fastest thing to rule out.

## Open items

- User-to-user isolation still needs Windows Firewall rules pushed through Group Policy.
- The Attack network has no internet access by design — add a temporary outbound rule only when tooling needs updating, then remove it.
- Consider pinning the DC to a fixed RPC port instead of opening the whole dynamic range.
- Suricata (IDS/IPS) is not deployed yet; it will eventually handle content-aware outbound filtering.
