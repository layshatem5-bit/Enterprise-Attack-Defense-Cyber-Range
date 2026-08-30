# Target_2 — Windows 10 Client

Target_2 is the second "employee" workstation on the Users network. It's built and configured identically to Target_1 — domain-joined Windows 10, monitored by Sysmon, and running a Caldera agent during exercises.

## VM specifications

| Setting | Value |
|---|---|
| RAM | 3 GB |
| Disk | 30 GB |
| CPU cores | 1 |
| OS | Windows 10 Pro |
| Network | VMnet2 — Users (VLAN20) |
| IP address | 192.168.20.42 |
| Machine name (AD) | DESKTOP-F6VVVUG |

## Installation

1. Created the VM in VMware Workstation with the specs above and attached the Windows 10 ISO.
2. Ran a standard Windows 10 Pro install.
3. Attached the network adapter to VMnet2 so the machine lands on the Users network.
4. Let it pull an address from DHCP (192.168.20.42 from the Users pool).

## Network configuration

Same as Target_1 — the client must use the Domain Controller for DNS, not the firewall:

| Setting | Value |
|---|---|
| IP address | 192.168.20.42 (DHCP) |
| Gateway | 192.168.20.1 (OPNsense — Users interface) |
| Preferred DNS server | 192.168.30.59 (DC01) |

The gateway (`192.168.20.1`) is OPNsense and cannot resolve `laith.local`; only the DC (`192.168.30.59`) can. Pointing DNS at the DC is what makes the domain join work.

## Joining the domain

On **This PC → Properties → Advanced system settings → Computer Name tab → Change…**:

1. Set **Member of → Domain** to `laith.local`.
2. Entered `laith` (or `laith@laith.local`) and its password when prompted.
3. Got the "Welcome to the laith.local domain" confirmation and restarted.

Sign in with the domain-qualified name after reboot:

```
laith.local\laith
# or: LAITH\laith
```

## Endpoint monitoring

Sysmon is installed on this machine, using the Olaf Hartong `sysmon-modular` config rather than the default. Its events are collected by the Universal Forwarder and sent to Splunk — see `05-ubuntu-splunk-siem.md`.

## Verification

- `nslookup laith.local 192.168.30.59` resolves correctly.
- The machine appears under Computers in Active Directory Users and Computers on the DC.
- Signed in successfully with a domain account.
