# Target_1 — Windows 10 Client

Target_1 is one of the two "employee" workstations on the Users network. It's a domain-joined Windows 10 machine that Sysmon monitors and that later runs a Caldera agent during exercises.

## VM specifications

| Setting | Value |
|---|---|
| RAM | 3 GB |
| Disk | 30 GB |
| CPU cores | 1 |
| OS | Windows 10 Pro |
| Network | VMnet2 — Users (VLAN20) |
| IP address | 192.168.20.41 |
| Machine name (AD) | DESKTOP-QBQ5RET |

## Installation

1. Created the VM in VMware Workstation with the specs above and attached the Windows 10 ISO.
2. Ran a standard Windows 10 Pro install.
3. Attached the network adapter to VMnet2 so the machine lands on the Users network.
4. Let it pull an address from DHCP (192.168.20.41 from the Users pool).

## Network configuration

The one setting that matters before joining the domain is DNS. The client must point at the Domain Controller for DNS, not at the firewall:

| Setting | Value |
|---|---|
| IP address | 192.168.20.41 (DHCP) |
| Gateway | 192.168.20.1 (OPNsense — Users interface) |
| Preferred DNS server | 192.168.30.59 (DC01) |

This is the part that's easy to get wrong. The gateway of any network is always OPNsense (`x.x.x.1`), but OPNsense knows nothing about the `laith.local` domain — that zone only exists on the DC. If the client's DNS is left pointing at the gateway, every lookup for `laith.local` comes back as a non-existent domain and the join fails. The DNS server and the gateway are two different machines; only the DC can resolve the domain.

## Joining the domain

On **This PC → Properties → Advanced system settings → Computer Name tab → Change…**:

1. Set **Member of → Domain** to `laith.local`.
2. When prompted for credentials, entered `laith` (or `laith@laith.local`) and its password.
3. Got the "Welcome to the laith.local domain" confirmation and restarted.

After the reboot the login screen defaults to the last local account. To sign in with a domain account, click **Other user** and use the domain-qualified name:

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

> Firewall note: right after the Users → Servers lockdown was applied, domain logon hung on the "Welcome" screen until the RPC dynamic port range was added to the AD ports alias. That's documented in `01-opnsense-firewall.md`, issue 3.
