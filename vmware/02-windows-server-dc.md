# Windows Server — Domain Controller (DC01)

This is the Domain Controller for the `laith.local` domain. It runs Active Directory Domain Services and DNS, and it sits on the Servers network. This document covers the VM build, the static IP setup, promoting it to a DC, and creating the OUs, users, and groups.

## VM specifications

| Setting | Value |
|---|---|
| RAM | 4 GB |
| Disk | 60 GB |
| CPU cores | 2 |
| OS | Windows Server 2022 (Desktop Experience) |
| Network | VMnet3 — Servers (VLAN30) |
| IP address | 192.168.30.59 |
| Domain | laith.local |

> The Windows hostname still shows as the auto-generated `WIN-IC59S2PCTCD`. Renaming it to `DC01` is on the open-items list; every document refers to it as DC01 by role.

## Installation

1. Created the VM in VMware Workstation with the specs above and attached the Windows Server 2022 ISO.
2. Ran the installer and chose the **Desktop Experience** edition so the server has the full GUI (Server Manager, the AD management consoles, etc.) rather than Core.
3. Completed the standard install, set the local Administrator password, and signed in.
4. Attached the network adapter to VMnet3 so the machine lands on the Servers network.

## Static IP

A Domain Controller must never run on a floating DHCP address — every client's DNS, every GPO, and the log forwarder configuration all depend on it staying constant. It had originally leased `192.168.30.59` from DHCP, so I kept that same address to avoid breaking anything already pointing at it.

Set under **Control Panel → Network and Sharing Center → Change adapter settings → IPv4 Properties**:

| Setting | Value |
|---|---|
| IP address | 192.168.30.59 |
| Subnet mask | 255.255.255.0 |
| Default gateway | 192.168.30.1 (OPNsense — Servers interface) |
| Preferred DNS server | 127.0.0.1 (itself — the DC is the DNS server) |

## Promoting to a Domain Controller

1. **Server Manager → Add Roles and Features →** installed the **Active Directory Domain Services** role.
2. After the role installed, used the post-deployment flag (**Promote this server to a domain controller**).
3. Chose **Add a new forest** and set the root domain name to `laith.local`.
4. Set the Directory Services Restore Mode password and accepted the defaults through the rest of the wizard.
5. Let the server reboot to finish the promotion.

DNS is installed automatically as part of the promotion, and the `laith.local` forward lookup zone is created as Active Directory-integrated with the correct SOA, NS, and Host (A) records.

## Organizational Units

Created directly under the domain root in **Active Directory Users and Computers** (`dsa.msc`):

- Admins
- Standard Users
- Servers

## User accounts

| Logon name | OU | Purpose | Notes |
|---|---|---|---|
| laith | Admins | Primary admin account | Added to Domain Admins; password never expires |
| user1 | Standard Users | Test standard user | Default Domain Users membership only |
| user2 | Standard Users | Test standard user | Default Domain Users membership only |
| user3 | Standard Users | Test standard user | Default Domain Users membership only |
| service_account | Servers | Reserved for future service accounts (e.g. a Splunk forwarder) | Password never expires |

For every account I unchecked "User must change password at next logon" and checked "Password never expires". That's a lab convenience to avoid interruptions, not something I'd do in production.

## Group membership

- **laith** → added to **Domain Admins** on top of the default Domain Users membership. Done via right-click the user → **Properties → Member Of → Add → Domain Admins → Check Names → OK**.
- **user1 / user2 / user3 / service_account** → left at the default Domain Users membership. No role-based security groups yet; that's a later task once Group Policy targeting is set up.

## Verification

- `dcdiag` runs clean.
- The `laith.local` zone is present in DNS Manager, AD-integrated, status Running.
- Clients on the Users network can join the domain and authenticate (see the Target_1 and Target_2 documents).

## Endpoint monitoring

Sysmon is installed on this machine (as on both targets), using the Olaf Hartong `sysmon-modular` config rather than the default. Its events are collected by the Universal Forwarder and sent to Splunk — see `05-ubuntu-splunk-siem.md`.

## Open items

- Rename the Windows hostname from `WIN-IC59S2PCTCD` to `DC01`.
- Create role-based security groups instead of relying only on Domain Admins / Domain Users.
- Group Policy is not configured yet — the first planned GPO is a host firewall policy to enforce user-to-user isolation.
