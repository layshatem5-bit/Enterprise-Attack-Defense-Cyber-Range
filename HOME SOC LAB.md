# 🏠 HOME — SOC Lab

Home base for the SOC home lab. Everything about the project links from here.

A segmented VMware lab: Active Directory behind an OPNsense firewall, Windows endpoints monitored by Sysmon, Splunk as the SIEM, and Caldera for adversary emulation and detection testing.

---

## 📌 Status snapshot

- ✅ Network segmented (OPNsense — 4 networks)
- ✅ Active Directory (`laith.local`) + 2 Windows clients joined
- ✅ Sysmon (Olaf config) on all 3 Windows hosts
- ✅ Splunk collecting Windows + firewall + Ubuntu logs, dashboard live
- ✅ Caldera deployed, agents live, first attack proven end-to-end
- ✅ Detection **01** (Registry Persistence) — deployed & validated
- ✅ Detection **02** (Encoded PowerShell) — deployed & validated
- ✅ Detection **03** (LSASS Credential Access) — deployed & validated
- ⬜ Detection **04** (Privileged Group) — ready
- ⬜ Host-naming cleanup
- ⬜ Full purple-team scenarios + IR reports

---

## 🖥️ Infrastructure (build guides)

- [OPNsense — Firewall & networks](vmware/01-opnsense-firewall.md)
- [Windows Server — Domain Controller](vmware/02-windows-server-dc.md)
- [Target 1 — Windows 10 client](vmware/03-target-1.md)
- [Target 2 — Windows 10 client](vmware/04-target-2.md)
- [Ubuntu — Splunk SIEM](vmware/05-ubuntu-splunk-siem.md)
- [Caldera — Adversary emulation](vmware/06-caldera.md)

## ⚙️ Config reference

- [OPNsense remote logging](configs/opnsense-remote-logging.md)
- [Splunk inputs & netplan](configs/splunk-inputs.md)
- [Splunk dashboard](configs/splunk-dashboard.md)
- [Caldera commands](configs/caldera-commands.md)

## 🛡️ Detections

- [Detections overview](detections/README.md)
- [01 — Registry Run Key Persistence](detections/01-registry-run-key-persistence.md) ✅
- [02 — Suspicious / Encoded PowerShell](detections/02-suspicious-powershell.md) ✅
- [03 — LSASS Credential Access](detections/03-lsass-credential-access.md) ✅
- [04 — Privileged Group Modification](detections/04-privileged-group-modification.md)

## 📓 Journal

- [Progress Log](Progress Log.md) — the full story, in order

---

## ✏️ Scratch space

Rough notes, ideas, and things-to-try live in the `notes/` folder (kept out of GitHub). Write freely there.
