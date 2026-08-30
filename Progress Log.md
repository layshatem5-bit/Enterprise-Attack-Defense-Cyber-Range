# 📓 Progress Log

The project in order — what was built, what broke, and how it was fixed. Each entry links to the full write-up. Back to [HOME](HOME SOC LAB.md).

---

## 2026-08-24 — Active Directory & first network pains

- Stood up **Windows Server 2022** as the Domain Controller for `laith.local`: OUs, users, groups, static IP, DNS. → [Windows Server — DC](vmware/02-windows-server-dc.md)
- Hit a **DNS gotcha**: clients pointed at the firewall (`.1`) for DNS instead of the DC, so `laith.local` wouldn't resolve. Fixed by pointing clients at the DC.
- Chased a **DHCP outage** — clients falling back to APIPA. Two causes: a stale dnsmasq process holding port 67, and (the real one) the Dnsmasq "Interface" list not including all VLANs. → [OPNsense firewall doc, issue 4](vmware/01-opnsense-firewall.md)

## 2026-08-25 — Segmentation, Sysmon, and the Splunk box

- Built the real **OPNsense firewall rules**: Users → Servers only on AD ports, Servers can't initiate to Users, Attack fully isolated. Learned that same-subnet user-to-user blocking can't be done at the router, that rule order matters, and that RPC needs the dynamic port range (logon hung until I opened it). → [OPNsense — Firewall](vmware/01-opnsense-firewall.md)
- Deployed **Sysmon** on all 3 Windows hosts using the **Olaf Hartong** config.
- Provisioned the **Ubuntu Server** VM for Splunk.

## 2026-08-28 — Splunk SIEM online

- Installed **Splunk Enterprise** (survived a power-cut dpkg corruption → full reinstall, an entropy hang fixed with `haveged`, and the run-as-root flag).
- Installed **Universal Forwarders** on the 3 Windows hosts; added one narrow firewall rule for port 9997.
- Wired up all **three log sources** (Sysmon → `main`, firewall syslog → `firewall`, Ubuntu → `ubuntu`) and built the **SOC Lab Overview dashboard**. → [Ubuntu — Splunk SIEM](vmware/05-ubuntu-splunk-siem.md)

## 2026-08-29 — Caldera & first attack

- Installed **Caldera 5.3.0** on its own VM (fought the git submodule prompt, the Magma build, an accidentally-deleted `default.yml`, and the venv).
- Deployed **sandcat agents** to all 3 Windows hosts (one narrow firewall rule for port 8888).
- Ran the first operation and a **Registry persistence test (T1547.001)** — confirmed the event reached Splunk as Sysmon Event ID 13. → [Caldera](vmware/06-caldera.md)

## 2026-08-30 — Detections built, deployed, and validated

- Wrote **4 detection rules** mapped to MITRE ATT&CK. → [Detections](detections/README.md)
- **Deployed & validated Detection 01 (Registry Persistence)** through the full purple-team loop: ran the technique from Caldera, the scheduled alert fired automatically in Splunk. → [01](detections/01-registry-run-key-persistence.md)
  - Learned two things fixing it: the real Sysmon sourcetype is `XmlWinEventLog`, and registry paths come uppercase with an `HKU\<SID>\` prefix (match case-insensitively).
  - Also learned that Run keys are noisy (Edge writes them constantly) — the value-based filter is what separates the attack from the noise.
- **Deployed & validated Detection 02 (Encoded PowerShell)** — its `ParentImage` chain even revealed the C2 origin (`sandcat.exe` → `powershell.exe`). → [02](detections/02-suspicious-powershell.md)
- **Deployed & validated Detection 03 (LSASS Credential Access)** via a live procdump test run through Caldera Manual Command. → [03](detections/03-lsass-credential-access.md)
  - The first version of the rule missed the real test event entirely: `GrantedAccess` is logged uppercase (`0x1FFFFF`) but the filter list was lowercase, and Splunk string comparison is case-sensitive. Fixed with `lower()` — same class of bug as rule 01's registry-path case issue.
  - Also found that PowerShell routinely opens a weak, benign handle to `lsass.exe` (SID-to-username lookups), which was tripping the rule as a false positive on all three hosts before any real test ran. Fixed by only trusting the weak-access/unknown-callstack combination when the source process isn't PowerShell; a genuinely dump-capable access mask still alerts no matter what opened it.
- Started the **host-naming cleanup** (same machine was reporting under two names).
- Cleaned up the test artifacts (removed the fake Run keys, deleted LSASS dump files).

---

## ⬜ Next up

- Deploy & validate Detection **04 (Privileged Group)**.
- Finish host-naming standardization.
- Build full purple-team scenarios (APT emulation, ransomware, insider threat), each written up as an **Incident Response report**.
