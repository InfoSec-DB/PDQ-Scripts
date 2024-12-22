# Windows Security Audit Script 🔒🛡

A comprehensive PowerShell script to audit the security posture of a Windows server or workstation. It logs findings to both a text file and CSV file for easy analysis.

### Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [How It Works](#how-it-works)
- [Usage](#usage)
- [Script](#script)
- [Contributing](#contributing)
- [License](#license)

---

## Features
✅ **Checks system information** (OS, uptime, memory, BIOS, locale, time zone)  
✅ **Checks domain group policy** (via `gpresult`)  
✅ **Audits local security policies** (UAC, LSA, etc.)  
✅ **Enumerates installed security updates & missing patches**  
✅ **Inventories installed software**  
✅ **Verifies firewall status & open ports**  
✅ **Audits startup programs & scheduled tasks**  
✅ **Checks suspicious processes** (using Sysinternals `pslist.exe`)  
✅ **Checks registry persistence** (using Sysinternals `autorunsc.exe`)  
✅ **Verifies RDP status**  
✅ **Audits SSL/TLS protocols & ciphers**  
✅ **Checks SMB settings**  
✅ **Lists installed server certificates**  
✅ **Lists disk usage, shadow copies, BitLocker status**  
✅ **Retrieves logon events & recent security events**  
✅ **Lists ARP table, network adapters, active connections**  
✅ **Audits DNS settings**  
✅ **Scans browser security settings** (IE/Edge/Chrome/Firefox)  
✅ **Audits removable storage & USB policy**  
✅ **Logs output** to both `.log` and `.csv` files

---

## Requirements
1. **Windows PowerShell** (v5.1 or higher)  
2. **Administrator privileges** (for many checks, including reading certain registry keys)  
3. **Internet access** (if you want to download Sysinternals tools on-the-fly)  

---

## How It Works
1. **Creates** a `C:\AuditLogs\` folder (if it doesn’t exist) and names the log files with a timestamp.  
2. **Installs/ensures** required modules like `ActiveDirectory` and `PSWindowsUpdate`.  
3. **Runs** each check (firewall, open ports, suspicious processes, etc.).  
4. **Copies** relevant data (like browser history) and logs critical findings.  
5. **Exports** both text and CSV logs for further analysis.  

---

## Usage
1. **Open PowerShell** as an administrator.
2. **Clone** this repository or **download** the script.
3. **Run** the script:
   ```powershell
   .\SecurityAudit_Script.ps1
