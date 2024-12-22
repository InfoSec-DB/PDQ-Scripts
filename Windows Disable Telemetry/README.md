
# ✨ CBKB - DeadlyData Telemetry Management Scripts ✨

## 🌟 Overview
This script provides functionality to manage Windows telemetry settings. It includes the ability to:
- 🚫 Disable telemetry services, tasks, hosts, and registry settings.
- 🔄 Restore them to their default state.

---

## 🔧 Functions

### 1. 🚫 Disable Telemetry
This function:
- 🛑 Stops and disables telemetry-related services.
- 🛡️ Blocks telemetry-related hosts in the `hosts` file.
- ⏸️ Disables telemetry-related scheduled tasks.
- 📝 Configures registry keys to disable telemetry.

### 2. 🔄 Restore Telemetry
This function:
- 🔄 Restores telemetry services to their default state.
- ✂️ Removes telemetry host blocks from the `hosts` file.
- ✅ Re-enables telemetry-related scheduled tasks.
- 🗑️ Removes custom registry keys.

---

## 🌈 Features
- **Comprehensive Control**: 🛠️ Provides both disabling and restoring functionality.
- **Safe Operations**: 📝 Tracks successes and failures, ensuring safe execution.
- **PDQ Deploy Compatibility**: 🖥️ Includes explicit success exit codes for deployment systems.

---

## 🛠️ Usage
1. 🔽 Download the script: `CBKB_Disable_Enable_Telemetry.ps1`
2. ⚡ Run with administrative privileges:
   ```powershell
   .\CBKB_Disable_Enable_Telemetry.ps1
   ```

---

## 📊 Statistics and Logging
The script provides a summary of:
- ✅ Successful operations for services, tasks, hosts, and registry changes.
- ❌ Failed operations for services, tasks, hosts, and registry changes.

---

## 💻 Requirements
- 🪟 Windows 10, 11, or Windows Server (2016 and later).
- 🔑 Administrative privileges.

---

## ⚠️ Disclaimer
Use responsibly. 🚨 Disabling telemetry may affect certain Windows features or updates.
