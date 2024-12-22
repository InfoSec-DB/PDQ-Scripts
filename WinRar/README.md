
# 🗜️ PDQ Deploy Script: Install and Crack WinRAR

## Overview
This script automates the process of installing WinRAR and applying a registration key (crack) to unlock the full version. The installation file can either be downloaded directly from the official vendor or provided as part of the deployment.

---

## Prerequisites
1. **WinRAR Installer**: 
   - Download the latest version from the [WinRAR website](https://www.rarlab.com).
   - Alternatively, use the provided installer: `winrar-x64-710b1.exe`.

2. **Registration Key File**:
   - Ensure the registration key (`rarreg.key`) is placed in the specified source directory: `\xCore-Admin01\PDQ Repos\Winrar\`.

---

## Script Details
### Key Functions
1. **Ensure WinRAR Directory**:
   - The script checks if the required directory for WinRAR exists under the user's application data. If not, it creates the directory.

2. **Apply Registration Key**:
   - Copies the `rarreg.key` file from the source location (`\xCore-Admin01\PDQ Repos\Winrar\rarreg.key`) to the appropriate destination directory.

3. **Error Handling**:
   - Logs errors and stops execution if required files are missing or the copying process fails.

### Script Behavior
- Ensures the WinRAR installation directory exists.
- Copies the registration key file (`rarreg.key`) to the appropriate path: 
  ```plaintext
  %AppData%\WinRAR\rarreg.key
  ```

---

## Usage
1. **Prepare the Environment**:
   - Place the `winrar-x64-710b1.exe` installer in a shared or accessible location.
   - Ensure the `rarreg.key` file is in the `\xCore-Admin01\PDQ Repos\Winrar\` directory.

2. **Run the Script**:
   - Deploy the script using PDQ Deploy or execute it manually with administrative privileges.

3. **Verification**:
   - Check the destination path: `%AppData%\WinRAR\` for the `rarreg.key` file.

---

## Notes
- 🛡️ **Administrative Privileges**: Ensure the script runs with elevated permissions to create directories and copy files.
- ❗ **Disclaimer**: Use of cracked software may violate software licensing agreements. This script is for educational purposes only.

---

## Contact
For support, contact your IT administrator or refer to [WinRAR's support](https://www.rarlab.com/support.htm).
