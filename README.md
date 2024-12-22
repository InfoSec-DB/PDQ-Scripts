# PDQ-Scripts 🚀

A collection of **PowerShell scripts** and resources to streamline Windows system management, deployments, and tasks using **PDQ** solutions. These scripts are also compatible with standalone PowerShell usage, making them flexible for a variety of scenarios.

---

## Table of Contents
- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Features](#features)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [License](#license)

---

## Overview
**PDQ-Scripts** is a centralized location for scripts that tackle common administrative tasks on Windows machines. Whether you’re using **PDQ Deploy/Inventory** or a standard PowerShell console, these scripts can help:

- **Install/Update** software
- **Collect** system or user-based configurations
- **Audit** security settings
- **Automate** repetitive tasks

Each script (or folder of scripts) is documented to help you easily understand how it works and adapt it to your environment.

---

## Repository Structure
Below is an example layout of the repository. Your actual folder structure may vary.

```
PDQ-Scripts/
├── FolderA/
│   ├── ScriptA.ps1
│   └── ScriptB.ps1
├── FolderB/
│   ├── ScriptC.ps1
│   └── ScriptD.ps1
├── Security Audit/
│   ├── README.md
│   └── SecurityAudit.ps1
├── LICENSE
├── .gitattributes
└── README.md   <-- This file (main repo README)
```

- **FolderA, FolderB, etc.** – Grouped scripts by feature or function.  
- **Security Audit/** – Contains a comprehensive `SecurityAudit.ps1` script and its own README detailing usage.  
- **LICENSE** – Specifies license terms for this repository’s content.  
- **.gitattributes** – Git configuration for handling merges, line endings, etc.  
- **README.md** – You’re reading it right now! Describes the overall purpose of **PDQ-Scripts**.

---

## Features
- **PDQ-Friendly:** Easily integrate scripts into PDQ Deploy/Inventory for automated deployments or scans.  
- **Standalone PowerShell:** Scripts also run directly from PowerShell—no PDQ required.  
- **Modular Organization:** Each script (or set of scripts) is relatively standalone. Pick and choose what you need.  
- **Expandable:** Feel free to create new folders or add more scripts to tackle other tasks.  

---

## Getting Started
1. **Clone or Download** this repository:
   ```bash
   git clone https://github.com/YourAccount/PDQ-Scripts.git
   ```
2. **Review** the folders and scripts to find what matches your use case.
3. If you’re using **PDQ Deploy**, create a new package and point it to one of these `.ps1` files as the install/command step.
4. If you’re using **standalone PowerShell**, simply open an elevated PowerShell prompt and run:
   ```powershell
   .\ScriptName.ps1
   ```
5. **Test** everything in a lab or non-production environment first to avoid unexpected disruptions on live systems.

---

## Contributing
Contributions are always welcome! To contribute:
1. **Fork** the repository.
2. **Create** a new branch for your feature/fix.
3. **Commit** your changes with clear messages.
4. **Push** your branch.
5. **Open** a Pull Request detailing what you changed or added.

For issues or ideas, please open an **Issue** in this repo so we can discuss it. Thank you for helping improve **PDQ-Scripts**!

---

## License
This project is licensed under the [MIT License](./LICENSE). Feel free to modify and adapt the scripts for your personal or organizational needs.  

> **Enjoy using PDQ-Scripts!** If you find these scripts useful, consider giving the repository a ⭐ star or sharing it with others. Happy scripting!
