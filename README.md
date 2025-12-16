# SysMan | System Care & Crisis Solution

![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=flat-square)
![Architecture](https://img.shields.io/badge/Architecture-Native_Polyglot-red?style=flat-square)
![Scenarios](https://img.shields.io/badge/Scenarios-200%2B_Coverage-purple?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11%2FServer-lightgrey?style=flat-square)
![Language](https://img.shields.io/badge/Language-Batch%20%7C%20PowerShell-brightgreen)
![License](https://img.shields.io/badge/License-MIT-orange)

## Overview

**SysMan** is the ultimate solution for modern IT infrastructures. It transforms the chaos of complex diagnostic procedures into a single, simple interface.

SysMan is designed for the high-pressure realities of system administrators and DevOps engineers. Whether you're mitigating a critical ransomware attack or performing routine maintenance on fleets of systems, SysMan turns complex engineering challenges into a structured, actionable checklist.

**A Portable Toolbox for System Maintenance and Repair.**

---

## Advantages

In an industry where downtime equals revenue loss, SysMan reduces "Time-to-Resolution" (TTR) by removing the cognitive load of diagnostics.

* **🧠 Cognitive Offload:** Forget memorizing obscure PowerShell syntax or Registry paths. SysMan presents every possible scenario—from *Boot Failure* to *Network Isolation*—in a clear, human-readable menu.
* **🔌 Plug-and-Play Power:** A fully portable software that runs instantly on Windows machines. No agents, no prerequisites, no "DLL missing" errors.
* **🛡️ Dual-Mode Engineering:**
    * **Crisis Mode:** Instant incident response tools (Kill-Switch, Forensics, Unblocking).
    * **Maintenance Mode:** Proactive hygiene tools (Debloat, Optimize, Patch).

---

## Architecture

SysMan is architected around four pillars of system integrity:

### 1. Advanced Virtualization (Hyper-V)
*Unlock the full potential of your virtual labs without the complexity.*
* **GPU Partitioning (GPU-PV):** Provision hardware acceleration to VMs in seconds.
* **Nested Virtualization:** Run Hyper-V or Docker inside your VMs effortlessly.
* **Lifecycle Management:** Clone, snapshot, resize, and convert disks via a simple wizard.

### 2. Cybersecurity & Incident Response
*Military-grade tools for immediate threat containment.*
* **Ransomware Halt:** A "Panic Button" that severs SMB connections and locks down file access.
* **Forensic Snapshot:** Captures volatile evidence (RAM, Network, DNS) before shutdown.
* **Persistence Hunter:** Scans and neutralizes hidden startup items, WMI events, and scheduled tasks.
* **USB Audit:** Retrospective analysis of all physical device connections.

### 3. Network Infrastructure
*Diagnose connectivity issues with surgical precision.*
* **Stack Reconstruction:** Automated reset of TCP/IP, Winsock, and Driver interfaces.
* **Traffic Analysis:** Real-time port scanning and process-to-port mapping.
* **Config Mobility:** Export/Import Wi-Fi profiles and VPN configurations seamlessly.

### 4. System Maintenance
*Keep the fleet running at peak performance.*
* **Deep Sanitation:** Component Store (DISM) repair and rigorous temp file purging.
* **Performance Tuning:** Intelligent SSD trimming, RAM optimization, and bloatware removal.
* **Driver Repository:** Full driver export capabilities for disaster recovery.

---

## Scenarios

| Scenario | The Challenge | The Solution |
| :--- | :--- | :--- |
| **Emergency** | Server is unstable, BSOD loop, or under cyber attack. | Select symptom -> Execute Fix. Immediate stabilization. |
| **Maintenance** | Workstation is slow, clogged with updates, or drifting from policy. | One-click Deep Cleanup, Updates Reset, and Optimization. |
| **Deployment** | Setting up a new lab or employee workstation. | Install Tools, Debloat OS, and Configure Hyper-V NAT. |
| **Field Work** | Visiting a client site with unknown hardware/software state. | Plug USB -> Run SysMan -> Diagnose instantly. |

---

## Quick Start

1.  **Deploy:** Place SysMan directory on a USB drive or network share.
2.  **Launch:** Run `SysMan.exe` as Administrator (Elevated privileges required for deep access).
3.  **Execute:**
    * Select **Maintenance** for routine care.
    * Select **Troubleshooting** for critical repairs.
    * Select **Advanced** for granular control.

> *Tip: Use the advanced "Resources Monitor" (Option R) for an instant overview of CPU, RAM, and Disk health.*

---

## Technical Information

SysMan is built on a **Polyglot Architecture**, combining C# with a native PowerShell Script.
* **Transparency:** All operations use native Windows APIs—no third-party code.
* **Compliance:** Designed to adhere to "Least Privilege" and standard auditing practices.

---

## 📜 Legal & Licensing

**Copyright © 2025 Yaron Koresh.**

> *WARNING: The SysMan project is a project whose code is partly MIT (open source) and partly all rights reserved. [This repository](https://github.com/YaronKoresh/SysMan) is under the MIT license while the rest of the code is not open source and all rights to it are reserved. Both types of code are compiled and released as SysMan.exe. Any attempt to obtain the full source code of the SysMan project is strictly prohibited.*

Contact: aharonkoresh1@gmail.com

*This software is provided "AS IS" for professional use. While engineered for safety, the author accepts no liability for data loss or system instability resulting from misuse of administrative functions.*
