# pcfix Desktop Hardware Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20(x64)-0078D6.svg)](https://microsoft.com/windows)
[![Size: 180 KB](https://img.shields.io/badge/Binary%20Size-179.5%20KB-success.svg)](https://pcfix-tech.vercel.app/downloads/pcfix-scanner.exe)
[![Open Source: 100% C#](https://img.shields.io/badge/Source-100%25%20C%23%205.0-purple.svg)](Program.cs)

A standalone, zero-installation, portable hardware and storage forensic diagnostic scanner for Windows.

Built specifically to uncover physical hardware faults, storage degradation, PCIe downclocking, and kernel freeze events in under 5 seconds.

---

## Why pcfix Scanner?

Most hardware diagnostic utilities require multi-megabyte installers, install background kernel driver services, or harvest user telemetry.

**pcfix Scanner** is engineered under a zero-trust architecture:

- **Zero Installation**: Single portable `.EXE` (179.5 KB). Runs immediately without an installer.
- **100% Transparent Single-File Source**: The entire codebase is contained in [Program.cs](Program.cs). No hidden DLLs, no obfuscation, no third-party binary blobs.
- **Zero Network Telemetry**: Completely offline. Zero telemetry, analytics, or user data sent over the network. All diagnostic data remains on your local machine.
- **Offline Vector QR Bridge**: Generates sharp on-screen QR codes using pure vector polynomial math inside WPF. No external web APIs used.
- **Read-Only System Calls**: Queries native Windows APIs (Win32 DeviceIoControl, SetupAPI, WMI, and Event Logs). Never modifies your registry or installs kernel drivers.
- **Standard User Compatible**: Runs cleanly as standard user (`asInvoker`). Elevated features (like raw disk IOCTLs) activate automatically when run as Administrator.

---

## Core Forensic Capabilities

### 1. Storage Bad Block Hunter (Event IDs 7, 51, 153)
Queries the Windows System Event Log for physical disk bad blocks. In real-world testing, it identified 48,814 bad blocks on a failing secondary SSD before file system directory corruption caused permanent data loss.

### 2. Split-Boot Architecture Detector
Detects when the Windows EFI Bootloader resides on a separate drive (e.g. Disk 0) from the main Windows OS installation (e.g. Disk 1 C:). Warns users so they do not accidentally wipe or disconnect the boot drive.

### 3. Native S.M.A.R.T. IOCTL Engine
Communicates directly with disk controllers via Win32 `DeviceIoControl` (`SMART_RCV_DRIVE_DATA` and `IOCTL_STORAGE_QUERY_PROPERTY`) to extract raw media wear percentage, uncorrected read errors, and power-on hours for SATA and NVMe storage.

### 4. GPU PCIe Link Speed Validator
Uses Windows SetupAPI (`SetupDiGetDevicePropertyW`) to inspect the physical PCIe link width of present graphics cards. Detects if an RTX/Radeon GPU has silently down-negotiated from x16 to x8 or x4 due to PCIe slot dust or GPU card sag.

### 5. Kernel-Power 41 Freeze Cause Discriminator
Parses XML event parameters from Kernel-Power Event ID 41 to differentiate between sudden power supply unit (PSU) cutoffs, driver bugchecks, and clean power-button shutdowns.

### 6. Memory Diagnostic Scheduler
Allows technicians to schedule a native Windows Memory Diagnostic (`mdsched.exe`) pass on the next system reboot with 1 click.

---

## Building from Source

No Visual Studio, NuGet, or MSBuild installation is required. The scanner compiles natively using the C# 5.0 compiler (`csc.exe`) already included in every standard Windows 10/11 installation.

### 1-Command Build (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File "build.ps1"
```

The script locates `csc.exe` in `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\` and compiles `Program.cs` into:
- `bin\pcfix-scanner.exe` (~180 KB)

---

## Sample Diagnostic Report

```text
=== PCFIX HARDWARE REPORT ===
TIMESTAMP: 2026-10-10 06:40:20
OS: Microsoft Windows 11 Pro (Build 26200, 64-bit)
BOARD: Gigabyte Technology Co., Ltd. H410M S2 V2 | BIOS F2 (UEFI)
CPU: Intel(R) Core(TM) i5-10500 CPU @ 3.10GHz (6C/12T @ 3.10 GHz)
GPU: NVIDIA GeForce RTX 3060 [PCIe x16 Gen 3] (Driver v32.0.16.1742)
RAM: 32.0 GB DDR4 (2/4 slots, Dual-Channel @ 2666 MT/s)
CHASSIS: Desktop PC

SYSTEM_RELIABILITY_INDEX: 4.5 / 10.0 (Degraded / Unstable)

STORAGE_DISKS:
  [Disk 0] Apacer AS350 512GB (477 GB) [EFI Bootloader] -> D: | Internal | HEALTHY (0 Bad Blocks, SMART Verified)
  [Disk 1] PUSKILL 512GB (477 GB) [Windows OS] -> C: | Internal | CRITICAL FAILURE (48,814 Bad Blocks)

BOOT_ARCHITECTURE: SPLIT-BOOT DETECTED
  EFI Bootloader is on Disk 0 (Apacer AS350 512GB), but Windows OS C: is on Disk 1 (PUSKILL 512GB).

HARDWARE_INTEGRITY_AUDIT:
  Disk Bad Blocks (Event ID 7/51/153): 48,814
  Target Device: \Device\Harddisk1
  Verified Live Record: #3230795 @ 2026-10-10 06:12:06
  Event Message: The device, \Device\Harddisk1\DR1, has a bad block.
  Unclean Freeze Reboots (Kernel-Power Event 41): 0
  WHEA Hardware Errors (Event 18/19/47): 0 
  BugCheck BSOD (Event 1001): 0 
================================
```

---

## Web Integration

Generated reports can be pasted directly into the [pcfix AI Web Troubleshooter](https://pcfix-tech.vercel.app/troubleshoot) for immediate, automated triage and verified repair instructions.

---

## License

Licensed under the [MIT License](LICENSE).
Copyright (c) 2026 pcfix.
