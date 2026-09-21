# 🏹 HUNTER — Windows Malware Analysis Platform (DFIR & EDR Workbench)

> **HUNTER (codename *Valhalla*)** is an all-in-one Windows forensics, malware analysis and detection workbench.
> It blends a **33-page WPF investigation workspace**, a **real-time packet capture engine** (SharpPcap / Npcap,
> the Wireshark family), a **49-slot native inline API-hook engine**, a **dual IL/native decompiler**, a **WDM kernel
> telemetry driver**, **ETW event tracing**, **artifact forensics** (Prefetch, Shimcache, UserAssist, USN Journal,
> Shellbags, LNK/Jumplists) and dozens of detection heuristics — all in a single desktop application.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11-0078D6)]()

> ## ⚠️ IMPORTANT — READ BEFORE USE
> **HUNTER is a dual-use security tool.** It performs process injection, API hooking, kernel telemetry collection and
> live traffic capture — techniques that are equally valuable to defenders and attractive to attackers. You are
> responsible for:
>
> - Using this software **only on systems you own or are explicitly authorized to test**.
> - Understanding that many actions require **Administrator privileges** and may trigger your own AV/EDR.
> - Treating this as a **research and incident-response artifact**, not a production-grade antivirus.
>
> The project is published for **defensive security research, forensics and education**. Misuse is entirely at your own
> risk and responsibility.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Features at a glance](#2-features-at-a-glance)
3. [The user interface](#3-the-user-interface)
4. [Architecture](#4-architecture)
5. [Repository layout](#5-repository-layout)
6. [Technology stack](#6-technology-stack)
7. [Requirements](#7-requirements)
8. [Building from source](#8-building-from-source)
9. [Running the application](#9-running-the-application)
10. [Feature deep-dive](#10-feature-deep-dive)
11. [Configuration](#11-configuration)
12. [Known limitations](#12-known-limitations)
13. [FAQ / Troubleshooting](#13-faq--troubleshooting)
14. [Security & responsible use](#14-security--responsible-use)
15. [Roadmap](#15-roadmap)
16. [Contributing](#16-contributing)
17. [License](#17-license)
18. [Acknowledgements](#18-acknowledgements)

---

## 1. Overview

HUNTER is a **single-process Windows investigation cockpit**. It was designed around a simple idea: a forensic
analyst or incident responder should be able to go from "double-click the executable" to "I know what this machine is
doing" without launching six different tools.

What you get out of the box:

| Capability | Where it lives |
|---|---|
| Live process / thread / module inventory with token, integrity, Authenticode & reputation context | `Processes` page |
| Deep memory scanning (RWX regions, PE injections, shellcode/NOP-sled patterns, entropy, heap/stack/PEB/TEB) | `Deep Memory` page |
| Live packet capture with payload hex (SharpPcap + PacketDotNet, Npcap) | `Live Network` page |
| Reliable, hook-free network contact enumeration (IP / URL, GET / POST, TLS) | `Network` / `Malware Hunt` |
| MITRE-mapped heuristic **RuleEngine** for processes, persistence, network and events | `Triage` / `Malware Hunt` |
| **BYOVD driver audit** — 20+ known-vulnerable drivers, kernel-API risk matrix, 0–100 composite score | `DriverHunter` |
| **AMSI bypass / obfuscation analysis** on PowerShell/Script telemetry | `AMSI` / `AMSI Monitor` / `Script Monitoring` |
| **ETW real-time tracing** (Kernel-Process, Kernel-Image, TCPIP) | `ETW` / `ETW Tracker` |
| **Artifact forensics**: Prefetch, Shimcache, UserAssist, USN Journal, Shellbags, LNK & JumpLists, cross-artifact timeline | `Forensics` / `Historical` |
| **Dual decompiler**: custom managed-IL decompiler + ILSpy/Mono.Cecil module tree + native PE view | Decompiler window |
| **Native PE analysis**: Rich header, compiler fingerprint, packers, imports, TLS callbacks, section entropy | `PE Headers` / Native Analyzer window |
| **YARA-style rule matching** (regex-based engine, `.yar` rule store, file + live process-memory scanning) | `YARA` |
| **VirusTotal** hash lookup (embedded hash DB + optional `VT_API_KEY`) | `VirusTotal` |
| **LOLBin** catalog (14 binaries), persistence, services, scheduled tasks, registry, software, hardware/USB, SRUM, Wi-Fi & BT, timeline | dedicated pages |
| **84-method native inline API-hook engine** with shared-memory rings, arg/return formatting, payload capture | `ApiHookWindow`, `NetworkMonitorWindow` |
| **WDM kernel telemetry driver** (process create/exit + image-load notify routines → user-mode queue) | driver project |
| **Background telemetry service** (ETW real-time session as a Windows service) | `MalwareAnalyzer.Service` |
| CSV / JSON report export | Report window |

---

## 2. Features at a glance

- **33-page investigation workspace** with dark cyber-chrome UI (animated GIF logo, particle field, fade transitions).
- **Real packet capture, capture-free**: the `.NET` side only reads what SharpPcap exposes; *no* network injection.
- **Two independent telemetry channels**: live pcap traffic AND the native HookEngine ring (API calls + network
  send/recv payload inspection).
- **Five auxiliary windows**: API Hook Engine, Packet Monitor, Decompiler, Native Analyzer, Report generator — plus a
  branded **SplashScreen** at startup.
- **Host-wide sweeps**: whole-system RWX memory sweep, loaded-driver sweep, hardware/USB sweep, persistence sweep.
- **Turkish-verdict scoring** (`TEMİZ` / `ŞÜPHELİ` / `ZARARLI` / `KRİTİK`) in the hook-verdict layer; the rest of the
  chrome is English.
- **Optional licensing module** (`LicenseCore.dll`) with HWID binding, file-tamper detection and VMProtect-ready markers
  (disabled by default, no SDK required).

---

## 3. The user interface

### 3.1 Splash & main window

`App.xaml.cs` shows an animated **SplashWindow**, then fades the **MainWindow** into view. The main window is a
left-navigation dock with a **33-page workspace**, a live status bar (Admin / Sysmon / Driver / ETW status) and a
refresh-driven telemetry collector pipeline.

### 3.2 The 33 workspace pages

| # | Page | What it shows / does |
|---|---|---|
| 1 | **Triage** | Quick-risk review: flagged processes, persistence, network, events, global verdict |
| 2 | **Processes** | Full process table (PSAPI/Toolhelp32) + token, integrity level, AUTH hash, reputation, Sysmon correlation, deep-dive per PID |
| 3 | **Timeline** | Chronological event list built from collectors & rules |
| 4 | **Disassembly** | Own **x86-64 decoder** (OpCode decode, XED-style), flags `syscall` / `sysenter` / `rdtsc`, addresses & mnemonics |
| 5 | **Deep Memory** | `VirtualQueryEx` sweep + deep scan: RWX/private-exec regions, PE-injection signature, NOP/INT3 sled, high entropy, heap/stack/PEB/TEB walking, dump region to disk |
| 6 | **Strings** | ASCII/Unicode string extraction with printable filters |
| 7 | **Dump Analyzer** | Crash-minidump (`MDMP`) header parse + string IOC extraction, section stats |
| 8 | **PE Headers** | Full PE parse: DOS/NT headers, sections, entropy, flags, suspicious indicators (RWX, timestomp, overlay) |
| 9 | **Hex Editor** | Byte-level inspection of selected file / memory region |
| 10 | **Malware Hunt** | Aggregated triage across processes, files, network, registry with severity scoring |
| 11 | **DriverHunter** | Loaded-driver audit + `DriverAnalysisEngine` BYOVD database (RTCore64, DBUtil 2.3, gdrv, mhyprot2, procexp, capcom, AsIO, zam64, speedfan, eneio64, iqvw64e, cpuz141, winring0, kprocesshacker, echo_driver …) with heuristics |
| 12 | **AMSI Monitor** | Live AMSI events; deobfuscated script content, raw logged content, verdict & mitigation |
| 13 | **Script Monitoring** | PowerShell (Event ID 4104) script block logging capture |
| 14 | **ETW Tracker** | Real-time ETW session list and tracking console |
| 15 | **LOLBin** | 14 living-off-the-land binaries catalog & detection |
| 16 | **YARA** | Rule store browser; add/edit regex rules; scan files, processes and memory; severity & description |
| 17 | **VirusTotal** | SHA-256 hash lookup via `VT_API_KEY` or embedded hash DB |
| 18 | **AMSI** | AMSI bypass patterns & obfuscation analysis on scripts |
| 19 | **Persistence** | Autoruns, IFEO, Winlogon, Defender exclusions, startup folders |
| 20 | **Services** | Service inventory (name, path, start type, state, signed?) |
| 21 | **Tasks** | Scheduled tasks via `schtasks /query /v /fo csv` |
| 22 | **Registry** | Sensitive-key audits + full registry browser with inventory |
| 23 | **Drivers** | Loaded kernel modules via `psapi` (EnumDeviceDrivers) |
| 24 | **Software** | Installed software inventory |
| 25 | **Historical** | Cross-artifact historical forensics correlation engine |
| 26 | **Forensics** | Prefetch / Shimcache / UserAssist sub-grids (`HistoricalForensicsEngine`) |
| 27 | **SRUM** | Live resource-usage approximation (synthesized from running processes) |
| 28 | **WiFi & BT** | Wi-Fi profiles/connections (`netsh`) + Bluetooth devices (`BTHPORT`) |
| 29 | **Hardware** | CPU, RAM, disk, GPU, USB history forensics |
| 30 | **Network** | Active TCP/UDP connections via `GetExtendedTcpTable`, PID→process correlation, 2s diff monitor |
| 31 | **ETW** | ETW provider/event stream (system providers; requires admin) |
| 32 | **Live Network** | Continuous **SharpPcap** capture: device, packet tree, payload hex |
| 33 | **EventLog** | Windows event log reader with filters |

### 3.3 Auxiliary windows

| Window | Purpose |
|---|---|
| **API Hook Engine** (`ApiHookWindow`) | Load `HookEngine.dll`, pick a target PID or launch a suspended process, inject, watch live hook events (PID + API + formatted args + return). 4 tabs of instrumentation. |
| **Packet Monitor** (`NetworkMonitorWindow`) | Live pcap packets plus the HookEngine network ring; per-packet tree and payload hex with filter box. |
| **Decompiler** (`DecompilerWindow`) | Load any PE. Detects managed vs native: custom IL decompiler + ILSpy C# module tree (types, methods, references, string literals, IPs, base64) + Cecil assembly tree; native binaries fall back to PE/NativeAnalyzer view. |
| **Native Analyzer** (`NativeAnalyzerWindow`) | `NativeAnalyzer.dll` deep-dive: Rich header, compiler fingerprint, packers, imports, TLS callbacks, entropy chart, disassembly summary. |
| **Report** (`ReportWindow`) | CSV / JSON export of collected telemetry and verdicts. |

### 3.4 Custom controls

`AnimatedGifImage.cs` (delta-frame-aware GIF player via GDI+), `FadeTransition.cs`, `ParticleField.cs` (ambient
particles), `IconLabel` (Fluent-style glyphs), `SyntaxCodeViewer` (syntax-highlighted script viewer).

---

## 4. Architecture

```
                        ┌─────────────────────────────────────────────────────────┐
                        │                 HUNTER UI (WPF, net8.0-windows)          │
                        │  MainWindow (33 pages)  · MainViewModel (~4300 lines)    │
                        │  ApiHook · NetworkMonitor · Decompiler · Native · Report │
                        └───────┬──────────────┬───────────────┬──────────────────┘
                                │              │               │
              ┌─────────────────┘      ┌───────┴──────┐        └───────────────┐
              ▼                          ▼             ▼                        ▼
   ┌─────────────────┐     ┌────────────────────┐ ┌────────────────┐  ┌───────────────────┐
   │  Collectors     │     │  Detection engines │ │  Forensics     │  │  Memory            │
   │  22 services    │     │  10 engines        │ │  7 parsers     │  │  ProcessMemoryScanner│
   └────────┬────────┘     └─────────┬──────────┘ └───────┬────────┘  └────────┬──────────┘
            │                        │                    │                    │
            └──────────────┬─────────┴─────────┬──────────┴────────────────────┘
                           ▼                   ▼
                  ┌─────────────────┐   ┌──────────────────────────────┐
                  │   Decompiler    │   │  Network / Capture layer      │
                  │  custom IL +    │   │  PacketCapturePcap (SharpPcap │
                  │  ILSpy/Cecil    │   │  · PacketDotNet · Npcap)      │
                  └─────────────────┘   └──────────────┬───────────────┘
                                                       ▼
NATIVE LAYER ────────────────────────────────────────────────────────────────
   HookEngine.dll  (49-slot inline API hooks, rings, injection, mod rules)
   NativeAnalyzer.dll (PE/Rich/compiler/packer/TLS analysis)
   PeNative.dll      (native PE parser used by PeAnalyzer)
   LicenseCore.dll   (HWID licensing, tamper hash, VMProtect markers — optional)
   MalwareAnalyzer.sys (WDM driver: process/image-load notify queues, IOCTL)
                                                       ▼
                              MalwareAnalyzer.Service (Windows service, ETW)
```

**Layering rules**

- `MalwareAnalyzer.UI` (WinExe) references `Core`, `Collectors`, `Forensics`, `Detection`, `Memory`, `Decompiler`.
- `Core` has **zero project dependencies** — it holds models, interfaces, enums and the Win32 API layer.
- `Detection` compiles as assembly **`MalwareAnalyzer.Engines`** and depends only on `Core`.
- `Collectors` depends on `Core` + `Memory`; `Forensics` and `Memory` depend only on `Core`.
- The `Service` depends on `Core` + `Collectors` and runs an ETW session in the background.
- Native code (C/C++ DLLs + driver) is loaded at runtime through small P/Invoke bridges
  (`HookEngineBridge.cs`, `NativeAnalyzerBridge.cs`, `NativePeParser.cs`).

---

## 5. Repository layout

```
Hunter/
├── Hunter.sln                                  # All 9 managed projects
├── README.md
├── LICENSE                                     # MIT
├── .gitignore
├── .gitattributes
└── src/
    ├── MalwareAnalyzer.UI/                     # WPF app (WinExe, net8.0-windows)
    │   ├── MainWindow.xaml(.cs)                #   33-page workspace (~3k lines XAML)
    │   ├── ApiHookWindow.xaml(.cs)             #   HookEngine UI
    │   ├── NetworkMonitorWindow.xaml(.cs)      #   Live pcap + net-ring UI
    │   ├── DecompilerWindow.xaml(.cs)          #   Decompiler UI
    │   ├── NativeAnalyzerWindow.xaml(.cs)      #   Native PE analysis UI
    │   ├── ReportWindow.xaml(.cs)              #   CSV/JSON report UI
    │   ├── SplashWindow.xaml(.cs)              #   Animated splash
    │   ├── HookVerdictEngine.cs                #   TR verdict labels from hook telemetry
    │   ├── Network/
    │   │   └── PacketCapturePcap.cs            #   SharpPcap + PacketDotNet live capture
    │   ├── ViewModels/
    │   │   └── MainViewModel.cs                #   Orchestrates collectors, engines, UI state
    │   ├── native/                             #   Prebuilt x64 native engines (P/Invoke targets)
    │   │   ├── HookEngineBridge.cs             #   P/Invoke to HookEngine.dll
    │   │   ├── HookEventRouter.cs              #   Hook-event → UI routing
    │   │   ├── PeNative.c                      #   Native PE parser source (→ PeNative.dll)
    │   │   ├── HookEngine.dll                  #   (in-repo, force-tracked)
    │   │   ├── NativeAnalyzer.dll              #   (in-repo, force-tracked)
    │   │   └── PeNative.dll                    #   (in-repo, force-tracked)
    │   ├── Assets/                             #   hunter.ico, logo.gif, ValhallaLogo.png
    │   └── app.manifest                        #   requireAdministrator
    ├── MalwareAnalyzer.Core/                   # Models, enums, interfaces, Win32Api
    │   ├── Models/   (SystemModels.cs, RegistryInventoryRecord.cs, RegistryKeyNode.cs, HexRow.cs)
    │   ├── Interfaces/ICollectors.cs           #   24 collector contracts
    │   ├── Enums/
    │   └── Native/   (Win32 API layer)
    ├── MalwareAnalyzer.Collectors/             # 22 telemetry collectors & services
    │   ├── Services/   (…Collector.cs, NetworkActivityMonitor, AmsiCollector, EtwCollector …)
    │   └── Native/ReputationEvaluator.cs
    ├── MalwareAnalyzer.Detection/              # Detection engines (assembly: MalwareAnalyzer.Engines)
    │   └── Engines/
    │       ├── RuleEngine.cs                   #   MITRE-mapped rule engine
    │       ├── DriverAnalysisEngine.cs         #   BYOVD database + kernel-API matrix
    │       ├── AmsiAnalysisEngine.cs           #   AMSI bypass/obfuscation
    │       ├── EtwThreatEngine.cs              #   ETW C2 ports/dirs heuristics
    │       ├── YaraEngine.cs                   #   Regex-rule engine (file + process memory)
    │       ├── PeAnalyzer.cs                   #   PE heuristics (RWX, entropy, timestomp)
    │       ├── NativePeParser.cs               #   P/Invoke → PeNative.dll
    │       ├── CodeDisassembler.cs             #   x86-64 decoder
    │       ├── DumpAnalyzer.cs                 #   minidump MDMP + IOCs
    │       └── VirusTotalClient.cs             #   hash lookup (VT API / embedded DB)
    ├── MalwareAnalyzer.Forensics/              # Artifact parsers
    │   └── Parsers/ (Prefetch·Shimcache·UserAssist·UsnJournal·Shellbags·LnkJumpList·HistoricalForensicsEngine)
    ├── MalwareAnalyzer.Memory/                 # ProcessMemoryScanner{.Deep}.cs
    ├── MalwareAnalyzer.Decompiler/             # custom IL decompiler + Cecil/ILSpy + native bridge
    │   ├── DecompilerEngine.cs                 #   custom metadata/IL/body/source pipeline
    │   ├── Cecil/  (CecilDecompiler.cs)        #   dnSpy-style ILSpy integration
    │   ├── Met/, Il/, Pe/, Language/           #   parser building blocks
    │   └── Native/NativeAnalyzerBridge.cs      #   P/Invoke → NativeAnalyzer.dll
    ├── MalwareAnalyzer.Tests/                  # xUnit (PeAnalyzerTests, RuleEngineTests)
    ├── MalwareAnalyzer.Service/                 # Windows service (ETW real-time session)
    ├── MalwareAnalyzer.Driver/                  # WDM kernel driver (C)
    │   ├── Driver.c / Driver.h / Ioctl.h
    │   └── MalwareAnalyzer.Driver.vcxproj       #   WDK 10.0.28000.0
    ├── HookEngine/                             # Native inline hook engine (C)
    │   └── hook_engine.cpp / hook_engine.h     #   49 API slots, rings, injection, mod rules
    ├── NativeAnalyzer/                         # Native PE analyzer (C++)
    │   └── native_analyzer.cpp / .h            #   Rich header, compiler ID, packers, TLS
    └── LicenseCore/                            # Native licensing DLL (C++)
        ├── dllmain.cpp · hwid.cpp · license.cpp · network.cpp · sha256.cpp · vmprotect.h
        ├── LicenseCore.vcxproj
        └── build_vs.bat                        #   VS2022 x64 Release build
```

---

## 6. Technology stack

### Managed (.NET 8, all projects `net8.0-windows`)

| Package | Version | Used for |
|---|---|---|
| SharpPcap | 6.3.0 | Live pcap device capture (Npcap loaded at runtime) |
| PacketDotNet | 1.4.8 | Packet parsing (Ethernet/IP/TCP/UDP/payload) |
| ICSharpCode.Decompiler | 11.0.0.9375 | ILSpy-based C# decompilation backend |
| Mono.Cecil | 0.11.5 | Assembly tree / metadata model |
| System.Drawing.Common | 8.0.10 | Animated GIF delta-frame rendering |
| Microsoft.Diagnostics.Tracing.TraceEvent | 3.1.13 | ETW real-time session (collectors & service) |
| System.Management / EventLog / ServiceProcess | 8.0.0 | WMI, event-log, service enumeration |
| Microsoft.NET.Test.Sdk + xunit | 17.8.0 / 2.6.2 | Unit tests |

### Native (C / C++)

- **HookEngine** — 49-slot inline hook engine (self-hook + remote `CreateRemoteThread` injection), structured
  exception-free trampoline hot-patching of ntdll/user32/ws2_32, two 16 MB shared-memory rings
  (`Local\ValhallaHookRing`, `Local\ValhallaNetRing`), up to 8 configurable network **mod rules**.
- **NativeAnalyzer** — Rich header parser, compiler fingerprint, packer detection, import/TLS/entropy analysis.
- **PeNative** — native PE parser consumed by `PeAnalyzer` for section/entropy/overlay math.
- **MalwareAnalyzer.Driver** — WDM driver, WDK **10.0.28000.0**, `_WIN32_WINNT=0x0A00`, CFG enabled.
- **LicenseCore** — C++17, `winhttp.lib` + `bcrypt.lib`, builds without the VMProtect SDK (markers are no-ops then).

---

## 7. Requirements

### Runtime
- **Windows 10 x64 or Windows 11** (32-bit is not supported for the native engines).
- **.NET 8 Runtime** (bundled by the published app if you publish self-contained).
- **Administrator privileges** — the app requests `requireAdministrator` in `app.manifest` because ETW system
  providers, memory scanning, driver/AMSI exposure and some registry keys need elevation.
- **Npcap** (optional but recommended) — required **only** for the *Live Network* / real pcap capture tabs.
  Install from [npcap.com](https://npcap.com); SharpPcap finds the well-known install path at runtime.

### Build
| Tool | Version | Who needs it |
|---|---|---|
| .NET SDK | 8.0+ | Everyone (managed build & tests) |
| Visual Studio 2022 | any edition | WPF dev / solution browsing |
| WDK | 10.0.28000.0 | Kernel driver build (`MalwareAnalyzer.Driver.vcxproj`) |
| MSVC toolchain (cl.exe, VS2022 v143) | x64 | Native DLLs (HookEngine, NativeAnalyzer, PeNative, LicenseCore) |
| C++/CLI or CMake | — | not required (native build is plain `cl.exe`) |

---

## 8. Building from source

### 8.1 Managed app (recommended path)

```powershell
# from the repository root
dotnet restore Hunter.sln
dotnet build src/MalwareAnalyzer.UI/MalwareAnalyzer.UI.csproj -c Release
```

Or open `Hunter.sln` in Visual Studio 2022 and build the `MalwareAnalyzer.UI` project. Building the UI transitively
builds `Core`, `Collectors`, `Forensics`, `Detection`, `Memory` and `Decompiler` through project references.

Output lands in `src/MalwareAnalyzer.UI/bin/Release/net8.0-windows/`. The three prebuilt native DLLs
(HookEngine, NativeAnalyzer, PeNative) are copied from `src/MalwareAnalyzer.UI/native/` by the csproj.

### 8.2 Native engines

The UI expects **x64** DLLs named exactly `HookEngine.dll`, `NativeAnalyzer.dll` and `PeNative.dll` next to the
executable (the csproj copies them from `native\`). Prebuilt binaries are already committed in
`src/MalwareAnalyzer.UI/native/` so the repo builds out of the box. To rebuild them from source:

```bat
REM HookEngine — from src\HookEngine (x64 Native Tools Command Prompt)
cl /LD /O2 /EHsc /DHOOKENGINE_EXPORTS hook_engine.cpp /Fe:HookEngine.dll

REM NativeAnalyzer — from src\NativeAnalyzer
cl /LD /O2 native_analyzer.cpp /Fe:NativeAnalyzer.dll

REM PeNative — from src\MalwareAnalyzer.UI\native
cl /LD /O2 PeNative.c /Fe:PeNative.dll

REM Copy all three into src\MalwareAnalyzer.UI\native\ so the csproj picks them up.
```

> `smoke.c` / `ldetest.c` files in the native folders are standalone C harnesses for quick command-line testing of the
> engines and are not part of the product build.

### 8.3 Kernel driver (`MalwareAnalyzer.sys`)

The driver is optional — everything else works without it. Build with Visual Studio + WDK:

1. Open `src/MalwareAnalyzer.Driver/MalwareAnalyzer.Driver.vcxproj` (WDM flavor).
2. Select **x64 / Release** and build.
3. Enable test signing on the target machine: `bcdedit /set testsigning on` (then reboot).
4. Load with a signed test cert or your lab environment's driver loader (e.g. `sc create` / `Rundll32` loader of your
   choice in a VM). The device node is `\Device\MalwareAnalyzer`, symbolic link `\DosDevices\MalwareAnalyzer`.

**Driver interface**

| IOCTL | Purpose |
|---|---|
| `IOCTL_MALWARE_ANALYZER_GET_VERSION` (0x800) | Version info + total events |
| `IOCTL_MALWARE_ANALYZER_GET_PROCESS_EVENTS` (0x801) | Drain process create/exit queue |
| `IOCTL_MALWARE_ANALYZER_GET_IMAGE_LOAD_EVENTS` (0x802) | Drain image-load queue |
| `IOCTL_MALWARE_ANALYZER_SET_MONITOR_ACTIVE` (0x803) | Start/stop kernel monitoring |

Callbacks registered in `DriverEntry`: `PsSetCreateProcessNotifyRoutineEx` and `PsSetLoadImageNotifyRoutine`.
Events are stored in a **spinlock-protected ring buffer (1024 events)**; the newest event wins when full, so the
user-mode side never blocks the kernel.

### 8.4 LicenseCore (optional licensing DLL)

```bat
REM from src\LicenseCore
build_vs.bat          REM VS2022 x64 Release → bin\x64\Release\LicenseCore.dll
```

VMProtect integration is optional and **disabled by default** (see `vmprotect.h` `MA_USE_VMPROTECT`). Even without the
SDK the DLL builds, and `ma_verify` performs HWID + network + self-tamper licensing when the host app calls it. The
UI does not hard-depend on this DLL.

### 8.5 Tests

```powershell
dotnet test src/MalwareAnalyzer.Tests/MalwareAnalyzer.Tests.csproj
```

Covers the PE analyzer and the rule engine.

---

## 9. Running the application

1. **Install Npcap** (only needed for Live Network tabs): [npcap.com](https://npcap.com).
2. **Run as Administrator** — right-click → *Run as administrator* (the manifest enforces this).
3. Splash window plays, then the main workbench fades in.
4. Click **Refresh** to snapshot the machine: processes, services, persistence, network, tasks, registry, drivers,
   software, SRUM, hardware, Wi-Fi/BT, event logs.
5. Open the tab you care about:
   - `Processes` → select a process → **Deep-dive** (PE, strings, YARA, VT, disassembly, memory regions, Sysmon
     correlation).
   - `Malware Hunt` → one-click triage across all detectors with severity verdicts.
   - `DriverHunter` → **Scan All Loaded Drivers** or audit a specific `.sys` file.
   - `Live Network` → pick the pcap device → **Start** → watch packets and payload hex.
   - `AMSI Monitor` / `Script Monitoring` → watch PowerShell 4104 telemetry and deobfuscated content.
   - `Forensics` / `Historical` → Prefetch, Shimcache, UserAssist, USN Journal, Shellbags, LNK/JumpLists + correlated
     timeline.
6. Use the auxiliary windows for deeper work:
   - **API Hook Engine**: target PID → *Enjekte Et* (Inject) → live API call stream.
   - **Decompiler**: drop any `.exe`/`.dll` → managed IL or native PE analysis.
   - **Report**: export current session as **CSV** or **JSON**.

---

## 10. Feature deep-dive

### 10.1 Collection layer (`MalwareAnalyzer.Collectors`)

All collectors are thin services wrapping Win32/ETW/WMI reads and are exposed through interfaces in `Core/Interfaces`.

| Collector | Source | Notes |
|---|---|---|
| `ProcessCollector` | Toolhelp32 + OpenProcessToken | integrity level, Authenticode, ReputationEvaluator scoring |
| `ServiceCollector` | SCManager / `System.ServiceProcess` | name, path, start type, state |
| `PersistenceCollector` | Registry autoruns, IFEO, Winlogon, Defender exclusions, startup folders | |
| `NetworkCollector` | `GetExtendedTcpTable` | active TCP/UDP with PID→process resolution |
| `NetworkTelemetryCollector` / `NetworkActivityMonitor` | Win32 diffing | 2 s delta network monitor |
| `ProcessNetworkAnalyzer` | per-PID network contacts (IP/URL, GET/POST, TLS) | |
| `TaskCollector` | `schtasks /query /v /fo csv` | scheduled tasks |
| `RegistryCollector` | Registry | sensitive-key audits + full browser (`RegistryKeyNode` inventory) |
| `DriverCollector` | psapi `EnumDeviceDrivers` | loaded kernel modules |
| `SoftwareCollector` | Uninstall registry key | installed software |
| `SrumCollector` | **synthesizes** from running processes | *approximation*, does not read `SRUDB.dat` |
| `HardwareCollector` | WMI + registers | CPU/RAM/disk/GPU + USB history |
| `LolbinCollector` | process list | 14 known LOLBins flagged |
| `EventLogCollector` | `System.Diagnostics.Eventing.Reader` | event log queries |
| `EtwCollector` | `TraceEvent` | real-time ETW session (`StartRealtimeSession`) — admin required |
| `AmsiCollector` | PowerShell 4104 consumer | AMSI script events + deobfuscation stream |
| `TelemetryHistoryStore` | `%LocalAppData%\MalwareAnalyzer\` | JSONL telemetry persistence + cap |
| `ReputationEvaluator` | static heuristics | lightweight reputation score per file |

### 10.2 Detection engines (`MalwareAnalyzer.Detection` → `MalwareAnalyzer.Engines.dll`)

| Engine | What it detects |
|---|---|
| **RuleEngine** | MITRE-mapped behavioral rules on processes, persistence, network, registry, events. Output is typed `DetectionRule` records with severity; drives `Triage`, `Malware Hunt`, `Timeline`. |
| **DriverAnalysisEngine** | BYOVD database of **20+ known-vulnerable drivers** (with CVE, threat actors, remediation) + static kernel-API capability matrix (RWX, MSR, physical memory, IOCTL, VMX…) + composite **0–100** heuristic score and certificate validation. |
| **AmsiAnalysisEngine** | AMSI bypass patterns, obfuscation markers, suspicious PowerShell constructs. |
| **EtwThreatEngine** | C2-ish ports/directories and suspicious ETW event correlation. |
| **YaraEngine** | Regex-based rule engine (not libyara): scans files **and** live process memory; rule store auto-provisioned at `%LocalAppData%\MalwareAnalyzer\yara-rules`. |
| **PeAnalyzer** + `NativePeParser` | RWX sections, high Shannon entropy, timestomping, overlays, suspicious section names; native math via `PeNative.dll`. |
| **CodeDisassembler** | Own x64 decoder; flags `syscall`/`sysenter`/`rdtsc`; emits mnemonic + operand listings. |
| **DumpAnalyzer** | Minidump `MDMP` header parse + string IOCs. |
| **VirusTotalClient** | SHA-256 lookup via `VT_API_KEY` env var; embedded hash DB fallback when offline. |
| **HookVerdictEngine** *(UI)* | Scores HookEngine telemetry and emits Turkish verdicts: `TEMİZ` / `ŞÜPHELİ` / `ZARARLI` / `KRİTİK`. |

### 10.3 Forensics parsers (`MalwareAnalyzer.Forensics`)

| Parser | Artifact |
|---|---|
| `PrefetchParser` | `.pf` files incl. Windows 10 compressed MAM blocks (`RtlDecompressBufferEx`, XPRESS-HUFF) |
| `ShimcacheParser` | AppCompatCache `10ts` registry blob |
| `UserAssistParser` | ROT13-deobfuscated `HKCU\...\UserAssist` |
| `UsnJournalParser` | NTFS change journal via `FSCTL_READ_USN_JOURNAL` |
| `ShellbagsParser` | Folder navigation artifacts (some dates are static placeholders — see limitations) |
| `LnkJumpListParser` | `.lnk` shortcuts + Jumplist binaries |
| `HistoricalForensicsEngine` | Cross-artifact timeline correlation with severity rating |

### 10.4 Memory scanner (`MalwareAnalyzer.Memory`)

`ProcessMemoryScanner` sweeps a process with `VirtualQueryEx` looking for RWX / private-executable regions, then
`ProcessMemoryScanner.Deep.cs` performs a deep scan: PE-injection signature (MZ bumps in committed regions), NOP/INT3
sleds, common shellcode byte patterns, Shannon entropy thresholds, plus heap/stack/PEB/TEB walking and a
**whole-system sweep** across all processes. Identified regions can be dumped to disk for offline analysis.

### 10.5 Decompiler (`MalwareAnalyzer.Decompiler`)

A dual pipeline:

1. **Custom managed-IL decompiler** — `DecompilerEngine` reads PE metadata (`Met/`, `Il/`), builds method bodies
   (`BodyBuilder`), resolves tokens (`ResolveContext`, `SignatureReader`) and emits source via `SourceWriter` across
   the supported `Language/` back-ends. Language detection decides managed vs native at load time.
2. **ILSpy / dnSpy-style** — `Cecil/` wraps `Mono.Cecil` + `ICSharpCode.Decompiler` for a full-module C# view and a
   Cecil assembly tree exposing type/method graphs, string literals, IP addresses and base64 blobs.

Native (unmanaged) binaries are routed to `Native/NativeAnalyzerBridge.cs` → `NativeAnalyzer.dll`.

### 10.6 Network capture (`Network/PacketCapturePcap.cs`)

- SharpPcap **6.3.0** + PacketDotNet **1.4.8** — the Wireshark family.
- Npcap is discovered at runtime from its well-known install path; no bundled driver, no injection.
- Captures global, payload-includable traffic; the UI shows packet tree + payload hex with a filter box.
- A second, independent stream (`ValhallaNetRing`) comes from the native HookEngine on ws2_32 send/recv paths.

### 10.7 HookEngine (native, `src\HookEngine`)

A C engine that:

- Installs **inline API hooks** (x64 trampolines, hot-patched into ntdll / user32 / ws2_32 modules, or only ntdll) for
  a **49-slot catalog** — NtWriteVirtualMemory, NtProtectVirtualMemory (33), NtAllocateVirtualMemory (34),
  NtCreateThreadEx (35), GetAsyncKeyState (36), GetKeyState (37), plus keyboard/clipboard APIs and the ws2_32 send/
  recv family.
- Preserves **explicit-syscall** integrity via `r11` (the syscall-number convention) for post-W10 AMSI-style hooks.
- Emits structured `HEHookEvent` records (timestamp, PID/TID, API catalog index, formatted args, return, direction,
  up to 512-byte payload) into a **16 MB** shared memory ring (`Local\ValhallaHookRing`).
- Supports **remote injection**: `he_inject_process(pid, …)` and `he_spawn_and_inject(exe, …)` using
  `CreateRemoteThread`.
- Applies optional **network modification rules** (`he_set_mod_rule`) on send/recv/WSASend/WSARecv payloads —
  a transparent HTTP/non-TLS research hook, disabled by default.
- `he_total_calls(apiId)` per-API counters.

> The engine is fully opt-in: nothing hooks until you open a ring and enable hooks from the API Hook Engine window.

### 10.8 NativeAnalyzer (native, `src\NativeAnalyzer`)

Deep PE/executable analysis: **Rich header** (compiler/linker provenance), compiler fingerprinting, packer/protector
heuristics, import table scans, **TLS callbacks**, section entropy, and a summary view. `smoke.c` is a CLI harness.

### 10.9 Kernel driver (`MalwareAnalyzer.Driver`)

Optional WDM driver for **lightweight kernel telemetry** that survives user-mode tampering:

- `PsSetCreateProcessNotifyRoutineEx` → process create/exit events (PID, PPID, creating thread, FILETIME, image name,
  command line).
- `PsSetLoadImageNotifyRoutine` → image-load events (PID, image base/size, kernel-driver flag, full path).
- 1024-event spinlock ring; IOCTLs above; device `\Device\MalwareAnalyzer`.

### 10.10 Telemetry service (`MalwareAnalyzer.Service`)

`Worker.cs` (BackgroundService) starts a real-time **ETW session** (`EtwCollector.StartRealtimeSession`) and logs events;
registered as Windows service `MalwareAnalyzerTelemetryService` via `AddWindowsService`. Administrative rights are
required for the ETW session.

### 10.11 Licensing module (`LicenseCore`, optional)

- `ma_verify` → token + **HWID** (SMBIOS UUID + disk serial → SHA-256) + optional network validation (WinHTTP POST).
- Self-file tamper hash — a patched DLL silently poisons session tokens.
- `vmprotect.h` supplies no-op markers (`MA_VMP_ULTRA/_VM/_MUT`) usable without the SDK; see
  `VMProtect_Yonlendirme.md` for the mapping. **Disabled by default.**

---

## 11. Configuration

| Setting | How to set | Default / notes |
|---|---|---|
| VirusTotal API key | environment variable `VT_API_KEY` | Without it, only the embedded hash DB is used |
| YARA rule directory | auto-provisioned | `%LocalAppData%\MalwareAnalyzer\yara-rules` |
| Telemetry persistence | automatic | `%LocalAppData%\MalwareAnalyzer\` (JSONL history store) |
| Kernel driver device | driver-loaded only | `\\.\MalwareAnalyzer`; UI reports `NOT INSTALLED` otherwise |
| Sysmon bundling | optional | `Samples\Drivers\SysmonDrv.sys` copied to output **only if present** (the csproj item is conditional) |
| Event caps | collectors | stream caps ~1,500–20,000 depending on stream |

---

## 12. Known limitations

Being honest about what this workbench does *not* do:

- **SRUM** is a *live approximation* built from running processes — it does **not** parse `SRUDB.dat`, so anomaly values
  may differ from the true database.
- **Shellbags** folder dates are static placeholders in the parser output.
- **YARA is regex-based**, not the real libyara engine — treat results as heuristics.
- **VirusTotal** needs an API key for live lookups; without one it falls back to the embedded hash DB.
- **ETW system providers, memory scanning, AMSI and several registry reads require Administrator**; the manifest
  therefore demands elevation, which will trigger your own AV/EDR.
- **Driver console (`\\.\MalwareAnalyzer`)** is only active when the test-signed kernel driver is loaded (WDK build).
- **Live packet capture needs Npcap**; without it the pcap engine is skipped but the collectors still work.
- Some collectors are synchronous on the first refresh; very large system inventories can take several seconds.
- The native engines are **x64-only**; the UI targets `AnyCPU;x64`.
- A few UI chrome strings are Turkish while most labels are English (mixed i18n).

---

## 13. FAQ / Troubleshooting

**Q: `HookEngine.dll nerede? / HookEngine.dll not found`**
A: Copy `HookEngine.dll` (x64) next to the executable. The repo ships it in `src/MalwareAnalyzer.UI/native/`.

**Q: Live Network shows no devices.**
A: Install Npcap and restart. The engine uses SharpPcap's `CaptureDeviceList`.

**Q: ETW says "unavailable".**
A: Run as Administrator; system ETW providers deny non-elevated callers.

**Q: `\\.\MalwareAnalyzer` reports NOT INSTALLED.**
A: That is expected unless the WDK driver is built, test-signing enabled and the driver loaded.

**Q: Build fails with MSB3552 / missing file?**
A: Restore packages first (`dotnet restore`). The only content item that could go missing is the optional
`Samples\Drivers\SysmonDrv.sys` — it is conditional (`Exists`) and skips gracefully.

**Q: How do I stop a hook session?**
A: Use the API Hook Engine window (stop + unhook) or `he_unhook_all()`; rings are cleaned on process exit.

**Q: The app demands Administrator and my AV flags it.**
A: Expected. Elevation is required by design; add an exclusion if you trust your build.

**Q: Can I run the tests without Visual Studio?**
A: Yes — `dotnet test`.

---

## 14. Security & responsible use

- This is a **DFIR/research tool**, not an anti-virus product. Verdicts are heuristic hints, not proof.
- Only run against **systems you own or have written authorization to inspect**. Hooking, injection and kernel
  telemetry are invasive; make sure you understand the implications.
- The included kernel driver and hook engine implement techniques that **can be abused** — keep your build offline
  unless you need it, and never ship the driver to production endpoints.
- Telemetry is stored locally (`%LocalAppData%\MalwareAnalyzer`) — treat it as potentially sensitive forensic data.
- The `LicenseCore` module phoning home: if you build without it, remove it from the output; the app degrades
  gracefully.

---

## 15. Roadmap

Ideas for future work (PRs welcome):

- Real `libyara` / `yara-x` engine integration.
- True `SRUDB.dat` parsing (ESENT).
- EDR-style kernel ETW provider alignment (Microsoft-Windows-Sysmon schema parity).
- More BYOVD/LOLDrivers signatures + dynamic C2 beacon heuristics.
- Packaged `RuntimeIdentifier=win-x64` single-file publish and MSI installer.
- Dark/light theme and full i18n (tr/en).
- Threat-hunting queries (Sigma-ish) over the JSONL telemetry store.

---

## 16. Contributing

1. Fork and clone.
2. Create a feature branch.
3. Make changes; keep the `.gitignore` honored (never commit `bin/`, `AltOut/`, `obj/`).
4. Run `dotnet test src/MalwareAnalyzer.Tests`.
5. If you touch the native DLLs, rebuild them per §8.2 and update the committed binaries in `src/MalwareAnalyzer.UI/native/`.
6. Open a pull request describing the change and any verification performed.

### Code style
- `net8.0-windows`, nullable enable, implicit usings, `AllowUnsafeBlocks` where needed.
- Keep core-independent layering: `UI → engines`, `engine → Core` only.
- No comments unless they clarify non-obvious security logic (existing code style).

---

## 17. License

**MIT** — see [LICENSE](LICENSE). Third-party notices:

- **SharpPcap / PacketDotNet** — MIT (Wireshark-family licensing for packet capture).
- **ICSharpCode.Decompiler (ILSpy)** — MIT.
- **Mono.Cecil** — MIT.
- **Microsoft.Diagnostics.Tracing.TraceEvent** — MIT.
- **Sysmon** is a Microsoft tool used only for detection-status reporting (never bundled with this repo).

---

## 18. Acknowledgements

- Chris Sanders & Jasmin L. (Wireshark 101) and the SharpPcap maintainers for the capture stack inspiration.
- The ILSpy / dnSpy teams for the decompiler integration.
- Microsoft Sysinternals & the Sysmon community for the DFIR mindset this tool formalizes.
- Research references/public IOCs used inside `DriverAnalysisEngine` and `YaraEngine` are documented inline in the
  rule comments.