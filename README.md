<div align="center">

# 🛡️ CUSTOS FORENSIC SUITE

### Portable Windows Digital Forensics & Incident Response

**Acquire evidence. Organize findings. Support investigations.**

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-In_Development-F59E0B?style=for-the-badge)
![Project](https://img.shields.io/badge/Project-Final_Year_Project-6366F1?style=for-the-badge)

**Artifact Acquisition · Modular Collectors · Evidence Management · Forensic Reporting**

[Overview](#-overview) •
[Artifacts](#-artifact-coverage) •
[Getting Started](#-getting-started) •
[Roadmap](#-development-roadmap) •
[Team](#-authors-and-team)

</div>

---

## 📖 Overview

**Custos Forensic Suite** is a Windows-focused digital forensic acquisition project developed as a Final Year Project in **BS Cyber Security at Riphah International University**.

The project brings individual artifact collectors into a modular platform for acquiring system, memory, network, user-activity, and application evidence. Its planned desktop application will coordinate collection, organize cases, verify evidence integrity, and generate investigation reports.

The agentless design aims to avoid installing a persistent service on the target system. Individual collectors may still require administrator access, external utilities, or temporary acquisition drivers.

> **Development stage:** Artifact collector development and validation. Collector-level SHA-256 hashing, saved-file verification, and combined integrity reports are implemented. GUI integration, case management, case-level integrity services, encryption, and investigation reporting are planned application capabilities. Artifact coverage below describes the project scope rather than a certification that every collector is complete.

## 🎯 Project Objectives

| Objective | Intended Outcome |
|---|---|
| **Modular acquisition** | Independently runnable collectors with clearly defined responsibilities. |
| **Reliable output** | Results validated against their source or a suitable reference tool. |
| **Accessible operation** | Consistent launchers, readable documentation, and a planned desktop interface. |
| **Structured investigations** | Organized cases, evidence references, and collection records. |
| **Evidence integrity** | Hash generation and verification integrated into the case workflow. |
| **Protected storage** | Encryption for evidence storage and controlled exports. |
| **Clear reporting** | Reports that connect findings to collected evidence and documented limitations. |

## 🧩 Project Modules

| Module | Role |
|---|---|
| 📂 **Artifact Collectors** | Acquire individual artifacts using suitable Windows interfaces and specialist tools. |
| ⚙️ **Collection Controller** | Coordinate collector execution, dependencies, progress, and errors. |
| 🎛️ **Acquisition Profiles** | Define the scope and order of Quick, Standard, Full and custom collection. |
| 🖥️ **Desktop Interface** | Provide collection controls, result browsing, and case navigation. |
| 🗃️ **Case Management** | Maintain case details, examiner information, output locations, and evidence records. |
| 🔐 **Integrity and Protection** | Hash, verify, and encrypt evidence through case-level services. |
| 📋 **Chain of Custody** | Record evidence handling and relevant case actions. |
| 📅 **Timeline and Analysis** | Normalize supported records and connect related activity. |
| 📑 **Reporting and Export** | Produce readable reports and structured case exports. |

## 📂 Artifact Coverage

Artifacts are grouped by investigative purpose. Individual collector documentation defines the exact source, method, dependencies, privileges, and output.

### 🖥️ System Information

- Computer and Operating System Information
- Hardware Information
- BIOS/UEFI Information
- Installed Updates
- Time-Zone Configuration
- Installed Applications
- Services
- Drivers

### ⚡ Processes and Memory

- RAM Acquisition
- Running Processes
- Thread Inventory
- DLL and Module Inventory
- Handle Inventory
- Mutex/Mutant Metadata
- Crash Dumps
- Pagefile Metadata

### 🪟 Windows Configuration and Logs

- Registry Hives
- Windows Event Logs
- Security, System, and Application Log Channels
- Task Scheduler Logs
- Scheduled Tasks
- Startup Programs
- WMI Information
- Audit and Event-Log Configuration

### 👤 Accounts and User Activity

- Local Users
- Local Groups
- Logon Sessions
- Account Password Policy Metadata
- Recent Files
- Jump Lists
- LNK Files
- UserAssist
- Shellbags
- BAM Activity
- PowerShell History
- Command Prompt History
- Remote Desktop History
- Clipboard Information
- Screenshot Metadata

### 🌐 Browser Artifacts

- Browsing History
- Download History
- Cookies
- Browser Cache
- Browser Profiles
- Web Data
- Login Data Records, Subject to the Approved Collector Scope

### 🌍 Network Artifacts

- Active Network Connections
- Listening Ports
- TCP Sessions
- SMB Sessions
- Network Shares
- Network Adapters and IP Configuration
- DNS Cache
- ARP Cache
- Hosts File
- DNS and Hosts Context
- Wi-Fi Profiles
- Firewall Configuration and Logs
- WinRM Remoting Configuration
- BITS Transfer Jobs

### 📁 File System and Execution History

- Master File Table — MFT
- USN Journal
- Recycle Bin
- Prefetch
- Amcache
- Shimcache
- SRUM Database
- Temporary Files
- Desktop Metadata
- Downloads Metadata
- Documents Metadata
- Volume Shadow Copies
- Restore Points

### 🔌 Devices and Storage

- USB Device History
- Mounted Devices
- Device History
- Bluetooth Information
- BitLocker Metadata

### 🛡️ Security Artifacts

- Microsoft Defender Metadata
- Windows Defender Logs
- Certificates

## 🚀 Acquisition Profiles

The application will provide four collection profiles. Their exact collector lists and priorities will be maintained in the finalized profile configuration.

| Profile  | Intended Use | Collection Scope |
|----|---|---|
| ⚡ **Quick**  | Initial triage | A focused selection of priority artifacts. |
| 🔍 **Standard**  | Routine investigation | A broader selection of system, user, application, and network artifacts. |
| 🧪 **Full**  | Extended acquisition | The configured set of supported collectors, subject to availability and permissions. |
| ⚙️ **Custom**  | User-defined acquisition | Displays all supported artifacts with checkboxes. Only checked artifacts are collected, subject to availability and permissions. |

The collection controller determines execution order. Collectors remain independently runnable so they can be developed, validated, and reused across profiles.

## 🖥️ Planned Desktop Dashboard

| Area | Features |
|---|---|
| **Case Overview** | Case details, examiner information, target system, and evidence destination. |
| **Acquisition** | Profile selection, individual collector selection, and collection controls. |
| **Preflight Checks** | Privileges, dependencies, source availability, and free storage. |
| **Live Progress** | Running, completed, failed, and skipped collector states. |
| **Evidence Explorer** | Output folders, supported previews, and collection metadata. |
| **Search and Filtering** | Searchable records with artifact-specific filters. |
| **Timeline** | Chronological display of supported normalized events. |
| **Integrity** | Hash records and verification results. |
| **Reports** | Report configuration, generation, and case export. |

The GUI will invoke the collection controller directly. Standalone batch launchers remain available for individual collector operation.

## 🔐 Planned Evidence Protection

| Capability | Design Direction |
|---|---|
| **Evidence Hashing** | Implemented collector-level SHA-256 hashes for saved outputs; case-level integration is planned. |
| **Integrity Verification** | Implemented independent two-read saved-file hash comparison with metadata stability checks; case-level verification is planned. |
| **Evidence Encryption** | AES-256-GCM with authenticated encryption. |
| **Key Management** | Defined handling of encryption keys, passwords, and recovery requirements. |
| **Chain of Custody** | Evidence identifiers, handling events, timestamps, and examiner records. |
| **Audit Logging** | Acquisition actions, processing outcomes, and relevant case changes. |

These services will be integrated after standalone collection. A hash establishes whether data has changed relative to the hashed version; it does not establish whether acquisition was complete or accurate.

## 🔄 Collection Workflow

### Current Collector Workflow

```text
Select Artifact
      │
      ▼
Run launch.bat
      │
      ▼
Check Administrator Access
      │
      ▼
Select Output Location
      │
      ▼
Collect Available Data
      │
      ▼
Save Results and Collection Status
      │
      ▼
Review and Validate Output
```

### Planned Integrated Workflow

```text
Open or Create Case
      │
      ▼
Select Profile and Evidence Destination
      │
      ▼
Check Requirements and Storage
      │
      ▼
Execute Selected Collectors
      │
      ▼
Organize and Verify Evidence
      │
      ▼
Apply Configured Evidence Protection
      │
      ▼
Review Supported Analysis and Timeline
      │
      ▼
Generate Report and Export Case
```

Custody and audit events will be recorded throughout the integrated workflow.

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| **Python 3.12** | Collector implementation, processing, and application integration. |
| **Windows APIs** | Access to supported operating-system information. |
| **PowerShell and Windows Utilities** | Artifact-specific queries and collection operations. |
| **Windows Batch** | Collector startup and administrator elevation. |
| **Specialist Acquisition Tools** | Artifact acquisition where dedicated utilities are required. |
| **Artifact Parsers** | Interpretation of supported binary and structured formats. |
| **PySide6 — Planned** | Desktop GUI. |
| **SQLite — Planned** | Case metadata and supported normalized records. |
| **SHA-256 — Implemented** | Collector-level saved-output hashing and verification; case-level integration is planned. |
| **Cryptography Libraries — Planned** | Authenticated encryption and protected exports. |
| **HTML, PDF, JSON, and CSV — Planned** | Reporting and structured export. |

Dependencies differ by collector. Its `<Artifact Name>_Guide.md` documents the actual APIs, commands, libraries, and tools used.

## 📁 Repository Structure

The following illustrates the collector-oriented organization. Exact folder and setup-script names should match the checked-out repository.

```text
Custos/
│
├── docs/
├── tests/
├── setup_environment.bat
├── requirements.txt
└── README.md
└── artifacts/
    │
    ├── A01 - RAM/
    ├── A02 - Running Processes/
    ├── A03 - Network Connections/
    ├── A04 - DNS Cache/
    ├── A05 - ARP Cache/
    ├── A06 - Services/
    │
    └── ... remaining baseline and additional collectors
```

A collector contains only the files and dependencies it needs:

- **`launch.bat`** — entry point and administrator-access check.
- **Collector implementation** — acquisition and output logic.
- **`<Artifact Name>_Guide.md` documentation** — requirements, usage, output fields, and validation.
- **External tools** — where required and permitted by their distribution terms.
- **Collection outputs** — saved to the selected destination.

## ⚙️ Requirements

| Requirement | Details |
|---|---|
| **Operating System** | Windows; exact supported versions depend on the collector. |
| **Python** | Python 3.12. |
| **Privileges** | Administrator access where required. |
| **Dependencies** | Libraries and tools specified by the selected collector. |
| **Storage** | Sufficient free space for the acquisition and its outputs. |

RAM and large file acquisitions can require substantially more space than metadata collection.

## 🚀 Getting Started

### 1. Set Up the Environment

Open the project directory and run the environment setup batch file.

```bat
setup_environment.bat
```

If its filename differs in the repository, use the actual file provided. Follow its instructions and review any collector-specific requirements.

### 2. Open an Artifact Folder

Select the artifact you want to collect and read its `<Artifact Name>_Guide.md`.

### 3. Start the Collector

Run:

```bat
launch.bat
```

The launcher checks administrator access and requests elevation where required. Elevation logic is contained in the launcher itself.

### 4. Select the Save Location

Enter a custom output path when prompted, or leave the input blank to use the collector’s default artifact location.

Additional source-specific input may be required by individual collectors.

### 5. Review the Output

Check the generated results, completion status, warnings, and errors. Use the collector documentation to interpret its fields and perform validation.

## 📑 Output and Reporting

### Collector Results

Output varies by artifact and can include native evidence files, structured data, and readable result views. The default destination follows `<Artifact Name>_Output`; custom destinations are supported. The main structured result uses `<Artifact Name>_Output.json` where applicable; acquisition-specific result names and layouts remain documented in the artifact guide. Each collection produces one `<Artifact Name>_Hash & Timestamp Report.json` combining hashes, verification timestamps, and manifest information, rather than separate hash, manifest, summary, or verification reports. Native evidence files retain their acquisition-specific names.

All collectors use the same integrity-report fields. Each listed saved file is read twice independently for SHA-256 calculation; matching hashes and unchanged file metadata are required for a verified status. These are post-save checks, not proof of source-to-output equivalence or acquisition-time integrity. Existing historical outputs are not rewritten.

Collection records should identify:

- Artifact and source.
- Collection date, time, and time-zone context.
- Collection method.
- Destination and generated files.
- Success, failure, or partial completion.
- Unavailable information and known limitations.

### Planned Reports

| Report | Contents |
|---|---|
| **Executive Report** | Investigation scope, supported findings, and significant limitations. |
| **Technical Report** | Collection details, methods, evidence references, and relevant records. |
| **Artifact Report** | Artifact-specific results and field explanations. |
| **Timeline Report** | Supported events arranged chronologically with source references. |
| **Integrity Report** | Collector-level JSON reports are implemented; integrated case-level integrity reports are planned. |
| **Case Export** | Selected reports, structured records, and associated evidence references. |

Planned output formats include **HTML**, **PDF**, and **JSON**, depending on the report and data type.

## ✅ Validation and Quality

Collector validation covers:

- Comparison with appropriate Windows sources or trusted reference tools.
- Review of field meanings, timestamps, and record counts where applicable.
- Handling of missing sources, denied access, and empty results.
- Clear reporting of errors and partial collection.
- Documentation of the tested Windows environment.
- Confirmation that output can be interpreted using the collector's `<Artifact Name>_Guide.md`.

Implementation and validation status must be documented per collector. Successful execution alone does not prove complete acquisition.

## 🗺️ Development Roadmap

| Phase | Focus |
|---|---|
| **Artifact Collection** | Develop and validate standalone collectors. |
| **Integration** | Establish the collector interface, controller, and acquisition profiles. |
| **Desktop Application** | Build the dashboard and results explorer. |
| **Evidence Management** | Add cases, integrate existing collector hashes and verification, and add custody records and encryption. |
| **Analysis and Reporting** | Add supported timelines, correlation, reports, and exports. |
| **Release Preparation** | Validate integration, document deployment, and package the application. |

## 🔮 Future Enhancements

- Portable deployment on external SSDs and future dedicated acquisition hardware.
- Offline evidence collection and analysis.
- Extended memory analysis.
- Rule-based detection and IOC matching.
- Evidence-linked AI summaries.
- Cross-artifact timeline correlation.
- Plugin-based collector expansion.
- Controlled concurrency for suitable collection tasks.
- Remote acquisition research.
- Linux and macOS support.
- Threat-intelligence and SIEM integration.

## 👨‍💻 Authors and Team

| Team Member | Project Role |
|---|---|
| **Ayan Shahid** | Project Lead and Artifact Collector Developer |
| **Muhammad Tayyab Ayub** | Artifact Collector Developer |
| **Muhammad Faizan Ali** | Artifact Collector Developer |

The team shares responsibility for research, implementation, documentation, validation, and integration according to the approved work allocation.

**Academic Program:** Bachelor of Science in Cyber Security  
**Institution:** Riphah International University

## 📄 Licensing and Third-Party Tools

Project licensing is governed by the license file provided in the repository, when present. Academic development alone does not define a software license.

Third-party tools and libraries retain their respective licenses and redistribution requirements.

## ⚠️ Usage

Use Custos only on systems and evidence you are authorized to examine.

Live acquisition can change system state. Collection methods, errors, and limitations should be documented as part of the investigation.

