# 🔐 Universal Log Pre-processing Framework (ULPF)

> **Different Logs. One Processing Layer. One Standardized Output.**

ULPF is a **vendor-neutral, extensible and offline-capable log pre-processing framework** designed to ingest heterogeneous logs, automatically detect their format, parse and normalize them into a common schema, while preserving the original event for forensic traceability.

Developed as part of **Smart India Hackathon 2026**.

---

## 🚀 Overview

Modern organizations generate logs from almost every component of their infrastructure:

* Network Devices
* Firewalls
* Servers
* Operating Systems
* Applications
* Databases
* Cloud Platforms
* Containers
* Endpoint Security Tools
* Identity & Access Management Systems
* IoT Devices
* Custom Enterprise Software

The problem is that all these systems generate logs in different formats.

Common examples include:

```text
Syslog
JSON
XML
CSV
CEF
LEEF
Custom / Proprietary Formats
```

Security teams often need to create and maintain different parsers for every source before the logs can be used in SIEMs, analytics platforms, data lakes, or threat detection systems.

**ULPF solves this problem by introducing a universal preprocessing layer between raw log sources and downstream analytics platforms.**

---

# ❗ Problem

A typical enterprise logging environment looks like this:

```text
Different Log Sources
        ↓
Different Formats
        ↓
Different Field Names
        ↓
Source-Specific Parsers
        ↓
Complex Integration
        ↓
Security Analytics
```

For example:

```text
Firewall A → src_ip

Firewall B → sourceAddress

Application C → client_ip
```

All these fields may represent the same concept:

```text
source.ip
```

Without normalization, downstream systems need to understand every vendor-specific representation.

---

# 💡 Our Solution

ULPF converts heterogeneous logs into a predictable standardized event structure.

```text
RAW EVENT
    │
    ▼
┌──────────────────┐
│    Ingestion     │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Format Detection │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│     Parsing      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Normalization   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│    Validation    │
└────────┬─────────┘
         │
         ▼
┌──────────────────────┐
│  Standardized Event  │
└──────────┬───────────┘
           │
           ├──► SIEM
           ├──► Analytics
           ├──► Data Lake
           └──► Investigation
```

The original event is preserved alongside the normalized output so that forensic evidence is never lost.

---

# ✨ Key Features

## 🔹 Universal Log Ingestion

ULPF is designed to accept logs from multiple sources and formats through a common processing interface.

Supported and planned formats include:

```text
JSON
Syslog
CSV
XML
CEF
LEEF
Custom Logs
```

---

## 🔍 Automatic Format Detection

ULPF identifies the format of an incoming event using registered detection rules.

```text
Incoming Event
      ↓
Detection Engine
      ↓
Matching Parser
      ↓
Parsing
```

This removes the need to manually choose a parser for every event.

---

## 📚 Parser Registry

Parsers are managed through a registry instead of being tightly coupled with the application.

A parser can contain:

```text
Parser Name
Parser ID
Version
Detection Rules
Fixtures
Parsing Logic
Normalization Rules
```

Example:

```text
Common Event Format

ID       : cef
Version  : 1.0.0
Fixtures : 3
```

This makes ULPF easier to extend when new log formats are introduced.

---

## 🔄 Event Normalization

Different systems may use different field names for the same information.

Example:

```text
src_ip
sourceIP
client_ip
source_address
```

ULPF can normalize them into:

```text
source.ip
```

Similarly:

```text
dst_ip
destinationIP
server_ip
```

can be converted into:

```text
destination.ip
```

This makes downstream analytics and security rules much easier to maintain.

---

# 🧾 Raw Event Preservation

ULPF preserves the original event together with its normalized representation.

Conceptually:

```json
{
  "raw_event": "original log data",
  "normalized_event": {
    "source": {
      "ip": "10.0.0.4"
    }
  }
}
```

Raw event preservation is important for:

* Digital Forensics
* Incident Investigation
* Compliance
* Auditing
* Parser Debugging
* Event Reprocessing

---

# 🔗 Provenance & Traceability

ULPF is designed to maintain processing metadata for each event.

This can include:

```text
Where did the event come from?

Which parser processed it?

Which parser version was used?

What transformations were applied?

What was the original event?
```

This improves:

* Reproducibility
* Debugging
* Auditing
* Security Investigations

---

# ❓ Unknown Event Handling

Real-world environments will always produce previously unseen log formats.

ULPF does not simply discard unknown events.

```text
Unknown Event
      ↓
Raw Event Preserved
      ↓
Unknown / Onboarding
      ↓
Structural Inspection
      ↓
Parser Rule Creation
      ↓
Parser Registry
```

This allows unsupported logs to become supported formats over time.

---

# 📴 Offline & Air-Gapped Capability

ULPF is designed so that its **core processing pipeline can operate without internet connectivity or external cloud APIs**.

```text
┌─────────────────────────────────────┐
│        AIR-GAPPED ENVIRONMENT       │
│                                     │
│ Log Sources                         │
│      │                              │
│      ▼                              │
│ Local ULPF Instance                 │
│      │                              │
│      ├── Detection Engine           │
│      ├── Parser Registry            │
│      ├── Normalization Engine       │
│      ├── Validation                 │
│      └── Local Storage              │
│                                     │
└─────────────────────────────────────┘
```

ULPF can be deployed on:

* Local Machines
* Internal Enterprise Servers
* Private Networks
* Restricted Environments
* Air-Gapped Systems

---

# ☁️ Why Is the Prototype Hosted on Vercel?

The prototype may be hosted on **Vercel** for easier demonstration and accessibility.

However:

> **Vercel is not a requirement of the ULPF architecture.**

The core processing framework can be run locally.

```text
Vercel
   ↓
Prototype Demonstration
```

For real offline deployments:

```text
Local Server
     ↓
ULPF
     ↓
Local Processing
```

Therefore:

> **Cloud hosting is used only for prototype accessibility, while the core ULPF framework is designed to support standalone and offline deployment.**

---

# 🖥️ Current Prototype

The prototype is divided into four major areas.

## Overview

Provides a high-level overview of the framework and processing workflow.

---

## Work

Used for submitting and processing events.

Available workflows include:

```text
Past Event
Batch
Local File
Load Unknown Sample
Process Event
```

---

## Investigate

Provides tools for examining processed events.

```text
Event Explorer
Event Inspector
```

---

## Extend

Provides tools related to extensibility and parser management.

```text
Parser Registry
Unknown / Onboarding
```

---

# 🏗️ System Architecture

```text
                 ┌───────────────────────┐
                 │      LOG SOURCES      │
                 │                       │
                 │ Server │ Cloud │ Apps │
                 │ IAM    │ IoT   │ SOC  │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │       INGESTION       │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │    FORMAT DETECTION   │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │    PARSER REGISTRY    │
                 │                       │
                 │ JSON │ CEF │ CSV │... │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │        PARSING        │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │     NORMALIZATION     │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │      VALIDATION       │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │  STANDARDIZED EVENT   │
                 └───────────┬───────────┘
                             │
                ┌────────────┴─────────────┐
                │                          │
                ▼                          ▼
        Investigation                External Tools
                                     SIEM / Data Lake
```

---

# ⚙️ Technology Stack

## Backend

* Python
* FastAPI
* Uvicorn
* Pydantic
* PyYAML
* SQLite / Local Persistence

### FastAPI

Used to provide the API layer for event ingestion and processing.

### Pydantic

Used for structured models and schema validation.

### PyYAML

Used for configuration and registry-related data.

### SQLite

Provides lightweight local persistence suitable for prototype and offline environments.

---

## Frontend

* HTML
* CSS
* JavaScript

The frontend is intentionally lightweight and can be served locally.

---

## Testing

* pytest
* httpx

Testing helps ensure that parsers produce predictable output for known fixtures.

---

# 🧪 Example Processing

## Raw Input

```text
CEF:0|SecurityVendor|Firewall|1.0|1001|Connection Allowed|5|src=10.0.0.4 dst=10.0.0.8 spt=51230 dpt=443
```

---

## Detection

```text
Detected Format → CEF
Parser          → cef
```

---

## Parsed Output

```json
{
  "src": "10.0.0.4",
  "dst": "10.0.0.8",
  "spt": 51230,
  "dpt": 443
}
```

---

## Normalized Output

```json
{
  "source": {
    "ip": "10.0.0.4",
    "port": 51230
  },
  "destination": {
    "ip": "10.0.0.8",
    "port": 443
  }
}
```

The original CEF message can remain available for forensic verification.

---

# 🧠 AI Philosophy

ULPF does not require AI for its core processing.

Core functions such as:

```text
Format Detection
Parsing
Normalization
Validation
```

can remain deterministic and rule-based.

This makes ULPF:

* Predictable
* Explainable
* Reproducible
* Offline-capable

AI can later be used as an assistive layer.

Example:

```text
Unknown Event
      ↓
AI-Assisted Analysis
      ↓
Suggested Mapping
      ↓
Human Validation
      ↓
Parser Registry
```

AI assists onboarding instead of becoming a mandatory dependency for log processing.

---

# 🛡️ ULPF Is Not a SIEM

ULPF is designed to work **before a SIEM**.

```text
LOG SOURCES
     ↓
    ULPF
     ↓
Standardized Events
     ↓
┌─────────┬─────────────┬──────────────┐
│  SIEM   │  Data Lake  │ ML Analytics │
└─────────┴─────────────┴──────────────┘
```

A SIEM focuses on:

* Threat Detection
* Alerting
* Correlation
* Dashboards
* Investigation

ULPF focuses on:

* Ingestion
* Parsing
* Normalization
* Validation
* Raw Event Preservation
* Parser Extensibility

---

# ⚔️ Why Not Just Use Logstash / Fluentd / Existing SIEM Tools?

Existing tools such as Logstash, Fluent Bit, Fluentd and commercial SIEM platforms already provide strong log processing capabilities.

ULPF does not try to replace the entire observability ecosystem.

The project focuses specifically on creating:

> **A universal, vendor-neutral and extensible preprocessing abstraction for heterogeneous security logs with standardized output, raw-event preservation, provenance and structured unknown-source onboarding.**

ULPF can eventually integrate with existing platforms instead of replacing them.

---

# 🎯 Use Cases

ULPF can be useful in:

### Security Operations Centers

Normalize logs before sending them to a SIEM.

### Incident Response

Preserve original evidence while providing structured data.

### Threat Analytics

Provide consistent fields for detection engines.

### Compliance

Maintain traceability and raw event records.

### Hybrid Infrastructure

Normalize events from cloud, on-premise and legacy systems.

### Air-Gapped Networks

Process logs without internet dependency.

---

# 🌍 Example Real-World Scenario

An enterprise may use:

```text
Cisco Firewall
Windows Servers
Linux Servers
AWS
Custom Applications
IAM Systems
Endpoint Security
```

Without ULPF:

```text
Multiple Sources
      ↓
Multiple Parsers
      ↓
Different Field Structures
      ↓
Complex Detection Rules
```

With ULPF:

```text
Multiple Sources
      ↓
     ULPF
      ↓
Common Event Schema
      ↓
Unified Analytics
```

---

# 📊 Benefits

| Area             | Benefit                               |
| ---------------- | ------------------------------------- |
| Integration      | Reduces source-specific preprocessing |
| Analytics        | Provides consistent field structures  |
| Forensics        | Preserves original events             |
| Extensibility    | New parsers can be added              |
| Compliance       | Better traceability                   |
| Deployment       | Supports local/offline operation      |
| Maintainability  | Parser versioning and registry        |
| Interoperability | Vendor-neutral normalized output      |

---

# 📁 Repository Structure

```text
ULPF-Final-Prototype/
│
├── ulpf/
│   ├── api.py
│   ├── storage.py
│   ├── parsers/
│   ├── registry/
│   ├── normalization/
│   └── ...
│
├── static/
│   ├── index.html
│   ├── styles.css
│   └── app.js
│
├── tests/
│
├── requirements.txt
├── pyproject.toml
└── README.md
```

> The structure may evolve as development continues.

---

# 💻 Running Locally

## 1. Clone Repository

```bash
git clone https://github.com/Shaurya926/ULPF-Final-Prototype.git
```

```bash
cd ULPF-Final-Prototype
```

---

## 2. Create Virtual Environment

### Windows

```bash
python -m venv .venv
```

```bash
.venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Run ULPF

```bash
uvicorn ulpf.api:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

---

# 📴 Offline Demonstration

To demonstrate offline capability:

```text
1. Start ULPF locally
2. Open the interface
3. Process a log
4. Disconnect internet
5. Process another log
6. Verify that processing continues normally
```

This demonstrates that ULPF's core processing does not require a cloud API.

---

# 🧪 Running Tests

```bash
pytest
```

Parser testing can conceptually follow:

```text
Fixture
   ↓
Expected Parser
   ↓
Expected Fields
   ↓
Normalized Output
```

---

# 🧩 Adding a New Parser

```text
Create Parser
      ↓
Define Detection Rules
      ↓
Create Test Fixtures
      ↓
Define Field Mapping
      ↓
Validate Output
      ↓
Register Parser
```

The goal is to make new log source onboarding predictable and modular.

---

# 🗺️ Roadmap

## Phase 1 — Core Prototype

* [x] Log ingestion
* [x] Parser-based processing
* [x] Normalization pipeline
* [x] Interactive frontend
* [x] Event inspection
* [x] Parser registry concept
* [x] Unknown-event workflow
* [x] Local deployment capability

---

## Phase 2 — Format Expansion

* [ ] Additional Syslog variants
* [ ] Advanced CEF support
* [ ] LEEF support
* [ ] XML processing
* [ ] Enhanced CSV mapping
* [ ] Additional vendor-specific parsers

---

## Phase 3 — Parser Registry

* [ ] Parser lifecycle management
* [ ] Compatibility checks
* [ ] Parser version migration
* [ ] Parser signing
* [ ] Registry import/export
* [ ] Extended fixture testing

---

## Phase 4 — Scalability

* [ ] Streaming ingestion
* [ ] Queue-based architecture
* [ ] Parallel workers
* [ ] Performance benchmarking
* [ ] Distributed deployment

---

## Phase 5 — Intelligent Onboarding

* [ ] Structural inference
* [ ] Mapping suggestions
* [ ] AI-assisted parser generation
* [ ] Confidence scoring
* [ ] Human-in-the-loop validation
* [ ] Offline inference options

---

# 🔮 Future Architecture

```text
                         ┌───────────────┐
                         │  Log Sources  │
                         └───────┬───────┘
                                 │
                                 ▼
                         ┌───────────────┐
                         │   Ingestion   │
                         └───────┬───────┘
                                 │
                                 ▼
                     ┌─────────────────────┐
                     │ Detection / Routing │
                     └──────────┬──────────┘
                                │
               ┌────────────────┴────────────────┐
               │                                 │
               ▼                                 ▼
       ┌─────────────────┐             ┌─────────────────┐
       │   Known Format  │             │ Unknown Format  │
       └────────┬────────┘             └────────┬────────┘
                │                               │
                ▼                               ▼
       ┌─────────────────┐             ┌─────────────────┐
       │ Parser Registry │             │   Onboarding    │
       └────────┬────────┘             └────────┬────────┘
                │                               │
                └──────────────┬────────────────┘
                               │
                               ▼
                      ┌─────────────────┐
                      │  Normalization  │
                      └────────┬────────┘
                               │
                               ▼
                      ┌─────────────────┐
                      │  Common Schema  │
                      └────────┬────────┘
                               │
                  ┌────────────┴────────────┐
                  │                         │
                  ▼                         ▼
                SIEM                     Data Lake
```

---

# 🏆 Smart India Hackathon 2026

ULPF is being developed for **Smart India Hackathon 2026**.

### Problem Statement ID

```text
26156
```

### Project

```text
Universal Log Pre-processing Framework
```

### Domain

```text
Cybersecurity
Log Processing
Security Analytics
Data Standardization
```

The project focuses on demonstrating the feasibility of a universal log preprocessing architecture capable of operating across heterogeneous and restricted environments.

---

# 👥 Team

| Member           | Responsibility       |
| ---------------- | -------------------- |
| Aditya Jain      | Team Lead            |
| Shaurya Dubey    | Frontend Development |
| Pawani Sanghi    | Pitch & Presentation |
| Vishwajeet Singh | Backend Development  |
| Shourya Rai      | Research             |
| Ramanjee Mishra  | Irresponsible        |



The project is built collaboratively, with team members contributing across multiple areas when required.

---

# 🌟 Project Vision

Our goal is not simply to create another parser.

The long-term vision is:

```text
Any Log Source
      ↓
Any Supported Format
      ↓
Universal Processing
      ↓
Common Security Schema
      ↓
Any Analytics Platform
```

ULPF aims to reduce the complexity between raw enterprise telemetry and the systems responsible for understanding it.

---

# 💬 Core Philosophy

> **Different logs. One processing layer. One predictable representation.**

---

# 🤝 Contributions

The project is under active development.

Potential contribution areas include:

* New Parsers
* Detection Rules
* Normalization Mappings
* Test Fixtures
* Performance Improvements
* UI Enhancements
* Security Validation
* Documentation

---

# ⚠️ Disclaimer

ULPF is currently a **prototype developed for research, learning and hackathon demonstration**.

It should not yet be considered a production-ready replacement for enterprise log processing systems without additional:

* Security Hardening
* Performance Benchmarking
* Scalability Testing
* Operational Monitoring
* Enterprise Validation

---

# ⭐ Support

If you find this project useful, consider starring the repository.

> **ULPF — Transforming heterogeneous logs into standardized, traceable and actionable security events.**
