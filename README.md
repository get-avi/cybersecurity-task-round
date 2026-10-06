# Cybersecurity Domain Task Round — Submission

[![Tests](https://img.shields.io/badge/tests-6%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)]()
[![License](https://img.shields.io/badge/defense-educational%20only-red.svg)]()

This repository contains the complete technical assessment deliverables for the **Technical Team: Task Round — Cybersecurity Domain**, addressing both **Task 1: Vulnerability Assessment & Security Analysis** and **Task 2: Custom Security Tooling & Automation**.

---

## 📁 Repository Structure

```
cybersecurity-task-round/
├── AUDIT_REPORT.md             # Task 1: Comprehensive Security Audit & Vulnerability Assessment
├── README.md                   # Project overview, installation, usage, and defensive disclaimer
├── requirements.txt            # Environment requirements
├── demo_runner.py              # Automated live simulation showing baseline, attack, and detection
├── fim/                        # Task 2: Core File Integrity Monitor package
│   ├── __init__.py
│   ├── fim.py                  # CLI entry point (argparse, modes, signal handling)
│   ├── hasher.py               # Concurrent multi-threaded cryptographic hashing (SHA-256)
│   ├── detector.py             # Baseline persistence and state-delta comparator
│   └── reporter.py             # Color-coded ANSI console reporter & JSON Lines alert logger
└── tests/                      # Automated test suite
    ├── __init__.py
    └── test_fim.py             # Unit tests for baseline, modification, creation, deletion
```

---

## 🛡️ Task 1: Vulnerability Assessment & Security Analysis

A formal security assessment report is provided in **[`AUDIT_REPORT.md`](AUDIT_REPORT.md)**.

### Assessment Focus: Broken Access Control & Authentication (OWASP Top 10 A01:2021 & A07:2021)
- **Target Profile:** Enterprise REST API service and document management microservice.
- **Identified Findings:**
  1. **SEC-2026-001 (CVSS 8.5 - High):** Insecure Direct Object Reference (IDOR) on `/api/v1/documents/{id}` allowing cross-tenant data leakage.
  2. **SEC-2026-002 (CVSS 9.8 - Critical):** JWT Signature Verification Bypass & Algorithm Confusion (`alg: "none"`), allowing unauthorized vertical privilege escalation to administrator roles.
- **Deliverables Included in [`AUDIT_REPORT.md`](AUDIT_REPORT.md):**
  - **Executive Summary & CVSS v3.1 Scoring Vectors.**
  - **Step-by-Step Proof of Concept (PoC)** with exact `curl` reproduction commands and JSON payloads.
  - **Root Cause Source Code Analysis** exposing vulnerable patterns.
  - **Remediation & Patching Snippets** featuring object-level authorization (ABAC/RBAC) and asymmetric RSA (`RS256`) key verification.
  - **Regression Test Matrix & Strategic Security Recommendations.**

---

## ⚙️ Task 2: Custom Security Tooling — File Integrity Monitor (FIM)

The **File Integrity Monitor (FIM)** is a high-performance defensive Host Intrusion Detection System (HIDS) CLI tool written in Python. It detects unauthorized modifications, injections, or deletions across monitored filesystem hierarchies.

### Key Capabilities
- **Cryptographic Hashing:** Uses `hashlib.sha256` (also supports `sha512` and `md5`) with 64 KB chunked streaming to handle large files with minimal RAM overhead.
- **Multi-Threaded Concurrency:** Employs `concurrent.futures.ThreadPoolExecutor` to hash hundreds of files in parallel.
- **Three Operational Modes:**
  - `--init-baseline`: Generates a portable, cryptographically signed JSON manifest of the target directory.
  - `--verify`: Performs an instant audit comparison against the baseline and returns standard exit codes (`0` for clean, `1` for compromised).
  - `--monitor`: Runs continuous real-time directory polling at a user-defined interval.
- **Tri-State Event Categorization:** Categorizes anomalies into `CREATED`, `MODIFIED`, and `DELETED`.
- **Dual Output Channels:** Rich ANSI color-coded console notifications and structured machine-readable JSON logging (`fim_alerts.json`) compatible with SIEM ingestion (Splunk, Elastic, Sentinel).
- **Robust Error Handling:** Seamlessly tolerates permission errors, missing files, and race conditions during scans.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.9 or higher.
- Standard POSIX environment (Linux / macOS) or Windows.
- No external third-party dependencies are required for core execution (built on standard library).

### Installation
Clone the repository and install optional test dependencies:
```bash
git clone <your-repository-url>
cd cybersecurity-task-round
pip install -r requirements.txt
```

---

## 💻 CLI Usage Guide

### 1. Initialize Baseline Manifest
Generate the initial trusted state manifest for a sensitive directory:
```bash
python3 fim/fim.py --init-baseline -t /path/to/target_dir -b baseline.json -w 4
```

### 2. Verify Directory Integrity (Audit Check)
Run a one-time audit against the established baseline:
```bash
python3 fim/fim.py --verify -t /path/to/target_dir -b baseline.json -o fim_alerts.json
```
*Exit codes:*
- `0`: All files match baseline (Integrity intact).
- `1`: Tampering or unauthorized changes detected.
- `2`: Configuration or filesystem error.

### 3. Continuous Real-Time Monitoring
Monitor the target directory every 5 seconds for live modifications:
```bash
python3 fim/fim.py --monitor -t /path/to/target_dir -b baseline.json -i 5 -o fim_alerts.json
```

### 4. Machine-Readable JSON Output
Output raw JSON to stdout for automated pipelines or scripts:
```bash
python3 fim/fim.py --verify -t /path/to/target_dir -b baseline.json --json
```

---

## 📊 Sample Terminal Output

### Clean Verification:
```text
======================================================================
  [FIM] File Integrity Monitor & Defensive Tamper Detection Engine
  Automated Host Intrusion Detection System (HIDS) Tool
======================================================================
[*] Auditing Directory: /srv/web_portal
[*] Baseline: baseline.json (Algorithm: SHA256)

[*] Audit Timestamp: 2026-10-02T02:57:30.237211+00:00
[*] Files Inspected: 24

[+] STATUS: INTEGRITY VERIFIED - No unauthorized changes detected.
----------------------------------------------------------------------
```

### Tampering / Intrusion Alert:
```text
======================================================================
  [FIM] File Integrity Monitor & Defensive Tamper Detection Engine
  Automated Host Intrusion Detection System (HIDS) Tool
======================================================================
[*] Auditing Directory: /srv/web_portal
[*] Baseline: baseline.json (Algorithm: SHA256)

[*] Audit Timestamp: 2026-10-02T02:57:35.527205+00:00
[*] Files Inspected: 25

[!] ALERT: INTEGRITY COMPROMISED - 2 deviation(s) detected!

  [+] NEW FILE DETECTED: backdoor.sh
      SHA-256: 6f3e6d992dbf984ca244efa671e3c71e89073c74126fdb372fab7378908f1997 (16 bytes)
  [!] TAMPERING DETECTED (MODIFIED): server.js
      Baseline Hash: feddf179f6c9514d75e5815d2f5f16394dfe17ab45c81311d92e46ec61f5c6df
      Current  Hash: 5785cf02143f00a1ab46eac499e232d3feec2915ef54d3c13ccf6a80010b1f82
----------------------------------------------------------------------
```

---

## 🧪 Automated Testing & Live Demo

### Run Unit Test Suite
Verify that all cryptographic checks, baseline persistence, and delta detection tests pass:
```bash
python3 -m unittest discover -s tests -v
```

### Run End-to-End Live Demonstration
Execute the automated demonstration runner that sets up a sandbox, creates a baseline, executes simulated adversarial modifications, and displays detection:
```bash
python3 demo_runner.py
```

---

## 🔒 Security & Educational Disclaimer

> [!CAUTION]
> **DISCLAIMER:**  
> This software and accompanying vulnerability audit report are developed strictly for **educational, defensive, and authorized assessment purposes** as part of a technical evaluation. 
> - All vulnerability testing, PoC demonstrations, and file integrity operations are designed and verified on isolated local environments (`localhost`).
> - The File Integrity Monitor (FIM) is intended for blue-team defensive host hardening and intrusion detection.
> - Unauthorized testing or auditing against third-party systems without prior explicit written authorization is illegal.
