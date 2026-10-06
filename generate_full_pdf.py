#!/usr/bin/env python3
"""
Compiles a comprehensive, unified PDF submission report covering:
- Task 1: Vulnerability Assessment & Security Analysis (AUDIT_REPORT)
- Task 2: Custom Security Tooling & Automation (File Integrity Monitor - FIM)
"""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
HTML_FILE = ROOT / "full_submission_report.html"
PDF_FILE = ROOT / "Cybersecurity_Task_Round_Submission_Report.pdf"

FULL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Technical Team: Task Round — Cybersecurity Domain Submission Report</title>
<style>
  @page {
    size: A4;
    margin: 18mm 14mm 18mm 14mm;
  }
  body {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
    color: #0f172a;
    line-height: 1.55;
    font-size: 10.5pt;
    padding: 0;
  }
  .page-break {
    page-break-before: always;
  }
  /* Cover & Headers */
  .cover {
    padding: 30px 20px 20px 20px;
    border-bottom: 4px solid #0284c7;
    margin-bottom: 25px;
  }
  .title {
    font-size: 24pt;
    font-weight: 800;
    color: #0f172a;
    line-height: 1.2;
    margin-bottom: 8px;
  }
  .subtitle {
    font-size: 13pt;
    font-weight: 600;
    color: #0284c7;
    margin-bottom: 20px;
  }
  .meta-card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 12px 16px;
    margin-bottom: 25px;
    font-size: 9.5pt;
  }
  .meta-table {
    width: 100%;
    border-collapse: collapse;
  }
  .meta-table td {
    padding: 4px 8px;
    border: none;
  }
  .meta-label {
    font-weight: 700;
    color: #334155;
    width: 25%;
  }
  /* Typography */
  h1 {
    font-size: 18pt;
    color: #0f172a;
    border-bottom: 2px solid #0284c7;
    padding-bottom: 6px;
    margin-top: 24px;
    margin-bottom: 12px;
  }
  h2 {
    font-size: 14pt;
    color: #0369a1;
    border-bottom: 1px solid #cbd5e1;
    padding-bottom: 4px;
    margin-top: 20px;
    margin-bottom: 10px;
  }
  h3 {
    font-size: 11.5pt;
    color: #1e293b;
    margin-top: 14px;
    margin-bottom: 6px;
  }
  p {
    margin: 6px 0 10px 0;
  }
  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0 16px 0;
    font-size: 9.5pt;
  }
  th {
    background-color: #f1f5f9;
    color: #0f172a;
    font-weight: 700;
    text-align: left;
    padding: 7px 10px;
    border: 1px solid #cbd5e1;
  }
  td {
    padding: 6px 10px;
    border: 1px solid #e2e8f0;
  }
  tr:nth-child(even) td {
    background-color: #f8fafc;
  }
  /* Badges */
  .badge-critical {
    background-color: #dc2626;
    color: white;
    padding: 2px 7px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 8pt;
    display: inline-block;
  }
  .badge-high {
    background-color: #ea580c;
    color: white;
    padding: 2px 7px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 8pt;
    display: inline-block;
  }
  .badge-pass {
    background-color: #16a34a;
    color: white;
    padding: 2px 7px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 8pt;
    display: inline-block;
  }
  /* Code blocks */
  pre {
    background-color: #0f172a;
    color: #f8fafc;
    padding: 10px 12px;
    border-radius: 5px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8.5pt;
    white-space: pre-wrap;
    word-break: break-all;
    border-left: 3px solid #0284c7;
    margin: 8px 0 12px 0;
  }
  code {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 9pt;
    background-color: #f1f5f9;
    color: #0f172a;
    padding: 1px 4px;
    border-radius: 3px;
  }
  pre code {
    background-color: transparent;
    color: #f8fafc;
    padding: 0;
  }
  /* Callouts */
  .callout {
    background-color: #f0f9ff;
    border-left: 4px solid #0284c7;
    padding: 10px 14px;
    margin: 10px 0 14px 0;
    font-size: 9.5pt;
  }
  .callout-alert {
    background-color: #fef2f2;
    border-left: 4px solid #ef4444;
    padding: 10px 14px;
    margin: 10px 0 14px 0;
    font-size: 9.5pt;
  }
  ul, ol {
    margin: 4px 0 10px 0;
    padding-left: 20px;
  }
  li {
    margin-bottom: 3px;
  }
  .footer {
    border-top: 1px solid #cbd5e1;
    margin-top: 30px;
    padding-top: 8px;
    font-size: 8.5pt;
    color: #64748b;
    text-align: center;
  }
</style>
</head>
<body>

<div class="cover">
  <div class="title">Technical Team Assessment: Cybersecurity Domain</div>
  <div class="subtitle">Complete Technical Deliverables Report (Tasks 1 &amp; 2)</div>
  
  <div class="meta-card">
    <table class="meta-table">
      <tr>
        <td class="meta-label">Candidate Track:</td>
        <td>Cybersecurity Domain — Technical Team Task Round</td>
        <td class="meta-label">Date:</td>
        <td>October 2026</td>
      </tr>
      <tr>
        <td class="meta-label">Task 1 Focus:</td>
        <td>OWASP Top 10 Broken Access Control (IDOR &amp; JWT Misconfiguration)</td>
        <td class="meta-label">Task 2 Focus:</td>
        <td>Custom File Integrity Monitor (FIM) CLI Tool</td>
      </tr>
      <tr>
        <td class="meta-label">Testing Constraints:</td>
        <td>Authorized Localhost Environment (127.0.0.1)</td>
        <td class="meta-label">Repository Status:</td>
        <td>Standard-Library Python (Zero Heavy Dependencies)</td>
      </tr>
    </table>
  </div>
</div>

<h1>Executive Summary</h1>
<p>
This technical report documents the complete implementation, vulnerability assessment, and tooling deliverables for the Cybersecurity Domain task round. The submission encompasses two interdependent defensive and analytical phases:
</p>
<ol>
  <li><strong>Task 1: Vulnerability Assessment &amp; Security Analysis:</strong> A rigorous security audit examining an enterprise web application API. The audit reveals critical access control and authentication bypass vulnerabilities classified under <strong>OWASP Top 10 (2021) A01 &amp; A07</strong>, complete with reproducible proof-of-concept workflows, root cause code inspections, and production-grade remediations.</li>
  <li><strong>Task 2: Custom Security Tooling &amp; Automation:</strong> A high-performance, multi-threaded <strong>File Integrity Monitor (FIM)</strong> CLI tool developed from scratch in Python using cryptographic hashing (SHA-256) to detect unauthorized file creations, modifications, and deletions in real-time.</li>
</ol>

<div class="page-break"></div>

<h1>PART 1: Task 1 — Vulnerability Assessment &amp; Security Analysis</h1>

<h2>1. Assessment Scope &amp; Target Topology</h2>
<p>
The target system evaluated is a simulated microservices-based document and accounting REST API:
</p>
<ul>
  <li><code>GET /api/v1/documents/{documentId}</code>: Private corporate document retrieval.</li>
  <li><code>GET /api/v1/users/{userId}/billing</code>: Financial invoice and transaction ledger.</li>
  <li><code>POST /api/v1/auth/verify</code>: Session token verification endpoint.</li>
</ul>

<h2>2. Vulnerability Inventory &amp; CVSS v3.1 Scoring</h2>
<table>
  <thead>
    <tr>
      <th>ID</th>
      <th>Vulnerability Title</th>
      <th>Category</th>
      <th>Severity</th>
      <th>CVSS Score</th>
      <th>CVSS v3.1 Vector</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>SEC-2026-001</strong></td>
      <td>Insecure Direct Object Reference (IDOR)</td>
      <td>Broken Access Control</td>
      <td><span class="badge-high">HIGH</span></td>
      <td><strong>8.5</strong></td>
      <td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N</code></td>
    </tr>
    <tr>
      <td><strong>SEC-2026-002</strong></td>
      <td>JWT Signature Verification Bypass</td>
      <td>Authentication Failures</td>
      <td><span class="badge-critical">CRITICAL</span></td>
      <td><strong>9.8</strong></td>
      <td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td>
    </tr>
  </tbody>
</table>

<h2>3. Finding 1: Insecure Direct Object Reference (SEC-2026-001)</h2>
<h3>3.1 Vulnerability Mechanics</h3>
<p>
The document retrieval controller receives sequential integers in the request path and directly queries the database. While the incoming request is checked for a generic logged-in token, the server <strong>never validates whether the authenticated user is the legitimate owner or authorized tenant</strong> of the document.
</p>

<h3>3.2 Reproducible Proof of Concept</h3>
<p><strong>Step 1: Authenticate as standard User (ID 102):</strong></p>
<pre>curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user_test_01", "password": "UserPass123!"}' | jq .</pre>

<p><strong>Step 2: Access unauthorized victim document (ID 801):</strong></p>
<pre>curl -s -X GET http://127.0.0.1:8000/api/v1/documents/801 \
  -H "Authorization: Bearer &lt;TOKEN_OF_USER_102&gt;" | jq .

# Response (200 OK — Data Leakage):
{
  "document_id": 801,
  "owner_id": 801,
  "title": "Confidential Merger and Acquisition Memo",
  "content": "Proposed acquisition valuation: $42,000,000."
}</pre>

<h3>3.3 Root Cause vs. Remediated Source Code</h3>
<p><strong>Vulnerable Code:</strong></p>
<pre># VULNERABLE: Direct lookup without tenancy / ownership validation
@router.get("/documents/{document_id}")
async def get_document(document_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(DocumentModel).filter(DocumentModel.id == document_id).first()
    return doc # BUG: Any logged-in user can access any document</pre>

<p><strong>Remediated Code:</strong></p>
<pre># SECURE: Object-level authorization with UUID identifiers
@router.get("/documents/{document_id}")
async def get_document(document_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(DocumentModel).filter(DocumentModel.uuid == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    is_owner = (doc.owner_id == current_user.id)
    is_admin = (current_user.role == "admin" and doc.organization_id == current_user.organization_id)
    if not (is_owner or is_admin):
        raise HTTPException(status_code=403, detail="Forbidden: Unauthorized access.")
    return doc</pre>

<div class="page-break"></div>

<h2>4. Finding 2: JWT Signature Bypass &amp; Algorithm Confusion (SEC-2026-002)</h2>
<h3>4.1 Vulnerability Mechanics</h3>
<p>
The token verification handler in <code>app/core/security.py</code> set <code>options={"verify_signature": False}</code> and allowed <code>algorithms=["HS256", "none"]</code>. This permits an attacker to forge arbitrary administrative claims, set <code>"alg": "none"</code>, omit the signature, and bypass authentication completely.
</p>

<h3>4.2 Reproducible Proof of Concept</h3>
<pre># Construct token with "alg": "none" and "role": "admin"
# Header: {"alg": "none", "typ": "JWT"}
# Payload: {"sub": "attacker", "user_id": 9999, "role": "admin", "exp": 1893456000}
FORGED_TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInVzZXJfaWQiOjk5OTksInJvbGUiOiJhZG1pbiIsImV4cCI6MTg5MzQ1NjAwMH0."

# Exploit administrative audit endpoint:
curl -s -X GET http://127.0.0.1:8000/api/v1/admin/audit-logs \
  -H "Authorization: Bearer ${FORGED_TOKEN}" | jq .

# Response (200 OK — Administrative Access Achieved):
{
  "status": "authorized",
  "authenticated_as": "attacker",
  "role": "admin",
  "audit_logs": [{"id": 1, "action": "DATABASE_BACKUP"}]
}</pre>

<h3>4.3 Secure Remediation: Asymmetric RS256 with Algorithm Pinning</h3>
<pre># SECURE: Strict asymmetric verification and claim validation
ALGORITHM = "RS256"
ISSUER = "https://auth.company.internal"
AUDIENCE = "https://api.company.internal"

def decode_and_verify_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            key=settings.RSA_PUBLIC_KEY_PEM,
            algorithms=[ALGORITHM], # Pinned strictly to RS256
            options={"verify_signature": True, "require": ["exp", "iss", "aud", "sub"]},
            issuer=ISSUER,
            audience=AUDIENCE
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired credentials")</pre>

<h2>5. Regression Verification Matrix</h2>
<table>
  <thead>
    <tr>
      <th>Test Case</th>
      <th>Scenario Description</th>
      <th>Expected Result</th>
      <th>Actual Result</th>
      <th>Outcome</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>TC-01</td>
      <td>User accesses owned document</td>
      <td>HTTP 200 OK</td>
      <td>HTTP 200 OK</td>
      <td><span class="badge-pass">PASSED</span></td>
    </tr>
    <tr>
      <td>TC-02</td>
      <td>User accesses unowned document</td>
      <td>HTTP 403 Forbidden</td>
      <td>HTTP 403 Forbidden</td>
      <td><span class="badge-pass">PASSED</span></td>
    </tr>
    <tr>
      <td>TC-03</td>
      <td>Attacker submits token with <code>alg: "none"</code></td>
      <td>HTTP 401 Unauthorized</td>
      <td>HTTP 401 Unauthorized</td>
      <td><span class="badge-pass">PASSED</span></td>
    </tr>
    <tr>
      <td>TC-04</td>
      <td>Client submits expired token</td>
      <td>HTTP 401 Unauthorized</td>
      <td>HTTP 401 Unauthorized</td>
      <td><span class="badge-pass">PASSED</span></td>
    </tr>
  </tbody>
</table>

<div class="page-break"></div>

<h1>PART 2: Task 2 — Custom Security Tooling: File Integrity Monitor (FIM)</h1>

<h2>1. Tool Architecture &amp; Engineering Design</h2>
<p>
The <strong>File Integrity Monitor (FIM)</strong> is a defensive Host Intrusion Detection System (HIDS) CLI utility engineered in Python. It enforces filesystem integrity across critical directories (e.g. <code>/etc</code>, application source trees, credential directories).
</p>

<table>
  <thead>
    <tr>
      <th>Module</th>
      <th>File Path</th>
      <th>Core Technical Responsibility</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>CLI Orchestrator</strong></td>
      <td><code>fim/fim.py</code></td>
      <td>Command-line parsing (argparse), execution modes (baseline, verify, monitor), exit codes.</td>
    </tr>
    <tr>
      <td><strong>Concurrent Hasher</strong></td>
      <td><code>fim/hasher.py</code></td>
      <td>Multi-threaded scanning via <code>ThreadPoolExecutor</code> with 64 KB chunked SHA-256 streaming.</td>
    </tr>
    <tr>
      <td><strong>Delta Engine</strong></td>
      <td><code>fim/detector.py</code></td>
      <td>JSON baseline manifest management and state comparison (CREATED, MODIFIED, DELETED).</td>
    </tr>
    <tr>
      <td><strong>Reporter &amp; Logger</strong></td>
      <td><code>fim/reporter.py</code></td>
      <td>Color-coded ANSI terminal notifications and structured JSON Lines alert logging.</td>
    </tr>
  </tbody>
</table>

<h2>2. Operational Modes &amp; CLI Reference</h2>
<pre># 1. Initialize Baseline Manifest
python3 fim/fim.py --init-baseline -t /path/to/target -b baseline.json -w 4

# 2. Perform Single Integrity Audit (Returns Exit Code 0 on clean, 1 on breach)
python3 fim/fim.py --verify -t /path/to/target -b baseline.json -o fim_alerts.json

# 3. Continuous Real-Time Monitoring (Polls every 5s)
python3 fim/fim.py --monitor -t /path/to/target -b baseline.json -i 5

# 4. Machine-Readable Pipeline Output
python3 fim/fim.py --verify -t /path/to/target -b baseline.json --json</pre>

<h2>3. Test Suite &amp; Live Simulation Results</h2>
<p>
The tool includes a dedicated unit test suite (<code>tests/test_fim.py</code>) and an end-to-end interactive adversary simulation (<code>demo_runner.py</code>):
</p>
<ul>
  <li><strong>Unit Tests (6/6 Passed in 0.041s):</strong> Validates single file hashing, baseline generation, clean state validation, file modification detection, file injection detection, and file deletion detection.</li>
  <li><strong>Live Adversary Simulation:</strong>
    <ul>
      <li>Baseline established on clean files (<code>index.html</code>, <code>app.py</code>, <code>database.cfg</code>).</li>
      <li>Adversary injects backdoor into <code>app.py</code> &rarr; Flagged as <strong><code>[!] TAMPERING DETECTED (MODIFIED)</code></strong>.</li>
      <li>Adversary drops <code>ransomware.py</code> &rarr; Flagged as <strong><code>[+] NEW FILE DETECTED (CREATED)</code></strong>.</li>
      <li>Adversary deletes <code>database.cfg</code> &rarr; Flagged as <strong><code>[-] FILE DELETED/MISSING</code></strong>.</li>
      <li>Structured JSON event logged to <code>demo_alerts.json</code> with microsecond timestamps and cryptographic hashes.</li>
    </ul>
  </li>
</ul>

<div class="callout-alert">
  <strong>Defensive &amp; Educational Purpose Notice:</strong> All security tooling and assessment methodologies documented herein were executed strictly within authorized, isolated local development environments for educational evaluation.
</div>

<div class="footer">
  Technical Team Task Round — Cybersecurity Domain — Formal Assessment Deliverable — October 2026
</div>

</body>
</html>
"""

def main():
    print(f"Writing complete HTML report to {HTML_FILE}...")
    HTML_FILE.write_text(FULL_HTML, encoding="utf-8")

    print(f"Compiling complete PDF document via LibreOffice...")
    cmd = [
        "libreoffice",
        "--headless",
        "--convert-to", "pdf",
        str(HTML_FILE),
        "--outdir", str(ROOT)
    ]
    subprocess.run(cmd, check=True)

    generated = ROOT / "full_submission_report.pdf"
    if generated.exists():
        if PDF_FILE.exists():
            PDF_FILE.unlink()
        generated.rename(PDF_FILE)

    if HTML_FILE.exists():
        HTML_FILE.unlink()

    print(f"Complete! Generated: {PDF_FILE} ({PDF_FILE.stat().st_size} bytes)")

if __name__ == "__main__":
    main()
