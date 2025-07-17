# 🔐 TokenAuth - AAD Token Validation Library

## 🔍 Overview

**TokenAuth** is a reusable Python package for validating Azure Active Directory (AAD) Bearer tokens across Fyras microservices. It extracts and returns authentication context (issuer, tenant ID, user ID, name, email, etc.) from incoming requests.

## 🎯 Use Cases

- ✅ Validate and decode JWT tokens issued by Microsoft AAD
- ✅ Extract tenant ID and user ID for tenant-aware logic
- ✅ Share token validation logic across:
  - Content Moderation Service
  - Token Usage Estimation Service
  - Redaction/Obfuscation Service

---

## 📦 Installation

### 👉 Option 1: Install directly from GitHub using HTTPS

```bash
pip install "fyras-token-auth @ git+https://github.com/Sam-Fyras/TokenAuth.git@main"
````

### 👉 Option 2: Install using SSH (recommended for internal usage)

Ensure you have access to the repo via SSH, then run:

```bash
pip install "fyras-token-auth @ git+ssh://git@github.com/Sam-Fyras/TokenAuth.git@main"
```

---

## 🔧 Usage

```python
from token_auth.claim_extraction.auth import TokenVerifier

def handle_request(request):
    token = request.headers.get("Authorization").split(" ")[1]
    verifier = TokenVerifier()
    auth_ctx = verifier.get_claims(token)

    print("Tenant ID:", auth_ctx.tid)
    print("User ID:", auth_ctx.sub)
    print("Name:", auth_ctx.name)
    print("Email:", auth_ctx.email)
```

---

## 🧱 AuthContext (Output)

```python
from pydantic import BaseModel
from typing import Optional

class AuthContext(BaseModel):
    iss: str
    aud: str
    exp: int
    tid: str
    kid: str
    alg: str
    iat: int
    nbf: int
    sub: str
    name: Optional[str] = None
    email: Optional[str] = None
```

---

## 🔐 Supported Token Claims

* `tid` → Tenant ID
* `sub` → User ID (subject)
* `name` → User's display name
* `email` → User's email address
* `aud` → Audience
* `iss` → Issuer
* `roles` (if present) → Assigned roles

---

## 🔄 Internals

* 🧠 Built on [PyJWT](https://pyjwt.readthedocs.io/) for JWT parsing and validation
* 🌐 Fetches Azure AD public keys (JWKS) from tenant OpenID configuration
* ✅ Validates token signature, issuer, and audience
* 🔧 Requires environment variables:

  * `AZURE_TENANT_ID`
  * `AZURE_CLIENT_ID`
* 📜 Provides logging for debugging and traceability

---

## 🚧 Future Enhancements

* 🔄 Automatic JWKS refresh and caching
* 🧩 Support for multiple AAD tenants
* 🛡️ Scoped permissions and RBAC enforcement
* 🧼 Custom exceptions and error handler middleware

---

## 🧪 Run Tests Locally

```bash
pytest tests/
```

---

## 👥 Contributors

* Samuthrakumar Venugopalan
* Srihari Raman
* Fyras Internship Team

---

## 📄 License

MIT License (or as defined per Fyras internal policy)