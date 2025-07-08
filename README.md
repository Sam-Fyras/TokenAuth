# TokenAuth - AAD Token Validation Library

## 🔍 Overview

TokenAuth is a reusable Python package for validating Azure Active Directory (AAD) Bearer tokens across Fyras microservices. It extracts and returns authentication context (issuer, tenant ID, user ID, name, email, etc.) from incoming requests.

## 🎯 Use Cases

- Validate and decode JWT tokens issued by Microsoft AAD
- Extract tenant ID and user ID for tenant-aware logic
- Share the same token validation logic across:
  - Content Moderation Service
  - Token Usage Estimation Service
  - Redaction/Obfuscation Service

## 📦 Installation

```bash
pip install git+https://github.com/fyras/TokenAuth.git@main
```

## 🔧 Usage

```python
from token_auth.claim_extraction.auth import get_claims

def handle_request(request):
    token = request.headers.get("Authorization").split(" ")[1]
    auth_ctx = get_claims(token)

    print("Tenant ID:", auth_ctx.tid)
    print("User ID:", auth_ctx.sub)
    print("Name:", auth_ctx.name)
    print("Email:", auth_ctx.email)
```

## 🧱 AuthContext (Output)

```python
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

## 🔐 Supported Token Claims

- `tid` → Tenant ID
- `sub` → User ID (subject)
- `name` → User's display name
- `email` → User's email address
- `aud` → Audience
- `iss` → Issuer
- `roles` (if present) → Assigned roles

## 🔄 Internals

- Uses [PyJWT](https://pyjwt.readthedocs.io/) for JWT parsing and validation
- Fetches Azure AD public keys (JWKS) from the tenant-specific OpenID configuration endpoint
- Validates token signature, issuer, and audience
- Environment variables required:
  - `AZURE_TENANT_ID`
  - `CLIENT_ID`
- Logging for debugging and error tracing

## 📘 Future Enhancements

- Automatic JWKS refresh and caching
- Support for multiple AAD tenants
- Scoped permissions
- Custom exceptions and error handler middleware

## 🧪 Test Locally

```bash
pytest tests/
```

## 👥 Contributors

- Samuthrakumar Venugopalan
- Srihari Raman
- Fyras Internship Team

## 📄 License

MIT License (or as defined per Fyras internal policy)
