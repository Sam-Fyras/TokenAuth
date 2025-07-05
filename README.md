TokenAuth - AAD Token Validation Library

🔍 Overview

TokenAuth is a reusable Python package for validating Azure Active Directory (AAD) Bearer tokens across Fyras microservices. It extracts and returns authentication context (tenant ID, user ID, etc.) from incoming requests.

🎯 Use Cases

Validate and decode JWT tokens issued by Microsoft AAD

Extract tenant ID and user ID for tenant-aware logic

Share the same token validation logic across:

Content Moderation Service

Token Usage Estimation Service

Redaction/Obfuscation Service

📦 Installation

pip install git+https://github.com/fyras/TokenAuth.git@main

🔧 Usage

from tokenauth.validator import validate_token

# In FastAPI or Flask route handler:
def handle_request(request):
    token = request.headers.get("Authorization").split(" ")[1]
    auth_ctx = validate_token(token)

    print("Tenant ID:", auth_ctx.tenant_id)
    print("User ID:", auth_ctx.user_id)

🧱 AuthContext (Output)

class AuthContext(BaseModel):
    tenant_id: str
    user_id: str
    username: Optional[str] = None
    roles: Optional[List[str]] = []

🔐 Supported Token Claims

tid → Tenant ID

sub or oid → User ID

upn → User principal name

roles → Assigned roles

🔄 Internals

Uses authlib or python-jose to validate JWT

Uses AAD public key from:

https://login.microsoftonline.com/common/discovery/keys

Optional caching of JWKS for performance

📘 Future Enhancements

Automatic JWKS refresh

Support for multiple AAD tenants

Scoped permissions

Custom exceptions and error handler middleware

🧪 Test Locally

pytest tests/

👥 Contributors

Samuthrakumar Venugopalan

Fyras Internship Team

📄 License

MIT License (or as defined per Fyras internal policy)

