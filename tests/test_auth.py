import os
import pytest
from dotenv import load_dotenv
from fyras_token_auth.claim_extraction.auth import TokenVerifier
from fyras_token_auth.schemas.claims_response import AuthContext

load_dotenv()

@pytest.fixture(scope="module")
def verifier() -> TokenVerifier:
    return TokenVerifier()

@pytest.fixture(scope="module")
def valid_token() -> str:
    token = os.getenv("TEST_TENANT_TOKEN")
    if not token:
        raise RuntimeError("TEST_TENANT_TOKEN not found in environment")
    return token

def test_verify_token_success(verifier, valid_token):
    """Test successful verification of a valid JWT token."""
    payload = verifier.verify_token(valid_token)
    assert isinstance(payload, dict)
    assert "iss" in payload
    assert "aud" in payload
    assert "exp" in payload

def test_get_auth_context_success(verifier, valid_token):
    """Test successful extraction of AuthContext from a valid token."""
    context = verifier.get_auth_context(valid_token)
    assert isinstance(context, AuthContext)
    assert context.iss is not None
    assert context.aud is not None
    assert context.exp is not None
    assert context.kid is not None
    assert context.alg == "RS256"

def test_invalid_token_signature(verifier):
    """Test behavior when token has an invalid signature."""
    bad_token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZha2UgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0."
        "FakeSignature"
    )
    with pytest.raises(ValueError, match="Token decoding failed"):
        verifier.verify_token(bad_token)

def test_invalid_issuer(verifier, valid_token):
    """Test token with tampered issuer fails verification."""
    parts = valid_token.split(".")
    import base64, json

    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    payload["iss"] = "https://untrusted.issuer.com"
    tampered_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    with pytest.raises(ValueError, match="Token issuer is not trusted"):
        verifier.verify_token(tampered_token)

def test_protected_attributes(verifier):
    """Test that tenant_id and client_id attributes are inaccessible."""
    with pytest.raises(AttributeError):
        _ = verifier.tenant_id
    with pytest.raises(AttributeError):
        _ = verifier.client_id
