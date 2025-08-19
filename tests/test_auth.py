import os
import pytest
from unittest.mock import patch, MagicMock
from dotenv import load_dotenv
from fyras_token_auth.claim_extraction.auth import TokenVerifier
from fyras_token_auth.schemas.claims_response import AuthContext

load_dotenv()

@pytest.fixture(scope="module")
def mock_jwks():
    """Mock JWKS response for testing."""
    return {
        "keys": [
            {
                "kid": "test-key-id",
                "kty": "RSA",
                "use": "sig",
                "n": "test-modulus",
                "e": "AQAB"
            }
        ]
    }

@pytest.fixture(scope="module")
def mock_openid_config():
    """Mock OpenID configuration response."""
    return {
        "issuer": "https://login.microsoftonline.com/20c5e6f4-ceef-4c8d-a854-cdb6f5a08fba/v2.0",
        "jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    }

@pytest.fixture(scope="module")
def verifier(mock_openid_config, mock_jwks) -> TokenVerifier:
    """Create a TokenVerifier with mocked network calls."""
    with patch('requests.get') as mock_get:
        # Mock the OpenID config response
        config_response = MagicMock()
        config_response.json.return_value = mock_openid_config
        config_response.raise_for_status.return_value = None
        
        # Mock the JWKS response
        jwks_response = MagicMock()
        jwks_response.json.return_value = mock_jwks
        jwks_response.raise_for_status.return_value = None
        
        # Configure mock to return different responses based on URL
        def side_effect(url, **kwargs):
            if 'openid-configuration' in url:
                return config_response
            elif 'keys' in url:
                return jwks_response
            return MagicMock()
        
        mock_get.side_effect = side_effect
        return TokenVerifier()

@pytest.fixture(scope="module")
def valid_token() -> str:
    token = os.getenv("TEST_TENANT_TOKEN")
    if not token:
        raise RuntimeError("TEST_TENANT_TOKEN not found in environment")
    return token

def test_verify_token_success(verifier, valid_token):
    """Test successful verification of a valid JWT token."""
    # Mock both the public key retrieval and JWT decode to skip signature verification
    with patch.object(verifier, '_TokenVerifier__get_public_key') as mock_get_key, \
         patch('jwt.decode') as mock_decode:
        
        mock_get_key.return_value = "mock-public-key"
        mock_decode.return_value = {
            "iss": "https://login.microsoftonline.com/20c5e6f4-ceef-4c8d-a854-cdb6f5a08fba/v2.0",
            "aud": "79b961dd-435b-43dc-b05c-a8b366798546",
            "exp": 9999999999,
            "tid": "20c5e6f4-ceef-4c8d-a854-cdb6f5a08fba",
            "sub": "test-user-456",
            "name": "Test User",
            "email": "test.user@testorg.com"
        }
        payload = verifier.verify_token(valid_token)
        assert isinstance(payload, dict)
        assert "iss" in payload
        assert "aud" in payload
        assert "exp" in payload

def test_get_auth_context_success(verifier, valid_token):
    """Test successful extraction of AuthContext from a valid token."""
    # Mock both the public key retrieval and JWT decode to skip signature verification
    with patch.object(verifier, '_TokenVerifier__get_public_key') as mock_get_key, \
         patch('jwt.decode') as mock_decode:
        
        mock_get_key.return_value = "mock-public-key"
        mock_decode.return_value = {
            "iss": "https://login.microsoftonline.com/20c5e6f4-ceef-4c8d-a854-cdb6f5a08fba/v2.0",
            "aud": "79b961dd-435b-43dc-b05c-a8b366798546",
            "exp": 9999999999,
            "tid": "20c5e6f4-ceef-4c8d-a854-cdb6f5a08fba",
            "sub": "test-user-456",
            "name": "Test User",
            "email": "test.user@testorg.com",
            "iat": 1600000000
        }
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
