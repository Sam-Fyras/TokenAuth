import os
import jwt
import requests
import logging
from typing import Dict, Tuple, List
from dotenv import load_dotenv
from fyras_token_auth.schemas.claims_response import AuthContext

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class TokenVerifier:
    """
    A utility class to validate and decode Azure AD JWT tokens using OpenID Connect metadata.

    Attributes:
        __tenant_id (str): Azure AD tenant ID, loaded from environment.
        __client_id (str): Azure AD client (application) ID, loaded from environment.
        __audiences (List[str]): Expected audience strings derived from the client ID.
        __issuer (str): Token issuer retrieved from OpenID configuration.
        __jwks (dict): JSON Web Key Set used to verify token signatures.
    """

    def __init__(self):
        # Try to load .env from multiple possible locations
        import pathlib
        current_dir = pathlib.Path.cwd()
        possible_env_paths = [
            current_dir / ".env",
            current_dir.parent / ".env",
            pathlib.Path(__file__).parent.parent.parent / "ContentModeratorService" / ".env",
            pathlib.Path(__file__).parent.parent.parent / "LLMFirewall" / ".env"
        ]

        for env_path in possible_env_paths:
            if env_path.exists():
                load_dotenv(env_path)
                logger.debug(f"[TokenVerifier] Loaded .env from: {env_path}")
                break
        else:
            load_dotenv()  # Fallback to default behavior

        self.__tenant_id: str = os.getenv("AZURE_TENANT_ID", "")
        self.__client_id: str = os.getenv("AZURE_CLIENT_ID", "")

        if not self.__tenant_id:
            logger.error("[TokenVerifier] AZURE_TENANT_ID not found in environment variables")
            raise RuntimeError("AZURE_TENANT_ID environment variable is required")

        if not self.__client_id:
            logger.error("[TokenVerifier] AZURE_CLIENT_ID not found in environment variables")
            raise RuntimeError("AZURE_CLIENT_ID environment variable is required")

        # Accept both "api://<client_id>" and "<client_id>" as valid audiences
        self.__audiences: List[str] = [f"api://{self.__client_id}", self.__client_id]
        logger.debug(
            f"[TokenVerifier] Initialized with tenant_id: {self.__tenant_id}, client_id: {self.__client_id}, audiences: {self.__audiences}")
        self.__issuer, self.__jwks = self.__fetch_openid_metadata()

    # Properties to restrict access to sensitive attributes
    @property
    def tenant_id(self) -> str:
        raise AttributeError("Access to tenant_id is restricted")

    @property
    def client_id(self) -> str:
        raise AttributeError("Access to client_id is restricted")

    def __fetch_openid_metadata(self) -> Tuple[str, Dict]:
        """
        Fetches the OpenID configuration and JWKS for the tenant.

        Returns:
            Tuple[str, Dict]: Issuer URL and JWKS dictionary.

        Raises:
            RuntimeError: If metadata cannot be fetched.
        """
        logger.info(f"[TokenVerifier] Fetching metadata for tenant: {self.__tenant_id}")
        config_url = f"https://login.microsoftonline.com/{self.__tenant_id}/v2.0/.well-known/openid-configuration"

        try:
            logger.debug(f"[TokenVerifier] Fetching config from: {config_url}")
            config_response = requests.get(config_url, timeout=10)
            config_response.raise_for_status()
            config = config_response.json()

            logger.debug(f"[TokenVerifier] Config keys: {list(config.keys())}")

            if "jwks_uri" not in config:
                logger.error(f"[TokenVerifier] No 'jwks_uri' in config. Available keys: {list(config.keys())}")
                raise RuntimeError("OpenID config missing 'jwks_uri'")

            jwks_url = config["jwks_uri"]
            logger.debug(f"[TokenVerifier] Fetching JWKS from: {jwks_url}")

            jwks_response = requests.get(jwks_url, timeout=10)
            jwks_response.raise_for_status()
            jwks = jwks_response.json()

            logger.info(f"[TokenVerifier] Successfully fetched metadata. Issuer: {config['issuer']}")
            return config["issuer"], jwks

        except requests.exceptions.RequestException as e:
            logger.error(f"[TokenVerifier] Network error fetching OpenID metadata: {e}")
            raise RuntimeError(f"Network error fetching OpenID config: {e}")
        except KeyError as e:
            logger.error(f"[TokenVerifier] Missing key in OpenID config: {e}")
            raise RuntimeError(f"Invalid OpenID config structure: missing {e}")
        except Exception as e:
            logger.error(f"[TokenVerifier] Unexpected error fetching OpenID metadata: {e}")
            raise RuntimeError(f"Unable to fetch OpenID config or JWKS: {e}")

    def __get_public_key(self, kid: str):
        """
        Retrieves the RSA public key from JWKS using the key ID.

        Args:
            kid (str): Key ID from the JWT header.

        Returns:
            RSA public key object.

        Raises:
            ValueError: If no matching key is found.
        """
        logger.debug(f"[TokenVerifier] Finding public key for kid: {kid}")
        for key in self.__jwks["keys"]:
            if key["kid"] == kid:
                # Use PyJWK to convert the key
                from jwt import PyJWK
                jwk = PyJWK(key)
                return jwk.key
        raise ValueError("No matching public key found for 'kid'")

    def __decode_unverified(self, token: str) -> Tuple[Dict, Dict]:
        """
        Decodes the JWT token without verifying the signature.

        Args:
            token (str): Raw JWT string.

        Returns:
            Tuple of decoded header and payload (claims).
        """
        try:
            header = jwt.get_unverified_header(token)
            claims = jwt.decode(token, options={"verify_signature": False})
            return header, claims
        except jwt.exceptions.DecodeError as e:
            logger.error(f"[TokenVerifier] Token decoding failed: {e}")
            raise ValueError(f"Token decoding failed: {e}")

    def verify_token(self, token: str) -> Dict:
        """
        Verifies the token's signature and claims using Azure public keys.

        Args:
            token (str): Raw JWT token.

        Returns:
            Dict: Verified payload (claims).

        Raises:
            ValueError: If signature or issuer is invalid.
        """
        logger.info("[TokenVerifier] Verifying token...")
        header, unverified_claims = self.__decode_unverified(token)

        token_issuer = unverified_claims.get("iss")
        valid_issuers = [
            self.__issuer,
            f"https://sts.windows.net/{self.__tenant_id}/"
        ]
        if token_issuer not in valid_issuers:
            raise ValueError("Token issuer is not trusted")

        public_key = self.__get_public_key(header["kid"])

        try:
            return jwt.decode(
                token,
                key=public_key,
                algorithms=["RS256"],
                audience=self.__audiences,  # <--- Accept both formats
                issuer=token_issuer
            )

        except jwt.PyJWTError as e:
            logger.error(f"[TokenVerifier] Token verification failed: {e}")
            raise ValueError(f"Token verification failed: {e}")

    def get_auth_context(self, token: str) -> AuthContext:
        """
        Verifies the token and converts the claims into an AuthContext object.

        Args:
            token (str): Raw JWT token.

        Returns:
            AuthContext: Structured representation of token claims.
        """
        payload = self.verify_token(token)
        header, _ = self.__decode_unverified(token)

        return AuthContext(
            iss=payload.get("iss"),
            aud=payload.get("aud"),
            exp=payload.get("exp"),
            tid=payload.get("tid"),
            kid=header.get("kid"),
            alg=header.get("alg"),
            iat=payload.get("iat"),
            nbf=payload.get("nbf"),
            sub=payload.get("sub"),
            name=payload.get("name"),
            email=payload.get("email")
        )
