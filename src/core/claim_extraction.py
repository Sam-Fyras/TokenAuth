import os
import jwt
import requests
import logging
from jwt.algorithms import RSAAlgorithm
from dotenv import load_dotenv
from fastapi import Request, HTTPException
from src.schemas.claims_response import AuthContext

# Load environment variables
load_dotenv()

# Configure logging
logger = logging.getLogger("auth")
logging.basicConfig(level=logging.INFO)

FYRAS_TENANT_ID = os.getenv("AZURE_TENANT_ID")
FYRAS_CLIENT_ID = os.getenv("CLIENT_ID")
FYRAS_AUDIENCE = f"api://{FYRAS_CLIENT_ID}"


def extract_auth_header(request: Request) -> str:
    """
    Extracts the JWT token from the Authorization header of a FastAPI request.
    """
    logger.info("Extracting Authorization header.")
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        logger.warning("Authorization header missing or invalid.")
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth_header.split(" ", 1)[1]
    logger.debug("Authorization token extracted successfully.")
    return token


def fetch_openid_config_and_jwks(tenant_id: str):
    """
    Retrieves the OpenID configuration and JWKS keys for the given Azure tenant.
    """
    logger.info(f"Fetching OpenID config for tenant: {tenant_id}")
    config_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
    try:
        config = requests.get(config_url, timeout=5).json()
        jwks_uri = config["jwks_uri"]
        issuer = config["issuer"]
        logger.debug(f"Issuer: {issuer}")
        logger.debug(f"JWKS URI: {jwks_uri}")

        logger.info("Fetching JWKS...")
        jwks = requests.get(jwks_uri, timeout=5).json()
        logger.debug("JWKS successfully fetched.")
        return issuer, jwks
    except Exception as e:
        logger.error(f"Failed to fetch OpenID configuration or JWKS: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve Azure metadata")


def get_public_key(jwks: dict, kid: str):
    """
    Extract the RSA public key from JWKS based on the kid.
    """
    logger.info(f"Locating public key with kid: {kid}")
    for jwk in jwks["keys"]:
        if jwk["kid"] == kid:
            logger.debug(f"Matching key found for kid: {kid}")
            return RSAAlgorithm.from_jwk(jwk)
    logger.error(f"No matching key found for kid: {kid}")
    raise HTTPException(status_code=401, detail="No matching 'kid' found in JWKS")


def decode_token_without_verification(token: str) -> tuple:
    """
    Decode the token header and claims without verifying the signature.
    """
    logger.debug("Decoding token without signature verification.")
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False})
    logger.debug(f"Token header: {header}")
    logger.debug(f"Token claims: {claims}")
    return header, claims


def verify_token_signature(token: str, audience: str, tenant_id: str) -> dict:
    """
    Fully verify the token signature using Azure public keys and expected issuer.
    """
    logger.info("Starting token verification process.")
    header, unverified_claims = decode_token_without_verification(token)

    issuer, jwks = fetch_openid_config_and_jwks(tenant_id)
    public_key_obj = get_public_key(jwks, header["kid"])

    token_issuer = unverified_claims.get("iss")
    issuer_v1 = f"https://sts.windows.net/{tenant_id}/"
    valid_issuers = [issuer, issuer_v1]

    logger.debug(f"Token issuer: {token_issuer}")
    logger.debug(f"Valid issuers: {valid_issuers}")
    logger.debug(f"Expected audience: {audience}")

    if token_issuer not in valid_issuers:
        logger.warning(f"Token issuer '{token_issuer}' is not in the list of accepted issuers.")
        raise HTTPException(status_code=401, detail="Invalid token issuer")

    try:
        logger.info("Verifying token signature and claims...")
        payload = jwt.decode(
            token,
            key=public_key_obj,
            algorithms=["RS256"],
            audience=audience,
            issuer=token_issuer
        )
        logger.info("Token signature successfully verified.")
        return payload
    except jwt.PyJWTError as e:
        logger.error(f"Token verification failed: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Token verification failed: {str(e)}")


def get_claims(request: Request) -> AuthContext:
    """
    Main function to extract, validate, and return token claims.
    """
    logger.info("Extracting and validating token...")
    token = extract_auth_header(request)

    if not FYRAS_TENANT_ID or not FYRAS_CLIENT_ID:
        logger.critical("Environment variables AZURE_TENANT_ID or CLIENT_ID are not set.")
        raise HTTPException(status_code=500, detail="Missing environment config")

    audience = f"api://{FYRAS_CLIENT_ID}"
    claims = verify_token_signature(token, audience, FYRAS_TENANT_ID)
    header, _ = decode_token_without_verification(token)

    logger.debug("Mapping verified claims to AuthContext schema.")
    return AuthContext(
        iss=claims.get("iss"),
        aud=claims.get("aud"),
        exp=claims.get("exp"),
        tid=claims.get("tid"),
        kid=header.get("kid"),
        alg=header.get("alg"),
        iat=claims.get("iat"),
        nbf=claims.get("nbf"),
        sub=claims.get("sub"),
        name=claims.get("name"),
        email=claims.get("email")
    )