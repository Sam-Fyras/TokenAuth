from fastapi import Request, HTTPException
from datetime import datetime
import jwt
import pathlib
from src.schemas.claims_response import ClaimsResponse


def extract_auth_header(request: Request):
    """
    Extracts the JWT token from the Authorization header of the request.
    Args:
        request: FastAPI Request object containing headers.

    Returns:
        str: The JWT token extracted from the Authorization header.

    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    return auth_header.split(" ")[1]


def get_jwt_header_and_payload(token: str):
    """
    Extracts the header and payload from a JWT token without verifying the signature.
    Args:
        token: str: The JWT token to decode.

    Returns:
        tuple: A tuple containing the JWT header and payload.

    """
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        return header, payload
    except jwt.DecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid token format: {str(e)}")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=400, detail=f"Invalid token structure: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Token validation error: {str(e)}")


def validate_jwt_header(header):
    """
    Validates the JWT header to ensure it contains the expected fields.
    Args:
        header: dict: The JWT header to validate.

    Returns:
        str: The algorithm used in the JWT header if valid.

    """
    if header.get("typ") != "JWT":
        raise HTTPException(status_code=400, detail="Invalid token type, expected JWT")
    alg = header.get("alg")
    if alg not in ["RS256", "RS512"]:
        raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {alg}")
    if not header.get("kid"):
        raise HTTPException(status_code=400, detail="Token missing key ID")
    return alg


def validate_jwt_claims(payload):
    """
    Validates the JWT payload to ensure it contains the required claims.
    Args:
        payload: dict: The JWT payload to validate.

    Returns:
        None: If all required claims are present.

    """
    required_claims = ["iss", "aud", "exp", "tid"]
    missing_claims = [claim for claim in required_claims if not payload.get(claim)]
    if missing_claims:
        raise HTTPException(status_code=400, detail=f"Token missing required claims: {missing_claims}")


def check_token_expiration(payload):
    """
    Checks if the JWT token has expired based on the 'exp' claim.
    Args:
        payload: The decoded JWT payload containing claims.

    Returns:
        bool: True if the token is still valid, False if it has expired.

    """
    exp = payload.get("exp")
    if exp:
        current_time = datetime.now().timestamp()
        if current_time <= exp:
            return True

    # If 'exp' claim is missing or token has expired
    raise HTTPException(status_code=401, detail="Token has expired or is invalid")


def get_claims(request: Request):
    """
    Extracts the tenant ID from the JWT token in the Authorization header.

    Parameters:
    - request: FastAPI Request object containing headers.

    Returns:
    - JSON response with the tenant ID if valid.
    """
    token = extract_auth_header(request)
    header, payload = get_jwt_header_and_payload(token)
    alg = validate_jwt_header(header)
    validate_jwt_claims(payload)
    if check_token_expiration(payload):
        return ClaimsResponse(
            iss=payload.get("iss"),
            aud=payload.get("aud"),
            exp=payload.get("exp"),
            tid=payload.get("tid"),
            kid=header.get("kid"),
            alg=alg,
            iat=payload.get("iat"),
            nbf=payload.get("nbf"),
            sub=payload.get("sub"),
            name=payload.get("name"),
            email=payload.get("email")
        )
        return None
    return None
