from fastapi import APIRouter, HTTPException, Request
from src.core.claim_extraction import get_claims

router = APIRouter()


@router.post("/extract-claims")
async def extract_claims_endpoint(request: Request):
    try:
        claims_response = get_claims(request)
        return {"claims": claims_response.jsonify()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
