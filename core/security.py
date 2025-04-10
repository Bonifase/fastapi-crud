# Security-related logic (e.g., JWT verification)

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models.models import User
from db.db import get_db
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import httpx
from jose import jwt, JWTError
from fastapi import HTTPException
from cryptography.hazmat.backends import default_backend
import base64
from .config import JWKS_URL, ALGORITHMS, ALGORITHM, AUTH0_AUDIENCE, AUTH0_DOMAIN, SECRET_KEY, M2M_CLIENT_ID

security = HTTPBearer()

async def get_public_key(token: str):
    async with httpx.AsyncClient() as client:
        jwks_response = await client.get(JWKS_URL)
        jwks = jwks_response.json()

        unverified_header = jwt.get_unverified_header(token)

        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                return construct_rsa_public_key(key)

    raise HTTPException(status_code=401, detail="Unable to find matching JWK")


def construct_rsa_public_key(jwk):
    n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=="), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=="), "big")
    public_numbers = rsa.RSAPublicNumbers(e, n)
    return public_numbers.public_key(backend=default_backend())


async def verify_jwt(token: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
        async with httpx.AsyncClient() as client:
            jwks = (await client.get(JWKS_URL)).json()

        rsa_key = None
        for key in jwks["keys"]:
            if key["kid"] == header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
        if not rsa_key:
            raise HTTPException(status_code=401, detail="Invalid token")

        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=AUTH0_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
        )
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid token") from e


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: AsyncSession = Depends(get_db)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

async def get_current_user_or_m2m(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    token = credentials.credentials

    try:
        # Extract the unverified payload to check the token type
        unverified_payload = jwt.get_unverified_claims(token)
        sub = unverified_payload.get("sub", "")

        # If it's an M2M token (client credentials flow)
        if M2M_CLIENT_ID in sub:
            RS_SECRET_KEY = await get_public_key(token)
            payload = jwt.decode(
                token,
                RS_SECRET_KEY,
                algorithms=ALGORITHMS,
                audience=AUTH0_AUDIENCE,
                issuer=f"https://{AUTH0_DOMAIN}/"
            )
            print("Decoded JWT Payload (M2M):", payload)
            return {"m2m": True}  # M2M Client Access

        # Otherwise treat it as a user token (local JWT)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
        result = await db.execute(select(User).filter(User.id == user_id))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user

    except JWTError as e:
        print("JWT Decode Error:", str(e))
        raise HTTPException(status_code=401, detail="Invalid token")