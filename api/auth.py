# Authentication-related functionality

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.future import select
from jose import jwt
from core.security import verify_jwt, get_public_key
from core.hashing import hash_password, verify_password
from models.models import User
from db.db import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
import datetime
from core.config import SECRET_KEY, ALGORITHM


router = APIRouter()


class UserCreate(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def generate_jwt(user_id: int):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    payload = {"sub": str(user_id), "exp": expiration}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/register", response_model=TokenResponse)
async def register_user(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.email == user_data.email))
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_pw = await hash_password(user_data.password)
    new_user = User(email=user_data.email, password_hash=hashed_pw)
    db.add(new_user)
    await db.commit()
    return generate_jwt(new_user.id)


@router.post("/login", response_model=TokenResponse)
async def login(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.email == user_data.email))
    user = result.scalars().first()
    if not user or not await verify_password(user_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return generate_jwt(user.id)
