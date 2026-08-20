import uuid
from fastapi import APIRouter, Cookie, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import User
from app.auth.schemas import UserCreate, UserLogin, UserOut
from app.auth.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    set_auth_cookies,
    clear_auth_cookies,
    get_current_user,
)

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=UserOut)
async def register(payload: UserCreate, response: Response, db: AsyncSession = Depends(get_db)):
    # Registration is permanently disabled — this is a single-tenant, locked
    # deployment. The only valid account is provisioned out-of-band via
    # scripts/seed_admin.py. Reject every registration attempt at the API layer
    # so the lock holds even if the frontend is bypassed.
    raise HTTPException(status_code=403, detail="No new registrations possible.")

@router.post("/login", response_model=UserOut)
async def login(payload: UserLogin, response: Response, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(User).where(User.email == payload.email))
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    set_auth_cookies(response, create_access_token(str(user.id)), create_refresh_token(str(user.id)))
    return user

@router.post("/refresh", response_model=UserOut)
async def refresh(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
):
    if refresh_token is None:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    try:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise ValueError
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User no longer exists")

    set_auth_cookies(response, create_access_token(str(user.id)), create_refresh_token(str(user.id)))
    return user

@router.post("/logout")
async def logout(response: Response):
    clear_auth_cookies(response)
    return {"detail": "Logged out"}

@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return current_user
