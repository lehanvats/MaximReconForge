import uuid
from datetime import datetime, timedelta
from fastapi import Cookie, Depends, HTTPException, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.db.session import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ACCESS_COOKIE_NAME = "access_token"
REFRESH_COOKIE_NAME = "refresh_token"

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(subject: str, expires_delta: timedelta, token_type: str) -> str:
    expire = datetime.utcnow() + expires_delta
    payload = {"sub": subject, "exp": expire, "type": token_type}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

def create_access_token(subject: str) -> str:
    return create_token(subject, timedelta(minutes=settings.jwt_access_token_expire_minutes), "access")

def create_refresh_token(subject: str) -> str:
    return create_token(subject, timedelta(days=settings.jwt_refresh_token_expire_days), "refresh")

def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])

def set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    # Cross-site deployments (frontend on Vercel, backend on the VPS) need
    # SameSite=None; Secure so the browser replays the cookie on API calls.
    # Same-origin/local dev keeps the SameSite=Lax, insecure defaults.
    secure = settings.cookie_secure
    samesite = settings.cookie_samesite.lower()
    response.set_cookie(
        ACCESS_COOKIE_NAME,
        access_token,
        max_age=settings.jwt_access_token_expire_minutes * 60,
        httponly=True,
        secure=secure,
        samesite=samesite,
        path="/",
    )
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        refresh_token,
        max_age=settings.jwt_refresh_token_expire_days * 24 * 60 * 60,
        httponly=True,
        secure=secure,
        samesite=samesite,
        path="/",
    )

def clear_auth_cookies(response: Response) -> None:
    # Deletion only takes effect if the attributes match the ones the cookie
    # was set with, so mirror secure/samesite from settings.
    secure = settings.cookie_secure
    samesite = settings.cookie_samesite.lower()
    response.delete_cookie(
        ACCESS_COOKIE_NAME, path="/", secure=secure, samesite=samesite, httponly=True
    )
    response.delete_cookie(
        REFRESH_COOKIE_NAME, path="/", secure=secure, samesite=samesite, httponly=True
    )

async def get_current_user(
    access_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
):
    from app.db.models import User

    if access_token is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_token(access_token)
        if payload.get("type") != "access":
            raise JWTError
        user_id = uuid.UUID(payload["sub"])
    except (JWTError, ValueError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return user
