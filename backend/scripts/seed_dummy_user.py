"""Seed a dummy login account for local development/testing.

Usage: python -m scripts.seed_dummy_user
"""
import asyncio
from sqlalchemy import select
from app.db.session import async_session
from app.db.models import User
from app.auth.security import hash_password

DUMMY_EMAIL = "test@maximrecon.com"
DUMMY_PASSWORD = "test1234"

async def seed() -> None:
    async with async_session() as db:
        existing = await db.scalar(select(User).where(User.email == DUMMY_EMAIL))
        if existing:
            print(f"Dummy user already exists: {DUMMY_EMAIL}")
            return
        user = User(email=DUMMY_EMAIL, hashed_password=hash_password(DUMMY_PASSWORD))
        db.add(user)
        await db.commit()
        print(f"Created dummy user: {DUMMY_EMAIL} / {DUMMY_PASSWORD}")

if __name__ == "__main__":
    asyncio.run(seed())
