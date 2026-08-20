"""Lock the deployment to a single admin credential.

This provisions (or resets) the one and only account allowed to log in, then
deletes every other user so the product is locked to exactly one credential.

The password is NEVER hardcoded or committed. It is read from the
ADMIN_SEED_PASSWORD environment variable at runtime:

    ADMIN_SEED_PASSWORD='<the-32-char-password>' python -m scripts.seed_admin

On the VPS, inside the backend container:

    docker compose exec -e ADMIN_SEED_PASSWORD='<password>' backend \
        python -m scripts.seed_admin

Idempotent: run it again any time to reset the password or re-purge stray users.
"""
import asyncio
import os
import sys

from sqlalchemy import delete, select, update

from app.db.session import async_session
from app.db.models import User, Engagement
from app.auth.security import hash_password

ADMIN_EMAIL = "maximtester@gmail.com"


async def seed() -> None:
    password = os.environ.get("ADMIN_SEED_PASSWORD")
    if not password:
        print(
            "ERROR: set ADMIN_SEED_PASSWORD to the admin password before running.\n"
            "  ADMIN_SEED_PASSWORD='...' python -m scripts.seed_admin",
            file=sys.stderr,
        )
        sys.exit(1)

    async with async_session() as db:
        admin = await db.scalar(select(User).where(User.email == ADMIN_EMAIL))
        if admin is None:
            admin = User(email=ADMIN_EMAIL, hashed_password=hash_password(password))
            db.add(admin)
            await db.flush()  # assign admin.id so the purge below can exclude it
            action = "Created"
        else:
            admin.hashed_password = hash_password(password)
            action = "Reset password for"

        # Lock to exactly one credential. Other users may own engagements
        # (engagements.created_by -> users.id), so reassign those to the admin
        # first — otherwise the FK constraint blocks the delete. This keeps all
        # engagement/scan history intact under the single surviving account.
        reassigned = await db.execute(
            update(Engagement)
            .where(Engagement.created_by != admin.id)
            .values(created_by=admin.id)
        )
        result = await db.execute(delete(User).where(User.id != admin.id))
        await db.commit()

    print(f"{action} admin: {ADMIN_EMAIL}")
    print(
        f"Reassigned {reassigned.rowcount} engagement(s) to admin; "
        f"purged {result.rowcount} other user(s). Only {ADMIN_EMAIL} can now log in."
    )


if __name__ == "__main__":
    asyncio.run(seed())
