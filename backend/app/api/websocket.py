"""Live engagement WebSocket stream.

Authenticates the socket from the same httpOnly access-token cookie the REST
API uses, verifies the caller owns the engagement, then relays progress + log
events from the in-process bus until the run ends or the client disconnects.
"""

import uuid
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError

from app.auth.security import decode_token
from app.db.models import Engagement
from app.db.session import async_session
from app.live.bus import bus

logger = logging.getLogger(__name__)

router = APIRouter()

# Close codes (application range) used when we reject a socket before streaming.
_WS_UNAUTHORIZED = 4401
_WS_NOT_FOUND = 4404


async def _authorize(websocket: WebSocket, engagement_id: uuid.UUID) -> bool:
    """Return True if the cookie identifies a user who owns this engagement."""
    token = websocket.cookies.get("access_token")
    if not token:
        return False
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            return False
        user_id = uuid.UUID(payload["sub"])
    except (JWTError, ValueError, KeyError):
        return False

    async with async_session() as session:
        engagement = await session.get(Engagement, engagement_id)
        if engagement is None or engagement.created_by != user_id:
            return False
    return True


@router.websocket("/ws/engagements/{engagement_id}/live")
async def engagement_live(websocket: WebSocket, engagement_id: uuid.UUID):
    """Stream live progress + log events for an engagement to the browser."""
    await websocket.accept()

    if not await _authorize(websocket, engagement_id):
        await websocket.close(code=_WS_UNAUTHORIZED, reason="Not authorized")
        return

    engagement_key = str(engagement_id)
    queue = bus.subscribe(engagement_key)
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
            if event.get("type") == "end":
                break
    except WebSocketDisconnect:
        logger.debug("Client disconnected from engagement %s stream", engagement_key)
    except Exception:  # pragma: no cover - defensive: keep the endpoint alive
        logger.exception("Error while streaming engagement %s", engagement_key)
    finally:
        bus.unsubscribe(engagement_key, queue)
