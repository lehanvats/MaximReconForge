from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.auth.routes import router as auth_router
from app.api.engagements import router as engagements_router
from app.api.websocket import router as websocket_router
from app.db.session import engine
from app.db.models import Base

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-create tables (safe on SQLite; no-op if they already exist)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

app = FastAPI(title="MaximReconForge", lifespan=lifespan)

_allowed_origins = [settings.frontend_origin] + [
    origin.strip()
    for origin in settings.extra_cors_origins.split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(engagements_router)
app.include_router(websocket_router)

@app.get("/health")
async def health():
    return {"status": "ok"}
