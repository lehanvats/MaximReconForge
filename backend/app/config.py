from pathlib import Path
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Insecure placeholder used only for local development. Startup fails if this
# value (or an empty one) survives into any non-development environment.
_DEV_JWT_SECRET = "dev-secret-key-change-in-production-32-chars-min"


class Settings(BaseSettings):
    environment: str = "development"

    # --- Auth ---
    jwt_secret_key: str = _DEV_JWT_SECRET
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # --- Database (Supabase Postgres) ---
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/maximreconforge"
    supabase_url: str = ""
    supabase_service_role_key: str = ""

    # --- Task queue ---
    redis_url: str = "redis://localhost:6379/0"

    # --- Frontend ---
    frontend_origin: str = "http://localhost:3000"
    # Extra allowed browser origins for local dev (comma-separated). The Vite
    # dev server may run on 3000 or 5173 depending on how it's started.
    extra_cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://127.0.0.1:3000"

    # --- Execution mode ---
    # Localhost mode: run the recon graph inline in the API process and stream
    # progress over WebSocket, instead of dispatching to the Redis/arq worker.
    run_scans_inline: bool = True

    # --- LLM: Groq (active) via OpenAI-compatible API ---
    groq_api_key: str = ""
    llm_default_model: str = "openai/gpt-oss-120b"
    llm_reporting_model: str = "openai/gpt-oss-120b"
    llm_fast_model: str = "openai/gpt-oss-20b"

    # --- LLM: Anthropic (future, not active yet) ---
    anthropic_api_key: str = ""

    # --- Embeddings (stub until Voyage AI key provided) ---
    voyageai_api_key: str = ""
    embedding_model: str = "voyage-3"
    embedding_dimension: int = 1024

    # --- Circuit breakers ---
    vuln_analysis_iteration_cap: int = 10
    exploitation_iteration_cap: int = 20
    vuln_analysis_token_ceiling: int = 100_000
    exploitation_token_ceiling: int = 200_000

    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parent.parent.parent / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @model_validator(mode="after")
    def _require_secure_jwt_secret(self) -> "Settings":
        """Reject the placeholder/empty JWT secret outside development.

        Without this, shipping to a non-dev environment without an override
        would leave every JWT trivially forgeable. Fail fast at startup instead.
        """
        if self.environment.lower() not in ("development", "dev", "test", "testing"):
            if not self.jwt_secret_key or self.jwt_secret_key == _DEV_JWT_SECRET:
                raise ValueError(
                    "JWT_SECRET_KEY must be set to a strong, unique value in "
                    f"the '{self.environment}' environment (the development "
                    "placeholder is not allowed)."
                )
            if len(self.jwt_secret_key) < 32:
                raise ValueError(
                    "JWT_SECRET_KEY must be at least 32 characters long."
                )
        return self


settings = Settings()
