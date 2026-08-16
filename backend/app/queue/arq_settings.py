"""
ARQ connection pool and job dispatch helpers.

Provides:
- enqueue_recon_job:  Kicks off the deterministic recon pipeline in the worker.
- enqueue_tool_job:   Dispatches a single tool call to the worker and waits for result.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from arq import create_pool
from arq.connections import RedisSettings, ArqRedis
from arq.jobs import Job

from app.config import settings

logger = logging.getLogger(__name__)

_pool: ArqRedis | None = None


async def get_arq_pool() -> ArqRedis:
    global _pool
    if _pool is None:
        _pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    return _pool


async def enqueue_recon_job(engagement_id: str, domain: str) -> Job:
    """Enqueue the full recon pipeline (subfinder → httpx → naabu → nmap).

    Returns the ARQ Job handle so the caller can optionally await results.
    """
    pool = await get_arq_pool()
    job = await pool.enqueue_job("run_recon", engagement_id, domain)
    logger.info("Enqueued run_recon for engagement=%s domain=%s", engagement_id, domain)
    return job


async def enqueue_tool_job(
    engagement_id: str,
    tool_name: str,
    params: dict[str, Any],
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Dispatch a single tool execution to the Docker worker and wait for the result.

    This is the missing bridge that lets graph nodes dispatch tool calls like
    run_nuclei, run_ffuf, run_sqlmap to the sandboxed worker container where
    the real binaries live.
    """
    pool = await get_arq_pool()
    job = await pool.enqueue_job(
        "run_tool_job",
        engagement_id,
        tool_name,
        params,
        timeout_seconds,
    )
    logger.info(
        "Enqueued run_tool_job: engagement=%s tool=%s", engagement_id, tool_name
    )

    # Poll for result — ARQ stores results in Redis.  We allow extra time for
    # queue latency on top of the tool's own timeout.
    wait_timeout = timeout_seconds + 60
    try:
        result = await job.result(timeout=wait_timeout)
    except asyncio.TimeoutError:
        logger.error(
            "Timed out waiting for worker result: engagement=%s tool=%s",
            engagement_id, tool_name,
        )
        return {
            "engagement_id": engagement_id,
            "tool_name": tool_name,
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "result_hash": "",
            "error": f"Worker result timeout after {wait_timeout}s",
        }

    return result


async def wait_for_recon(job: Job, timeout: int = 660) -> dict[str, Any]:
    """Wait for a previously enqueued recon job to complete."""
    try:
        return await job.result(timeout=timeout)
    except asyncio.TimeoutError:
        logger.error("Timed out waiting for recon pipeline result")
        return {"status": "error", "error": f"Recon pipeline timeout after {timeout}s"}
