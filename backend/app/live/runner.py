"""Inline engagement runner (localhost mode).

Executes the LangGraph supervisor graph directly inside the FastAPI process
(no Redis/arq/Docker worker) and streams progress + log lines to the live bus.

This is the web-facing counterpart of ``run_cli.py``: same graph, same native
scanners, same report output — but wired to a browser instead of a terminal.
"""

from __future__ import annotations

import contextvars
import logging
import time
from typing import Any

from app.context_store.store import ContextStore
from app.graph.state import EngagementState
from app.graph.supervisor import build_supervisor_graph
from app.live.bus import bus

logger = logging.getLogger(__name__)

# Tracks which engagement the current asyncio task tree belongs to, so the log
# bridge can route records emitted deep inside the graph to the right stream.
current_engagement: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_engagement", default=None
)

# Per-node progress + human label, emitted as each graph node completes. Values
# are cumulative percentages so the frontend rail advances monotonically.
_PHASE_META: dict[str, tuple[int, str, str]] = {
    # node name -> (progress %, stage id, label)
    "recon": (50, "recon", "Reconnaissance"),
    "enumeration": (60, "enumeration", "Enumeration"),
    "vuln_analysis": (76, "vuln_analysis", "Vulnerability analysis"),
    "exploitation": (88, "exploitation", "Exploitation"),
    "reporting": (98, "reporting", "Report generation"),
}

_STAGE_ORDER = ["validation", "recon", "enumeration", "vuln_analysis", "exploitation", "reporting"]


class _BusLogHandler(logging.Handler):
    """Forwards log records for the active engagement to the live bus."""

    def emit(self, record: logging.LogRecord) -> None:
        engagement_id = current_engagement.get()
        if engagement_id is None:
            return
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return
        bus.publish(
            engagement_id,
            {
                "type": "log",
                "level": record.levelname,
                "logger": record.name,
                "line": message,
            },
        )


_log_bridge_installed = False


def install_log_bridge() -> None:
    """Attach the bus log handler to the app loggers (idempotent)."""
    global _log_bridge_installed
    if _log_bridge_installed:
        return
    handler = _BusLogHandler()
    handler.setLevel(logging.INFO)
    # Attach to the "app" logger tree — every scanner/commander/node logs under it.
    app_logger = logging.getLogger("app")
    app_logger.addHandler(handler)
    app_logger.setLevel(logging.INFO)
    _log_bridge_installed = True


def compute_summary(findings: list[dict[str, Any]], target_domain: str) -> dict[str, int]:
    """Derive the four headline counts the frontend summary strip shows."""
    subdomains = sum(1 for f in findings if f.get("type") == "subdomain")
    live_hosts = sum(1 for f in findings if f.get("type") == "http_response")
    endpoints = sum(1 for f in findings if f.get("type") in ("exposed_path", "forbidden_path"))
    open_ports = sum(1 for f in findings if f.get("type") == "open_port")
    return {
        # +1 for the apex domain itself, which is always in scope.
        "subdomains": subdomains + 1,
        "liveHosts": live_hosts,
        "urls": endpoints,
        "openPorts": open_ports,
    }


async def _set_status(engagement_id: str, status: str) -> None:
    """Best-effort engagement status update; never fail the run over it."""
    try:
        import uuid

        from app.db.models import Engagement
        from app.db.session import async_session

        async with async_session() as session:
            engagement = await session.get(Engagement, uuid.UUID(engagement_id))
            if engagement is not None:
                engagement.status = status
                await session.commit()
    except Exception as exc:  # pragma: no cover - DB is optional for the stream
        logger.debug("Could not update engagement %s status: %s", engagement_id, exc)


async def run_engagement_inline(
    engagement_id: str,
    target_domain: str,
    user_id: str,
    risky_tools_enabled: bool = False,
) -> None:
    """Run the full supervisor graph, streaming progress to the bus."""
    install_log_bridge()
    token = current_engagement.set(engagement_id)
    started_at = time.monotonic()
    completed_stages: list[str] = []

    def emit_phase(stage_id: str, progress: int, label: str) -> None:
        if stage_id not in completed_stages:
            completed_stages.append(stage_id)
        bus.publish(
            engagement_id,
            {
                "type": "phase",
                "stageId": stage_id,
                "progress": progress,
                "label": label,
                "completedStages": list(completed_stages),
                "totalStages": len(_STAGE_ORDER),
            },
        )

    try:
        await _set_status(engagement_id, "running")
        bus.publish(engagement_id, {"type": "started", "target": target_domain})
        logger.info("[ENGAGEMENT] Starting live assessment for %s", target_domain)
        emit_phase("validation", 6, "Target validation")

        graph = build_supervisor_graph()
        initial_state: EngagementState = {
            "engagement_id": engagement_id,
            "target_domain": target_domain,
            "user_id": user_id,
            "status": "pending",
            "current_phase": "recon",
            "abort_requested": False,
            "risky_tools_enabled": risky_tools_enabled,
            "iteration_count": 0,
            "token_usage": 0,
            "scope_entries": [],
            "assets": [],
            "findings": [],
            "messages": [],
        }

        async for update in graph.astream(initial_state, stream_mode="updates"):
            for node_name, node_output in update.items():
                meta = _PHASE_META.get(node_name)
                if meta is not None:
                    progress, stage_id, label = meta
                    emit_phase(stage_id, progress, label)
                if node_name == "recon" and isinstance(node_output, dict):
                    findings = node_output.get("findings", []) or []
                    bus.publish(
                        engagement_id,
                        {"type": "counts", "summary": compute_summary(findings, target_domain)},
                    )

        # Final report + counts from the persisted whiteboard.
        store = ContextStore()
        all_findings = store.read_whiteboard_findings(engagement_id)
        summary = compute_summary(all_findings, target_domain)
        report_file = store.get_engagement_dir(engagement_id) / "report" / "final_report.md"
        has_report = report_file.exists()

        await _set_status(engagement_id, "completed")
        emit_phase("reporting", 100, "Complete")
        logger.info("[ENGAGEMENT] Assessment complete for %s", target_domain)
        bus.publish(
            engagement_id,
            {
                "type": "complete",
                "status": "completed",
                "durationSeconds": int(time.monotonic() - started_at),
                "summary": summary,
                "hasReport": has_report,
                "findingsCount": len(all_findings),
            },
        )
    except Exception as exc:
        logger.exception("[ENGAGEMENT] Assessment failed for %s", target_domain)
        await _set_status(engagement_id, "failed")
        bus.publish(
            engagement_id,
            {"type": "error", "message": f"{type(exc).__name__}: {exc}"},
        )
    finally:
        bus.finish(engagement_id)
        current_engagement.reset(token)
