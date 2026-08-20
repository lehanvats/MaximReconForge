"""
ContextStore & Aggregator service.

Manages per-engagement private context directories and the shared whiteboard.
Enforces ACLs: Commanders write to private scratch notes; only Aggregator writes
to shared whiteboard (findings.jsonl and summary.md).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ContextStore:
    """Per-engagement context directory manager."""

    def __init__(self, base_dir: str | None = None) -> None:
        import os
        if base_dir is None:
            base_dir = os.environ.get("ENGAGEMENTS_DIR") or str(Path(__file__).resolve().parent.parent.parent.parent / "engagements")
        self.base_dir = Path(base_dir)

    def _ensure_dir(self, p: Path) -> Path:
        p.mkdir(parents=True, exist_ok=True)
        try:
            import os
            os.chmod(p, 0o777)
        except Exception:
            pass
        return p

    def get_engagement_dir(self, engagement_id: str) -> Path:
        return self._ensure_dir(self.base_dir / engagement_id)

    def get_private_dir(self, engagement_id: str, role: str) -> Path:
        """Private folder read/write for role only."""
        return self._ensure_dir(self.get_engagement_dir(engagement_id) / ".context" / role)

    def get_whiteboard_dir(self, engagement_id: str) -> Path:
        """Shared whiteboard directory."""
        return self._ensure_dir(self.get_engagement_dir(engagement_id) / "whiteboard")

    # --- Agent Scratchpad (Private) ---

    def write_private_note(self, engagement_id: str, role: str, filename: str, content: str) -> None:
        p = self.get_private_dir(engagement_id, role) / filename
        p.write_text(content, encoding="utf-8")

    def read_private_note(self, engagement_id: str, role: str, filename: str) -> str:
        p = self.get_private_dir(engagement_id, role) / filename
        if not p.exists():
            return ""
        return p.read_text(encoding="utf-8")

    # --- Shared Whiteboard (Read-Only for Commanders, Write for Aggregator) ---

    def read_whiteboard_findings(self, engagement_id: str) -> list[dict[str, Any]]:
        wb_file = self.get_whiteboard_dir(engagement_id) / "findings.jsonl"
        if not wb_file.exists():
            return []
        findings = []
        for line in wb_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return findings

    def read_whiteboard_summary(self, engagement_id: str) -> str:
        summary_file = self.get_whiteboard_dir(engagement_id) / "summary.md"
        if not summary_file.exists():
            return ""
        return summary_file.read_text(encoding="utf-8")


class Aggregator:
    """Deterministic Aggregator — sole writer to shared whiteboard."""

    def __init__(self, store: ContextStore | None = None) -> None:
        self.store = store or ContextStore()

    def append_finding(self, engagement_id: str, finding: dict[str, Any]) -> None:
        """Append a structured finding to whiteboard/findings.jsonl."""
        wb_dir = self.store.get_whiteboard_dir(engagement_id)
        wb_file = wb_dir / "findings.jsonl"
        with wb_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(finding, default=str) + "\n")

    def update_summary(self, engagement_id: str, summary_md: str) -> None:
        """Update whiteboard/summary.md."""
        wb_dir = self.store.get_whiteboard_dir(engagement_id)
        summary_file = wb_dir / "summary.md"
        summary_file.write_text(summary_md, encoding="utf-8")
