"""
MaximReconForge — Local Command Line Assessment Runner

Usage:
    python run_cli.py --target example.com [--risky]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import uuid
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.scope_validator import validate_target_domain, ScopeValidationError
from app.graph.state import EngagementState
from app.graph.supervisor import build_supervisor_graph
from app.context_store.store import ContextStore

# Configure clean terminal logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("MaximReconForge-CLI")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MaximReconForge — Local Assessment CLI Runner"
    )
    parser.add_argument(
        "--target",
        "-t",
        required=True,
        help="Target domain to assess (e.g. example.com)",
    )
    parser.add_argument(
        "--risky",
        action="store_true",
        help="Enable risky exploitation tools (e.g. sqlmap)",
    )
    return parser.parse_args()


async def run_assessment(target_domain: str, risky_enabled: bool = False) -> None:
    print("\n" + "=" * 65)
    print(" [+] MaximReconForge -- Autonomous Assessment Engine")
    print("=" * 65 + "\n")

    # 1. Validate Target Syntax & Scope
    logger.info("Validating target domain: %s", target_domain)
    try:
        resolved_ips = validate_target_domain(target_domain)
        logger.info("Target validated successfully. Resolved IPs: %s", resolved_ips)
    except ScopeValidationError as exc:
        logger.error("Target validation failed: %s", exc)
        sys.exit(1)

    # 2. Generate Local Engagement Storage
    engagement_id = str(uuid.uuid4())
    logger.info("Engagement ID: %s", engagement_id)

    store = ContextStore(base_dir=str(backend_dir.parent / "engagements"))
    eng_dir = store.get_engagement_dir(engagement_id)
    logger.info("Local storage directory: %s", eng_dir)

    # Save metadata snapshot
    meta = {
        "engagement_id": engagement_id,
        "target_domain": target_domain,
        "resolved_ips": resolved_ips,
        "risky_tools_enabled": risky_enabled,
    }
    (eng_dir / "engagement_meta.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )

    # 3. Assemble & Execute LangGraph Supervisor Workflow
    logger.info("Assembling LangGraph Supervisor Workflow...")
    graph = build_supervisor_graph()

    initial_state: EngagementState = {
        "engagement_id": engagement_id,
        "target_domain": target_domain,
        "user_id": "cli-operator",
        "status": "pending",
        "current_phase": "recon",
        "abort_requested": False,
        "risky_tools_enabled": risky_enabled,
        "iteration_count": 0,
        "token_usage": 0,
        "scope_entries": [],
        "assets": [],
        "findings": [],
        "messages": [],
    }

    logger.info("Starting execution across 5 phases...")
    final_state = await graph.ainvoke(initial_state)

    # 4. Display & Report Summary
    print("\n" + "=" * 65)
    print(" [+] Assessment Completed Successfully!")
    print("=" * 65)
    print(f" Status:             {final_state.get('status', 'completed')}")
    print(f" Scope Entries:      {len(final_state.get('scope_entries', []))}")
    print(f" Discovered Assets:  {len(final_state.get('assets', []))}")
    print(f" Findings Recorded:  {len(final_state.get('findings', []))}")
    print(f" Total Tokens Used:  {final_state.get('token_usage', 0):,}")

    report_path = eng_dir / "report" / "final_report.md"
    if report_path.exists():
        print(f"\n [Report Location]: {report_path}")
        print("-" * 65)
        print(report_path.read_text(encoding="utf-8"))
    else:
        print("\n [!] Report file not found.")

    print("\n" + "=" * 65 + "\n")


def main() -> None:
    args = parse_args()
    asyncio.run(run_assessment(args.target, args.risky))


if __name__ == "__main__":
    main()
