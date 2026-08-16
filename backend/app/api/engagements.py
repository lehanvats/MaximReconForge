import asyncio
import uuid
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.config import settings
from app.db.session import get_db
from app.db.models import Engagement, User
from app.core.scope_validator import validate_target_domain, ScopeValidationError
from app.auth.security import get_current_user
from app.queue.arq_settings import enqueue_recon_job
from app.context_store.store import ContextStore
from app.live.runner import run_engagement_inline

router = APIRouter(prefix="/engagements", tags=["engagements"])

# Keep strong references to inline background tasks so they aren't garbage
# collected mid-run (asyncio only holds a weak reference to the task).
_inline_tasks: set[asyncio.Task] = set()


class EngagementCreate(BaseModel):
    target_domain: str


class EngagementOut(BaseModel):
    id: uuid.UUID
    target_domain: str
    status: str

    class Config:
        from_attributes = True


class ReportOut(BaseModel):
    engagement_id: uuid.UUID
    target_domain: str
    status: str
    report_markdown: str


@router.post("", response_model=EngagementOut, status_code=201)
async def create_engagement(
    payload: EngagementCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        resolved_ips = validate_target_domain(payload.target_domain)
    except ScopeValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    engagement = Engagement(
        target_domain=payload.target_domain.strip().lower(),
        status="pending",
        scope_snapshot={"resolved_ips": resolved_ips},
        created_by=current_user.id,
    )
    db.add(engagement)
    await db.commit()
    await db.refresh(engagement)

    if settings.run_scans_inline:
        # Localhost mode: run the graph inside this process and stream progress
        # over the WebSocket, instead of dispatching to the Redis/arq worker.
        task = asyncio.create_task(
            run_engagement_inline(
                engagement_id=str(engagement.id),
                target_domain=engagement.target_domain,
                user_id=str(current_user.id),
            )
        )
        _inline_tasks.add(task)
        task.add_done_callback(_inline_tasks.discard)
    else:
        # Docker worker mode: the graph still runs inline (it needs the LLM
        # for vuln_analysis/exploitation/reporting), but recon_node dispatches
        # the real tool pipeline to the Docker worker via ARQ/Redis.
        task = asyncio.create_task(
            run_engagement_inline(
                engagement_id=str(engagement.id),
                target_domain=engagement.target_domain,
                user_id=str(current_user.id),
            )
        )
        _inline_tasks.add(task)
        task.add_done_callback(_inline_tasks.discard)

    return engagement


@router.get("/{engagement_id}/report", response_model=ReportOut)
async def get_report(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Engagement).where(
        Engagement.id == engagement_id,
        Engagement.created_by == current_user.id,
    )
    res = await db.execute(stmt)
    engagement = res.scalar_one_or_none()

    if not engagement:
        # 404 (not 403) so we don't leak the existence of other users' engagements.
        raise HTTPException(status_code=404, detail="Engagement not found")

    store = ContextStore()
    report_file = store.get_engagement_dir(str(engagement_id)) / "report" / "final_report.md"

    if not report_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Report not generated yet. Engagement status is currently: " + engagement.status,
        )

    report_content = report_file.read_text(encoding="utf-8")
    return ReportOut(
        engagement_id=engagement.id,
        target_domain=engagement.target_domain,
        status=engagement.status,
        report_markdown=report_content,
    )


@router.get("/{engagement_id}/report/download", response_class=PlainTextResponse)
async def download_report(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return the raw markdown report as a file download (attachment)."""
    engagement = await _get_owned_engagement(db, engagement_id, current_user)

    store = ContextStore()
    report_file = store.get_engagement_dir(str(engagement_id)) / "report" / "final_report.md"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Report not generated yet.")

    filename = f"maximrecon_{engagement.target_domain.replace('.', '_')}_report.md"
    return PlainTextResponse(
        report_file.read_text(encoding="utf-8"),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{engagement_id}/findings")
async def get_findings(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return the structured whiteboard findings for the results dashboard."""
    engagement = await _get_owned_engagement(db, engagement_id, current_user)
    store = ContextStore()
    findings = store.read_whiteboard_findings(str(engagement_id))
    return {
        "engagement_id": str(engagement.id),
        "target_domain": engagement.target_domain,
        "status": engagement.status,
        "findings": findings,
    }


async def _get_owned_engagement(
    db: AsyncSession, engagement_id: uuid.UUID, current_user: User
) -> Engagement:
    """Fetch an engagement owned by the current user, or 404."""
    stmt = select(Engagement).where(
        Engagement.id == engagement_id,
        Engagement.created_by == current_user.id,
    )
    res = await db.execute(stmt)
    engagement = res.scalar_one_or_none()
    if not engagement:
        # 404 (not 403) so we don't leak the existence of other users' engagements.
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement


@router.post("/{engagement_id}/abort", response_model=EngagementOut)
async def abort_engagement(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Engagement).where(
        Engagement.id == engagement_id,
        Engagement.created_by == current_user.id,
    )
    res = await db.execute(stmt)
    engagement = res.scalar_one_or_none()

    if not engagement:
        # 404 (not 403) so we don't leak the existence of other users' engagements.
        raise HTTPException(status_code=404, detail="Engagement not found")

    engagement.status = "aborted"
    await db.commit()
    await db.refresh(engagement)

    return engagement
