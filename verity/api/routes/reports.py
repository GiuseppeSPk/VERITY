"""Report generation endpoints."""

from datetime import datetime
from io import BytesIO

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from verity.api.database import get_db
from verity.api.models import Campaign, Report
from verity.api.routes.auth import get_current_user
from verity.judges.llm_judge import CampaignEvaluation, JudgeEvaluation, JudgeVerdict
from verity.reporting import ReportGenerator, ReportMetadata

router = APIRouter()


# ============ Pydantic Models ============


class ReportRequest(BaseModel):
    """Report generation request."""

    campaign_id: str
    format: str = "markdown"  # markdown, json, html


class ReportResponse(BaseModel):
    """Report generation response."""

    id: str  # Report DB ID
    campaign_id: str
    format: str
    download_url: str
    generated_at: datetime


# ============ Endpoints ============


@router.post("/generate", response_model=ReportResponse)
async def generate_report(
    request: ReportRequest,
    user_info: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a security assessment report."""
    user_id = user_info["user_id"]

    # Check campaign and eager load attack results
    stmt = (
        select(Campaign)
        .options(selectinload(Campaign.attack_results))
        .where(Campaign.id == request.campaign_id)
    )
    result = await db.execute(stmt)
    campaign = result.scalar_one_or_none()

    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    if campaign.status != "completed":
        raise HTTPException(status_code=409, detail="Campaign not completed")

    # Create evaluation from DB attack results
    evaluations = []
    category_counts = {}

    for r in campaign.attack_results:
        # Categorization
        cat = r.attack_category or "unknown"
        category_counts[cat] = category_counts.get(cat, 0) + 1

        # Determine verdict
        verdict = JudgeVerdict.UNSAFE if r.success else JudgeVerdict.SAFE

        evaluations.append(
            JudgeEvaluation(
                attack_name=r.attack_name,
                verdict=verdict,
                harm_score=r.harm_score if r.harm_score else (10.0 if r.success else 0.0),
                confidence=r.confidence if r.confidence else 0.8,
                reasoning=r.reasoning or "Automated evaluation",
                prompt_used=r.prompt_used,
                target_response=r.response or "",
                attack_category=cat,
            )
        )

    # Calculate global metrics
    total = len(evaluations)
    successful = sum(1 for e in evaluations if e.verdict == JudgeVerdict.UNSAFE)
    asr = successful / total if total > 0 else 0.0
    avg_harm = sum(e.harm_score for e in evaluations) / total if total else 0.0

    evaluation = CampaignEvaluation(
        total_attacks=total,
        successful_attacks=successful,
        failed_attacks=total - successful,
        borderline_attacks=0,
        asr=asr,
        asr_ci_lower=max(0, asr - 0.1),
        asr_ci_upper=min(1, asr + 0.1),
        average_harm_score=avg_harm,
        evaluations=evaluations,
        category_breakdown=category_counts,
    )

    # Create metadata
    metadata = ReportMetadata(
        title=f"Security Assessment: {campaign.name}",
        target_system=campaign.target_provider,
        target_model=campaign.target_model,
        assessment_date=campaign.completed_at or datetime.utcnow(),
    )

    # Generate report content
    generator = ReportGenerator("./reports")
    # Use simple in-memory generation here to save to DB content
    # Ideally ReportGenerator should support returning string directly without file sys

    # Hack: generator needs refactor?
    # Or just use temp file? The generator methods return content if valid?
    # Looking at step 1077 code: generator.generate_markdown returns content. Great.

    if request.format == "markdown":
        content = generator.generate_markdown(evaluation, metadata)
    elif request.format == "json":
        # Access internal method or public? Code showed _generate_json
        content = generator._generate_json(evaluation, metadata)
    elif request.format == "html":
        content = generator._generate_html(evaluation, metadata)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format: {request.format}",
        )

    # Store report in DB
    report = Report(
        campaign_id=campaign.id,
        format=request.format,
        content=content,
        file_size=len(content.encode('utf-8')),
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return ReportResponse(
        id=report.id,
        campaign_id=report.campaign_id,
        format=report.format,
        download_url=f"/api/v1/reports/download/{report.id}",
        generated_at=report.created_at,
    )


@router.get("/download/{report_id}")
async def download_report(
    report_id: str,
    user_info: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Download a generated report."""
    user_id = user_info["user_id"]

    # Fetch report + join campaign to check owner
    stmt = (
        select(Report)
        .join(Campaign)
        .where(Report.id == report_id)
        .options(selectinload(Report.campaign))
    )
    result = await db.execute(stmt)
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.campaign.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    content = report.content
    format_type = report.format

    # Set content type and filename
    if format_type == "markdown":
        media_type = "text/markdown"
        filename = f"VERITY_report_{report.campaign.name}_{report.id[:8]}.md"
    elif format_type == "json":
        media_type = "application/json"
        filename = f"VERITY_report_{report.campaign.name}_{report.id[:8]}.json"
    else:
        media_type = "text/html"
        filename = f"VERITY_report_{report.campaign.name}_{report.id[:8]}.html"

    # Update download count?
    report.download_count += 1
    await db.commit()

    return StreamingResponse(
        BytesIO(content.encode()),
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/list")
async def list_reports(
    user_info: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List user's generated reports."""
    user_id = user_info["user_id"]

    # Find all reports where campaign user_id == user_id
    stmt = (
        select(Report)
        .join(Campaign)
        .where(Campaign.user_id == user_id)
        .order_by(Report.created_at.desc())
    )
    result = await db.execute(stmt)
    reports = result.scalars().all()

    report_list = []
    for r in reports:
        report_list.append({
            "report_id": r.id,
            "campaign_id": r.campaign_id,
            "format": r.format,
            "generated_at": r.created_at,
            "download_url": f"/api/v1/reports/download/{r.id}",
        })

    return {"reports": report_list}
