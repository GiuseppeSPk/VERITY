"""Attack execution endpoints.

Execute red teaming attacks against target models.
"""

from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel

from verity.api.routes.auth import get_current_user

"""Attack execution endpoints.

Refactored to use SQLAlchemy Async + PostgreSQL.
"""


from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from verity.api.database import get_db, get_db_context
from verity.api.models import AttackResult, Campaign

router = APIRouter()


# ============ Pydantic Models ============


class AttackRequest(BaseModel):
    """Attack execution request."""

    campaign_id: str
    attack_types: list[str] = ["injection", "jailbreak", "leak"]
    max_per_type: int = 3
    use_judge: bool = True


class AttackResultResponse(BaseModel):
    """Single attack result."""

    attack_name: str
    attack_category: str
    success: bool
    response_preview: str
    harm_score: float | None = None
    verdict: str | None = None


class AttackProgress(BaseModel):
    """Attack execution progress."""

    campaign_id: str
    status: str
    total_attacks: int
    completed_attacks: int
    successful_attacks: int
    progress_pct: float


class AttackSummary(BaseModel):
    """Attack campaign summary."""

    campaign_id: str
    status: str
    total_attacks: int
    successful_attacks: int
    asr: float
    asr_ci: tuple[float, float]
    average_harm_score: float
    results: list[AttackResultResponse]


# ============ Background Task ============


async def run_attacks_background(
    campaign_id: str,
    attack_types: list[str],
    max_per_type: int,
    use_judge: bool,
):
    """Run attacks in background using DB context."""
    from verity.core import create_provider
    from verity.red_team import get_all_agents

    async with get_db_context() as db:
        # Fetch campaign
        stmt = select(Campaign).where(Campaign.id == campaign_id)
        res = await db.execute(stmt)
        campaign = res.scalar_one_or_none()

        if not campaign:
            return

        # Update status to running
        campaign.status = "running"
        campaign.started_at = datetime.utcnow()
        await db.commit()

        try:
            # Create provider
            # Note: Assuming create_provider handles env vars or we fetch api keys here
            provider = create_provider(
                campaign.target_provider,
                model=campaign.target_model,
            )

            # Get agents
            agents = get_all_agents()
            all_results = []

            for agent in agents:
                if agent.category.value not in attack_types:
                    continue

                # Execute attacks
                # Note: agent.execute is async and returns list of AttackResult objects (internal)
                # We need to map them to DB AttackResult models
                results = await agent.execute(
                    provider=provider,
                    max_attacks=max_per_type,
                )

                # Save results to DB immediately (or batch)
                for r in results:
                    db_result = AttackResult(
                        campaign_id=campaign.id,
                        attack_name=r.attack_name,
                        attack_category=r.attack_category.value,
                        prompt_used=r.prompt,
                        response=r.response,
                        success=r.success,
                        verdict="unsafe" if r.success else "safe", # Simple heuristic mapper
                        harm_score=10.0 if r.success else 0.0,
                        latency_ms=r.latency_ms,
                        tokens_used=r.tokens_used
                    )
                    db.add(db_result)
                    all_results.append(r)

                # Commit batch
                await db.commit()

                # Update campaign stats incrementally
                campaign.total_attacks += len(results)
                campaign.successful_attacks += sum(1 for r in results if r.success)
                await db.commit()

            # Finalize campaign
            campaign.status = "completed"
            campaign.completed_at = datetime.utcnow()

            total = campaign.total_attacks
            success = campaign.successful_attacks
            campaign.asr = success / total if total > 0 else 0.0

            await db.commit()

        except Exception:
            await db.rollback() # Rollback current transaction if active
            # Re-fetch or use session to set failed
            # Since we rollbacked, campaign object might be detached or stale?
            # Safe way: fetch again and update
            # But async session persists.
            campaign.status = "failed"
            # Log error? print(f"Attack failed: {e}")
            await db.commit()


# ============ Endpoints ============


@router.post("/execute", status_code=status.HTTP_202_ACCEPTED)
async def execute_attacks(
    request: AttackRequest,
    background_tasks: BackgroundTasks,
    user_info: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Execute attacks on a campaign (async)."""
    user_id = user_info["user_id"]

    stmt = select(Campaign).where(Campaign.id == request.campaign_id)
    result = await db.execute(stmt)
    campaign = result.scalar_one_or_none()

    if not campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    if campaign.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized",
        )

    if campaign.status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Campaign already running",
        )

    # Start background task
    background_tasks.add_task(
        run_attacks_background,
        request.campaign_id,
        request.attack_types,
        request.max_per_type,
        request.use_judge,
    )

    return {
        "message": "Attack execution started",
        "campaign_id": request.campaign_id,
        "status_url": f"/api/v1/attacks/status/{request.campaign_id}",
    }


@router.get("/status/{campaign_id}", response_model=AttackProgress)
async def get_attack_status(
    campaign_id: str,
    user_info: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get attack execution status."""
    user_id = user_info["user_id"]

    stmt = select(Campaign).where(Campaign.id == campaign_id)
    result = await db.execute(stmt)
    campaign = result.scalar_one_or_none()

    if not campaign or campaign.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    return AttackProgress(
        campaign_id=campaign_id,
        status=campaign.status,
        total_attacks=campaign.total_attacks,
        # In real-time this lags slightly behind DB inserts if we rely on campaign.total_attacks column updates
        # But run_attacks_background updates it.
        completed_attacks=campaign.total_attacks,
        successful_attacks=campaign.successful_attacks,
        progress_pct=100.0 if campaign.status in ["completed", "failed"] else 50.0, # Approximate
    )


@router.get("/results/{campaign_id}", response_model=AttackSummary)
async def get_attack_results(
    campaign_id: str,
    user_info: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get attack results for a campaign."""
    user_id = user_info["user_id"]

    # Eager load results
    stmt = (
        select(Campaign)
        .options(selectinload(Campaign.attack_results))
        .where(Campaign.id == campaign_id)
    )
    result = await db.execute(stmt)
    campaign = result.scalar_one_or_none()

    if not campaign or campaign.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found",
        )

    results_resp = [
        AttackResultResponse(
            attack_name=r.attack_name,
            attack_category=r.attack_category,
            success=r.success,
            response_preview=r.response[:200] if r.response else "",
            harm_score=r.harm_score,
            verdict=r.verdict
        )
        for r in campaign.attack_results
    ]

    return AttackSummary(
        campaign_id=campaign_id,
        status=campaign.status,
        total_attacks=campaign.total_attacks,
        successful_attacks=campaign.successful_attacks,
        asr=campaign.asr if campaign.asr else 0.0,
        asr_ci=(0.0, 0.0), # TODO: implement CI logic
        average_harm_score=campaign.average_harm_score if campaign.average_harm_score else 0.0,
        results=results_resp,
    )

