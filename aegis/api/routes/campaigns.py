"""Campaign management endpoints."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from aegis.api.routes.auth import get_current_user

router = APIRouter()


"""Campaign management endpoints.

Refactored to use SQLAlchemy Async + PostgreSQL.
"""


from fastapi import APIRouter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.api.database import get_db
from aegis.api.models import Campaign

router = APIRouter()


# ============ Pydantic Models ============


class CampaignCreate(BaseModel):
    """Campaign creation request."""

    name: str
    target_provider: str = "ollama"
    target_model: str = "llama3"
    attack_types: list[str] = ["injection", "jailbreak", "leak"]
    max_attacks_per_type: int = 5


class CampaignResponse(BaseModel):
    """Campaign response model."""

    id: str
    name: str
    target_provider: str
    target_model: str
    status: str
    attack_types: list[str]
    created_at: datetime
    completed_at: datetime | None = None
    asr: float | None = None
    total_attacks: int = 0

    # Helper for converting DB list string to Pydantic list
    @staticmethod
    def from_orm(c: Campaign) -> "CampaignResponse":
        return CampaignResponse(
            id=c.id,
            name=c.name,
            target_provider=c.target_provider,
            target_model=c.target_model,
            status=c.status,
            attack_types=c.attack_types.split(","),
            created_at=c.created_at,
            completed_at=c.completed_at,
            asr=c.asr,
            total_attacks=c.total_attacks,
        )


class CampaignList(BaseModel):
    """Paginated campaign list."""

    campaigns: list[CampaignResponse]
    total: int
    page: int
    per_page: int


# ============ Endpoints ============


@router.post("/", response_model=CampaignResponse, status_code=status.HTTP_201_CREATED)
async def create_campaign(
    campaign_in: CampaignCreate,
    user_info: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new security assessment campaign."""
    user_id = user_info["user_id"]

    # Check limit check (pseudo code based on tier logic)
    # real tier logic would go here

    new_campaign = Campaign(
        user_id=user_id,
        name=campaign_in.name,
        target_provider=campaign_in.target_provider,
        target_model=campaign_in.target_model,
        attack_types=",".join(campaign_in.attack_types),
        max_attacks_per_type=campaign_in.max_attacks_per_type,
        status="pending",
    )

    db.add(new_campaign)
    await db.commit()
    await db.refresh(new_campaign)

    return CampaignResponse.from_orm(new_campaign)


@router.get("/", response_model=CampaignList)
async def list_campaigns(
    user_info: dict = Depends(get_current_user),
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List user's campaigns."""
    user_id = user_info["user_id"]

    # Calculate offset
    offset = (page - 1) * per_page

    # Query
    stmt = (
        select(Campaign)
        .where(Campaign.user_id == user_id)
        .order_by(Campaign.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(stmt)
    campaigns = result.scalars().all()

    # Count total (separate query for simplicity)
    # In production use count(*)
    count_stmt = select(Campaign).where(Campaign.user_id == user_id)
    count_res = await db.execute(count_stmt)
    total = len(count_res.scalars().all())

    return CampaignList(
        campaigns=[CampaignResponse.from_orm(c) for c in campaigns],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(
    campaign_id: str,
    user_info: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get campaign details."""
    user_id = user_info["user_id"]

    stmt = select(Campaign).where(Campaign.id == campaign_id)
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
            detail="Not authorized to access this campaign",
        )

    return CampaignResponse.from_orm(campaign)


@router.delete("/{campaign_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_campaign(
    campaign_id: str,
    user_info: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a campaign."""
    user_id = user_info["user_id"]

    stmt = select(Campaign).where(Campaign.id == campaign_id)
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
            detail="Not authorized to delete this campaign",
        )

    await db.delete(campaign)
    await db.commit()

