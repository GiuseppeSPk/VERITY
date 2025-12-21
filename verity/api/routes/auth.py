"""Authentication endpoints.

JWT + API Key dual authentication system.
Using bcrypt for secure password hashing.
Running on SQLAlchemy Async + PostgreSQL (via AsyncPG).
"""

import hashlib
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from verity.api.database import get_db
from verity.api.models import APIKey, User

# Password hashing context - using pbkdf2_sha256 for compatibility
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

router = APIRouter()


# ============ Pydantic Models ============


class UserCreate(BaseModel):
    """User registration model."""

    email: EmailStr
    password: str


class UserLogin(BaseModel):
    """User login model."""

    email: EmailStr
    password: str


class Token(BaseModel):
    """JWT token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 900  # 15 minutes


class TokenRefresh(BaseModel):
    """Refresh token request."""

    refresh_token: str


class APIKeyCreate(BaseModel):
    """API key creation request."""

    name: str
    expires_days: int = 90


class APIKeyResponse(BaseModel):
    """API key response (shown only once)."""

    key: str
    name: str
    created_at: datetime
    expires_at: datetime


class UserResponse(BaseModel):
    """User response model."""

    id: str
    email: str
    tier: str
    created_at: datetime


# ============ Utilities ============


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash password."""
    return pwd_context.hash(password)


def generate_token() -> str:
    """Generate secure random token."""
    return secrets.token_urlsafe(32)


def generate_api_key() -> str:
    """Generate API key with VERITY prefix."""
    return f"VERITY_{secrets.token_urlsafe(32)}"


# ============ Authentication Helpers ============

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

# Simple in-memory token storage (Production: use Redis)
# Dictionary mapping access_token -> {user_id, expires_at}
_active_tokens: dict = {}


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get current user from JWT or API key.

    Returns:
        dict: {"user_id": str, "auth_method": str}
    """

    # 1. API Key Authentication
    if x_api_key:
        key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()

        stmt = select(APIKey).where(
            APIKey.key_hash == key_hash,
            APIKey.is_active == True,
            APIKey.expires_at > datetime.utcnow()
        )
        result = await db.execute(stmt)
        api_key_obj = result.scalar_one_or_none()

        if api_key_obj:
            # Update last used
            api_key_obj.last_used = datetime.utcnow()
            await db.commit()
            return {"user_id": api_key_obj.user_id, "auth_method": "api_key"}

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        )

    # 2. JWT Authentication
    if token:
        token_data = _active_tokens.get(token)
        if token_data:
            if datetime.utcnow() < token_data["expires_at"]:
                return {"user_id": token_data["user_id"], "auth_method": "jwt"}
            else:
                # Expired
                del _active_tokens[token]

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ============ Endpoints ============


@router.post("/register", response_model=UserResponse)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user."""
    # Check existing
    stmt = select(User).where(User.email == user_in.email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Create user
    new_user = User(
        email=user_in.email,
        password_hash=get_password_hash(user_in.password),
        tier="free",
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return UserResponse(
        id=new_user.id,
        email=new_user.email,
        tier=new_user.tier,
        created_at=new_user.created_at,
    )


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """Login and get JWT token."""
    # Find user
    stmt = select(User).where(User.email == form_data.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate token
    access_token = generate_token()
    expires_at = datetime.utcnow() + timedelta(minutes=15)

    # Store in memory (Redis refactor planned)
    _active_tokens[access_token] = {
        "user_id": user.id,
        "expires_at": expires_at,
    }

    return Token(
        access_token=access_token,
        expires_in=900,
    )


@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    key_request: APIKeyCreate,
    user_info: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key."""
    api_key_str = generate_api_key()
    key_hash = hashlib.sha256(api_key_str.encode()).hexdigest()
    expires_at = datetime.utcnow() + timedelta(days=key_request.expires_days)

    new_key = APIKey(
        user_id=user_info["user_id"],
        name=key_request.name,
        key_hash=key_hash,
        expires_at=expires_at,
    )
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)

    return APIKeyResponse(
        key=api_key_str,  # Show only once
        name=new_key.name,
        created_at=new_key.created_at,
        expires_at=new_key.expires_at,
    )


@router.get("/me", response_model=dict)
async def get_current_user_info(user: dict = Depends(get_current_user)):
    """Get current user info."""
    return {
        "user_id": user["user_id"],
        "auth_method": user["auth_method"],
    }


@router.post("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    """Logout (invalidate token)."""
    if token in _active_tokens:
        del _active_tokens[token]
    return {"message": "Logged out successfully"}
