from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, Text, Float, Boolean, DateTime, ForeignKey, select, delete, update, func, JSON
from sqlalchemy.dialects.mysql import LONGTEXT
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import json
import httpx
from urllib.parse import urlencode

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

ROOT_DIR = Path(__file__).parent
if os.path.exists(ROOT_DIR / ".env"):
    load_dotenv(ROOT_DIR / ".env")

# Auth0 Config
AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN', 'probestack-usa-dev.us.auth0.com')
AUTH0_CLIENT_ID = os.environ.get('AUTH0_CLIENT_ID', '')
AUTH0_CLIENT_SECRET = os.environ.get('AUTH0_CLIENT_SECRET', '')
AUTH0_CALLBACK_URI = os.environ.get('AUTH0_CALLBACK_URI', 'https://probestack.io/callback')
from urllib.parse import quote_plus

DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")
INSTANCE_CONNECTION_NAME = os.environ.get("INSTANCE_CONNECTION_NAME")

if not all([DB_USER, DB_PASSWORD, DB_NAME]):
    raise RuntimeError("Database environment variables not set")

DB_PASSWORD = quote_plus(DB_PASSWORD)

if INSTANCE_CONNECTION_NAME:
    DATABASE_URL = (
        f"mysql+aiomysql://{DB_USER}:{DB_PASSWORD}@/{DB_NAME}"
        f"?unix_socket=/cloudsql/{INSTANCE_CONNECTION_NAME}"
    )
else:
    DATABASE_URL = (
        f"mysql+aiomysql://{DB_USER}:{DB_PASSWORD}@127.0.0.1:3306/{DB_NAME}"
    )

engine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    echo=False,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    expire_on_commit=False,
)

# JWT Config
JWT_SECRET = os.environ.get('JWT_SECRET', 'admin-dashboard-secret-key-2024')
JWT_ALGORITHM = "HS256"

# Create the main app
app = FastAPI(title="ProbeStack Admin Dashboard API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ==================== DATABASE MODELS ====================

class Base(DeclarativeBase):
    pass

class AdminModel(Base):
    __tablename__ = "admins"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="org_admin")  # super_admin, org_admin
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)  # NULL for super_admin
    organization_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)  # Who created this admin

class OrganizationModel(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    requested_plan: Mapped[str] = mapped_column(String(100), nullable=False)
    requested_tools: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    contact_person: Mapped[str] = mapped_column(String(255), nullable=False)
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    external_org_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, unique=True) 
    supported_domains: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    auth0_org_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

class SubscriptionModel(Base):
    __tablename__ = "subscriptions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_name: Mapped[str] = mapped_column(String(255), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(100), nullable=False)
    plan_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tools: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    status: Mapped[str] = mapped_column(String(50), default="active")
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    billing_cycle: Mapped[str] = mapped_column(String(50), default="monthly")
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class PlanModel(Base):
    __tablename__ = "plans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tool: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    features: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    price_monthly: Mapped[float] = mapped_column(Float, nullable=False)
    price_yearly: Mapped[float] = mapped_column(Float, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class UserModel(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[str] = mapped_column(String(36), nullable=False)
    role_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

class RoleModel(Base):
    __tablename__ = "roles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    permissions: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class BillingModel(Base):
    __tablename__ = "billing"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_name: Mapped[str] = mapped_column(String(255), nullable=False)
    subscription_id: Mapped[str] = mapped_column(String(36), nullable=False)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    invoice_number: Mapped[str] = mapped_column(String(100), nullable=False)
    billing_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    due_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    paid_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    payment_method: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class NotificationModel(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    link: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

class UserRequestModel(Base):
    """Model for user addition requests from external applications"""
    __tablename__ = "user_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_name: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_role: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, approved, rejected
    job_title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    approved_role_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

class PlanUpgradeRequestModel(Base):
    """Model for plan upgrade requests from organization admins"""
    __tablename__ = "plan_upgrade_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_name: Mapped[str] = mapped_column(String(255), nullable=False)
    current_plan_id: Mapped[str] = mapped_column(String(100), nullable=False)
    current_plan_name: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_plan_id: Mapped[str] = mapped_column(String(100), nullable=False)
    requested_plan_name: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_tools: Mapped[str] = mapped_column(Text, nullable=False) 
    status: Mapped[str] = mapped_column(String(50), default="pending")
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    requested_by: Mapped[str] = mapped_column(String(36), nullable=False)

class Auth0LoginRecordModel(Base):
    """Model for storing Auth0 login records"""
    __tablename__ = "auth0_login_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_name: Mapped[str] = mapped_column(String(255), nullable=False)
    external_org_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    auth0_org_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  
    auth0_user_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True) 
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    picture: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    access_token: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    id_token: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    token_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    expires_in: Mapped[Optional[int]] = mapped_column(nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    login_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

# ==================== PYDANTIC SCHEMAS ====================

class AdminLogin(BaseModel):
    email: str
    password: str

class AdminRegister(BaseModel):
    email: str
    password: str
    name: str

class AdminCreate(BaseModel):
    """Schema for super admin to create new admins"""
    email: str
    password: str
    name: str
    role: str  # super_admin, org_admin
    organization_id: Optional[str] = None  # Required for org_admin

class PlanUpgradeCreate(BaseModel):
    """Schema for org admin to request plan upgrade"""
    requested_plan_id: str
    requested_tools: List[str]
    reason: Optional[str] = None

class OrganizationCreate(BaseModel):
    name: str
    email: str
    domain: Optional[str] = None
    requested_plan: str
    requested_tools: List[str]
    contact_person: str
    phone: Optional[str] = None
    address: Optional[str] = None

class OrganizationRequest(BaseModel):
    """Schema for external API requests to register an organization"""
    name: str
    email: str
    domain: Optional[str] = None
    plan_id: str  # Plan ID like 'plan_api_pro', 'plan_ai_starter', etc.
    tools: List[str]  # List of tools: 'api_platform', 'ai_agentic', 'migration_tool'
    contact_person: str
    contact_phone: Optional[str] = None
    company_address: Optional[str] = None
    additional_notes: Optional[str] = None

class OrganizationUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    domain: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    external_org_id: Optional[str] = None
    supported_domains: Optional[List[str]] = None
    auth0_org_id: Optional[str] = None  # Auth0 organization ID

class IdentifyOrgRequest(BaseModel):
    """Request to identify organization from email"""
    email: str

class Auth0InitRequest(BaseModel):
    """Request to initiate Auth0 authentication"""
    email: str
    state: Optional[str] = None  # Optional state parameter for CSRF protection
    
class Auth0CallbackRequest(BaseModel):
    """Request to exchange Auth0 code for tokens"""
    code: str
    email: Optional[str] = None  # Original email for logging purposes

class PasswordResetRequest(BaseModel):
    """Request to reset password"""
    email: str

class PasswordChangeRequest(BaseModel):
    """Request to change password"""
    current_password: Optional[str] = None  # Not required for admin reset
    new_password: str

class AdminPasswordResetRequest(BaseModel):
    """Request for admin to reset user password"""
    admin_id: str
    new_password: str

class PlanCreate(BaseModel):
    name: str
    tool: str
    description: str
    features: List[str]
    price_monthly: float
    price_yearly: float

class UserCreate(BaseModel):
    email: str
    name: str
    organization_id: str
    role_id: str

class RoleCreate(BaseModel):
    name: str
    organization_id: str
    permissions: List[str]
    description: Optional[str] = None

class UserRequestCreate(BaseModel):
    """Schema for external API requests to add a user to an organization"""
    email: str
    name: str
    organization_id: str
    requested_role: str  # Role name like 'Admin', 'Developer', 'Viewer'
    job_title: Optional[str] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    notes: Optional[str] = None

# ==================== HELPERS ====================

def model_to_dict(model, json_fields=None):
    """Convert SQLAlchemy model to dict, parsing JSON fields"""
    json_fields = json_fields or []
    result = {}
    for column in model.__table__.columns:
        value = getattr(model, column.name)
        if column.name in json_fields and isinstance(value, str):
            try:
                value = json.loads(value)
            except:
                pass
        if isinstance(value, datetime):
            value = value.isoformat()
        result[column.name] = value
    return result

def create_token(admin_id: str, email: str, role: str, organization_id: Optional[str] = None) -> str:
    payload = {
        "sub": admin_id,
        "email": email,
        "role": role,
        "organization_id": organization_id,
        "exp": datetime.now(timezone.utc).timestamp() + 86400
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_super_admin(payload: dict = Depends(verify_token)):
    """Dependency to require super_admin role"""
    if payload.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Super admin access required")
    return payload

def require_any_admin(payload: dict = Depends(verify_token)):
    """Dependency to require any admin role"""
    if payload.get("role") not in ["super_admin", "org_admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    return payload

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/login")
async def login_admin(data: AdminLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AdminModel).where(AdminModel.email == data.email))
    admin = result.scalar_one_or_none()
    if not admin or not bcrypt.checkpw(data.password.encode(), admin.password_hash.encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not admin.is_active:
        raise HTTPException(status_code=401, detail="Account is disabled")
    
    token = create_token(admin.id, admin.email, admin.role, admin.organization_id)
    return {
        "token": token,
        "admin": {
            "id": admin.id,
            "email": admin.email,
            "name": admin.name,
            "role": admin.role,
            "organization_id": admin.organization_id,
            "organization_name": admin.organization_name
        }
    }

@api_router.get("/auth/me")
async def get_current_admin(payload: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AdminModel).where(AdminModel.id == payload["sub"]))
    admin = result.scalar_one_or_none()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    return {
        "id": admin.id,
        "email": admin.email,
        "name": admin.name,
        "role": admin.role,
        "organization_id": admin.organization_id,
        "organization_name": admin.organization_name,
        "is_active": admin.is_active
    }

# ==================== PASSWORD MANAGEMENT ====================

@api_router.post("/auth/forgot-password", tags=["Authentication"])
async def forgot_password(data: PasswordResetRequest, db: AsyncSession = Depends(get_db)):
    """
    Request password reset. In a production system, this would send an email.
    For now, it generates a reset token that can be used to reset the password.
    """
    result = await db.execute(select(AdminModel).where(AdminModel.email == data.email))
    admin = result.scalar_one_or_none()

    if not admin:
        # Don't reveal if email exists or not for security
        return {"message": "If the email exists, a password reset link will be sent."}

    # Generate a reset token (valid for 1 hour)
    reset_token = jwt.encode(
        {
            "sub": admin.id,
            "email": admin.email,
            "type": "password_reset",
            "exp": datetime.now(timezone.utc).timestamp() + 3600  # 1 hour
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )

    # In production, send email with reset link
    # For now, return the token (for testing purposes)
    return {
        "message": "If the email exists, a password reset link will be sent.",
        "reset_token": reset_token,  # Remove this in production
        "note": "In production, this token would be sent via email"
    }

@api_router.post("/auth/reset-password", tags=["Authentication"])
async def reset_password_with_token(reset_token: str, new_password: str, db: AsyncSession = Depends(get_db)):
    """
    Reset password using a reset token (from forgot password flow)
    """
    try:
        payload = jwt.decode(reset_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "password_reset":
            raise HTTPException(status_code=400, detail="Invalid reset token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Reset token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid reset token")

    result = await db.execute(select(AdminModel).where(AdminModel.id == payload["sub"]))
    admin = result.scalar_one_or_none()

    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")

    # Update password
    admin.password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    await db.commit()

    return {"message": "Password has been reset successfully"}

@api_router.post("/auth/change-password", tags=["Authentication"])
async def change_password(data: PasswordChangeRequest, payload: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    """
    Change password for the currently logged in admin (requires current password)
    """
    result = await db.execute(select(AdminModel).where(AdminModel.id == payload["sub"]))
    admin = result.scalar_one_or_none()

    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")

    # Verify current password
    if not data.current_password:
        raise HTTPException(status_code=400, detail="Current password is required")

    if not bcrypt.checkpw(data.current_password.encode(), admin.password_hash.encode()):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Update password
    admin.password_hash = bcrypt.hashpw(data.new_password.encode(), bcrypt.gensalt()).decode()
    await db.commit()

    return {"message": "Password changed successfully"}

@api_router.post("/admins/{admin_id}/reset-password", tags=["Admin Management"])
async def admin_reset_password(admin_id: str, data: PasswordChangeRequest, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """
    Super Admin can reset password for any admin user
    """
    result = await db.execute(select(AdminModel).where(AdminModel.id == admin_id))
    admin = result.scalar_one_or_none()

    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")

    # Update password
    admin.password_hash = bcrypt.hashpw(data.new_password.encode(), bcrypt.gensalt()).decode()
    await db.commit()

    return {"message": f"Password reset successfully for {admin.email}"}

# ==================== ADMIN MANAGEMENT (Super Admin Only) ====================

@api_router.get("/admins", tags=["Admin Management"])
async def get_all_admins(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Get all admin users (super admin only)"""
    result = await db.execute(select(AdminModel).order_by(AdminModel.created_at.desc()))
    admins = result.scalars().all()
    return [
        {
            "id": a.id, "email": a.email, "name": a.name, "role": a.role,
            "organization_id": a.organization_id, "organization_name": a.organization_name,
            "is_active": a.is_active, "created_at": a.created_at.isoformat() if a.created_at else None
        }
        for a in admins
    ]

@api_router.post("/admins", tags=["Admin Management"])
async def create_admin(data: AdminCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Create a new admin user (super admin only)"""
    # Validate role
    if data.role not in ["super_admin", "org_admin"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'super_admin' or 'org_admin'")
    
    # Check if email already exists
    existing = await db.execute(select(AdminModel).where(AdminModel.email == data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # For org_admin, organization_id is required
    org_name = None
    if data.role == "org_admin":
        if not data.organization_id:
            raise HTTPException(status_code=400, detail="organization_id is required for org_admin")
        org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == data.organization_id))
        org = org_result.scalar_one_or_none()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        if org.status != "approved":
            raise HTTPException(status_code=400, detail="Organization is not approved")
        org_name = org.name
    
    password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    admin = AdminModel(
        email=data.email,
        password_hash=password_hash,
        name=data.name,
        role=data.role,
        organization_id=data.organization_id if data.role == "org_admin" else None,
        organization_name=org_name,
        created_by=payload["sub"]
    )
    db.add(admin)
    await db.commit()
    
    return {
        "id": admin.id,
        "email": admin.email,
        "name": admin.name,
        "role": admin.role,
        "organization_id": admin.organization_id,
        "organization_name": admin.organization_name,
        "message": "Admin created successfully"
    }

@api_router.put("/admins/{admin_id}/toggle-status", tags=["Admin Management"])
async def toggle_admin_status(admin_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Enable/disable an admin (super admin only)"""
    if admin_id == payload["sub"]:
        raise HTTPException(status_code=400, detail="Cannot disable your own account")
    
    result = await db.execute(select(AdminModel).where(AdminModel.id == admin_id))
    admin = result.scalar_one_or_none()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    
    admin.is_active = not admin.is_active
    await db.commit()
    
    return {"message": f"Admin {'enabled' if admin.is_active else 'disabled'}", "is_active": admin.is_active}

@api_router.delete("/admins/{admin_id}", tags=["Admin Management"])
async def delete_admin(admin_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Delete an admin (super admin only)"""
    if admin_id == payload["sub"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    result = await db.execute(delete(AdminModel).where(AdminModel.id == admin_id))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Admin not found")
    await db.commit()
    return {"message": "Admin deleted"}

@api_router.post("/auth/register")
async def register_admin(data: AdminRegister, db: AsyncSession = Depends(get_db)):
    """Initial setup only - creates first super admin. Disabled after first admin exists."""
    # Check if any admin exists
    existing_admins = await db.execute(select(func.count()).select_from(AdminModel))
    count = existing_admins.scalar()
    if count > 0:
        raise HTTPException(status_code=403, detail="Registration disabled. Contact super admin to create accounts.")
    
    existing = await db.execute(select(AdminModel).where(AdminModel.email == data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    admin = AdminModel(
        email=data.email,
        password_hash=password_hash,
        name=data.name,
        role="super_admin"  # First user is always super_admin
    )
    
    db.add(admin)
    await db.commit()
    token = create_token(admin.id, admin.email, admin.role, admin.organization_id)
    
    return {
        "token": token,
        "admin": {
            "id": admin.id,
            "email": admin.email,
            "name": admin.name,
            "role": admin.role
        },
        "message": "Super admin account created. You can now create other admins."
    }

@api_router.get("/auth/check-setup")
async def check_setup(db: AsyncSession = Depends(get_db)):
    """Check if initial setup is needed (no admins exist)"""
    result = await db.execute(select(func.count()).select_from(AdminModel))
    count = result.scalar()
    return {"setup_required": count == 0}

# ==================== ORG ADMIN DASHBOARD (For Organization Admins) ====================

@api_router.get("/my-organization", tags=["Org Admin"])
async def get_my_organization(payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get current admin's organization details (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization. Use /organizations endpoint.")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    return model_to_dict(org, ["requested_tools", "supported_domains"])

@api_router.get("/my-organization/subscription", tags=["Org Admin"])
async def get_my_subscription(payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get current organization's subscription (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == org_id)
        .order_by(SubscriptionModel.created_at.desc())
    )
    subs = result.scalars().all()
    return [model_to_dict(s, ["tools"]) for s in subs]

@api_router.get("/my-organization/users", tags=["Org Admin"])
async def get_my_organization_users(payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get users in current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    result = await db.execute(
        select(UserModel)
        .where(UserModel.organization_id == org_id)
        .order_by(UserModel.created_at.desc())
    )
    return [model_to_dict(u) for u in result.scalars().all()]

@api_router.get("/my-organization/roles", tags=["Org Admin"])
async def get_my_organization_roles(payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get roles in current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    result = await db.execute(
        select(RoleModel)
        .where(RoleModel.organization_id == org_id)
        .order_by(RoleModel.created_at.desc())
    )
    return [model_to_dict(r, ["permissions"]) for r in result.scalars().all()]

@api_router.get("/my-organization/billing", tags=["Org Admin"])
async def get_my_organization_billing(payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get billing records for current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    result = await db.execute(
        select(BillingModel)
        .where(BillingModel.organization_id == org_id)
        .order_by(BillingModel.created_at.desc())
    )
    return [model_to_dict(b) for b in result.scalars().all()]

@api_router.get("/my-organization/user-requests", tags=["Org Admin"])
async def get_my_organization_user_requests(payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get user requests for current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    result = await db.execute(
        select(UserRequestModel)
        .where(UserRequestModel.organization_id == org_id)
        .order_by(UserRequestModel.created_at.desc())
    )
    return [model_to_dict(r) for r in result.scalars().all()]

@api_router.post("/my-organization/users/{user_id}/remove", tags=["Org Admin"])
async def remove_user_from_my_organization(user_id: str, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Remove a user from current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins should use /users/{id} endpoint")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    # Check user belongs to this organization
    result = await db.execute(
        select(UserModel).where(UserModel.id == user_id, UserModel.organization_id == org_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found in your organization")
    
    await db.execute(delete(UserModel).where(UserModel.id == user_id))
    await db.commit()
    
    return {"message": f"User {user.name} removed from organization"}

@api_router.post("/my-organization/user-requests/{request_id}/approve", tags=["Org Admin"])
async def approve_user_request_org_admin(request_id: str, role_id: str, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Approve a user request for current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins should use /user-requests/{id}/approve")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    # Check request belongs to this organization
    result = await db.execute(
        select(UserRequestModel).where(UserRequestModel.id == request_id, UserRequestModel.organization_id == org_id)
    )
    req = result.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="User request not found in your organization")
    if req.status != "pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    
    # Validate role exists in this organization
    role_result = await db.execute(
        select(RoleModel).where(RoleModel.id == role_id, RoleModel.organization_id == org_id)
    )
    role = role_result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found in your organization")
    
    now = datetime.now(timezone.utc)
    
    # Update request
    req.status = "approved"
    req.approved_at = now
    req.updated_at = now
    req.approved_role_id = role_id
    
    # Create user
    user = UserModel(
        email=req.email,
        name=req.name,
        organization_id=org_id,
        organization_name=req.organization_name,
        role_id=role_id,
        role_name=role.name
    )
    db.add(user)
    await db.commit()
    
    return {
        "message": "User request approved",
        "user_id": user.id,
        "user": {"name": user.name, "email": user.email, "role": role.name}
    }

@api_router.post("/my-organization/user-requests/{request_id}/reject", tags=["Org Admin"])
async def reject_user_request_org_admin(request_id: str, reason: str = "", payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Reject a user request for current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins should use /user-requests/{id}/reject")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    # Check request belongs to this organization
    result = await db.execute(
        select(UserRequestModel).where(UserRequestModel.id == request_id, UserRequestModel.organization_id == org_id)
    )
    req = result.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="User request not found in your organization")
    if req.status != "pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    
    now = datetime.now(timezone.utc)
    req.status = "rejected"
    req.rejected_at = now
    req.updated_at = now
    req.rejection_reason = reason
    
    await db.commit()
    
    return {"message": "User request rejected"}

# ==================== ORG ADMIN TEAM MANAGEMENT ====================

@api_router.get("/my-organization/team", tags=["Org Admin"])
async def get_my_team(payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get all admin accounts for current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    result = await db.execute(
        select(AdminModel)
        .where(AdminModel.organization_id == org_id)
        .order_by(AdminModel.created_at.desc())
    )
    return [model_to_dict(a) for a in result.scalars().all()]

class TeamMemberCreate(BaseModel):
    email: str
    password: str
    name: str

@api_router.post("/my-organization/team", tags=["Org Admin"])
async def create_team_member(data: TeamMemberCreate, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Create a new admin account for current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization")
    
    org_id = payload.get("organization_id")
    org_name = payload.get("organization_name")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    # Check if email already exists
    existing = await db.execute(select(AdminModel).where(AdminModel.email == data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new org admin for this organization
    hashed_password = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    admin = AdminModel(
        email=data.email,
        password_hash=hashed_password,
        name=data.name,
        role="org_admin",
        organization_id=org_id,
        organization_name=org_name,
        created_by=payload.get("sub")
    )
    db.add(admin)
    await db.commit()
    
    return {"message": "Team member created successfully", "id": admin.id}

@api_router.put("/my-organization/team/{admin_id}/toggle-status", tags=["Org Admin"])
async def toggle_team_member_status(admin_id: str, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Toggle team member active status (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization")
    
    org_id = payload.get("organization_id")
    current_admin_id = payload.get("sub")
    
    # Cannot toggle your own status
    if admin_id == current_admin_id:
        raise HTTPException(status_code=400, detail="Cannot change your own status")
    
    # Find admin in same organization
    result = await db.execute(
        select(AdminModel).where(
            AdminModel.id == admin_id,
            AdminModel.organization_id == org_id
        )
    )
    admin = result.scalar_one_or_none()
    if not admin:
        raise HTTPException(status_code=404, detail="Team member not found")
    
    admin.is_active = not admin.is_active
    await db.commit()
    
    return {"message": f"Team member {'activated' if admin.is_active else 'deactivated'}"}

@api_router.delete("/my-organization/team/{admin_id}", tags=["Org Admin"])
async def delete_team_member(admin_id: str, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Delete a team member account (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization")
    
    org_id = payload.get("organization_id")
    current_admin_id = payload.get("sub")
    
    # Cannot delete yourself
    if admin_id == current_admin_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    # Find admin in same organization
    result = await db.execute(
        select(AdminModel).where(
            AdminModel.id == admin_id,
            AdminModel.organization_id == org_id
        )
    )
    admin = result.scalar_one_or_none()
    if not admin:
        raise HTTPException(status_code=404, detail="Team member not found")
    
    await db.execute(delete(AdminModel).where(AdminModel.id == admin_id))
    await db.commit()
    
    return {"message": "Team member removed"}

@api_router.get("/my-organization/upgrade-requests", tags=["Org Admin"])
async def get_my_upgrade_requests(payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get upgrade requests for current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    result = await db.execute(
        select(PlanUpgradeRequestModel)
        .where(PlanUpgradeRequestModel.organization_id == org_id)
        .order_by(PlanUpgradeRequestModel.created_at.desc())
    )
    return [model_to_dict(r, ["requested_tools"]) for r in result.scalars().all()]

@api_router.get("/my-organization/dashboard", tags=["Org Admin"])
async def get_my_organization_dashboard(payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get dashboard stats for current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization. Use /dashboard/stats")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    # Get organization
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = org_result.scalar_one_or_none()
    
    # Get active subscription
    sub_result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == org_id)
        .where(SubscriptionModel.status == "active")
    )
    subscription = sub_result.scalar_one_or_none()
    
    # Counts
    user_count = await db.scalar(select(func.count()).select_from(UserModel).where(UserModel.organization_id == org_id))
    role_count = await db.scalar(select(func.count()).select_from(RoleModel).where(RoleModel.organization_id == org_id))
    pending_user_requests = await db.scalar(
        select(func.count()).select_from(UserRequestModel)
        .where(UserRequestModel.organization_id == org_id)
        .where(UserRequestModel.status == "pending")
    )
    
    # Total billed
    total_billed = await db.scalar(
        select(func.sum(BillingModel.amount))
        .where(BillingModel.organization_id == org_id)
        .where(BillingModel.status == "paid")
    ) or 0
    
    return {
        "organization": model_to_dict(org, ["requested_tools", "supported_domains"]) if org else None,
        "subscription": model_to_dict(subscription, ["tools"]) if subscription else None,
        "total_users": user_count or 0,
        "total_roles": role_count or 0,
        "pending_user_requests": pending_user_requests or 0,
        "total_billed": total_billed
    }

# ==================== PLAN UPGRADE REQUESTS (Org Admin) ====================

@api_router.post("/my-organization/request-upgrade", tags=["Org Admin"])
async def request_plan_upgrade(data: PlanUpgradeCreate, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Request a plan upgrade for current organization (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins should directly update subscriptions")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    # Get organization
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Get current subscription
    sub_result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == org_id)
        .where(SubscriptionModel.status == "active")
    )
    current_sub = sub_result.scalar_one_or_none()
    if not current_sub:
        raise HTTPException(status_code=400, detail="No active subscription found")
    
    # Validate requested plan exists
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == data.requested_plan_id))
    new_plan = plan_result.scalar_one_or_none()
    if not new_plan:
        raise HTTPException(status_code=404, detail="Requested plan not found")
    
    # Validate tools
    valid_tools = ['api_platform', 'ai_agentic', 'migration_tool']
    for tool in data.requested_tools:
        if tool not in valid_tools:
            raise HTTPException(status_code=400, detail=f"Invalid tool: {tool}")
    
    # Check for existing pending request
    existing = await db.execute(
        select(PlanUpgradeRequestModel)
        .where(PlanUpgradeRequestModel.organization_id == org_id)
        .where(PlanUpgradeRequestModel.status == "pending")
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="You already have a pending upgrade request")
    
    # Create upgrade request
    upgrade_request = PlanUpgradeRequestModel(
        organization_id=org_id,
        organization_name=org.name,
        current_plan_id=current_sub.plan_id,
        current_plan_name=current_sub.plan_name,
        requested_plan_id=data.requested_plan_id,
        requested_plan_name=new_plan.name,
        requested_tools=json.dumps(data.requested_tools),
        reason=data.reason,
        requested_by=payload["sub"]
    )
    db.add(upgrade_request)
    
    # Create notification
    notif = NotificationModel(
        title="Plan Upgrade Request",
        message=f"{org.name} requested to upgrade from {current_sub.plan_name} to {new_plan.name}",
        type="info",
        link="/upgrade-requests"
    )
    db.add(notif)
    
    await db.commit()
    
    return {
        "request_id": upgrade_request.id,
        "status": "pending",
        "message": "Upgrade request submitted successfully",
        "upgrade": {
            "from_plan": current_sub.plan_name,
            "to_plan": new_plan.name,
            "requested_tools": data.requested_tools
        }
    }

# ==================== PLAN UPGRADE MANAGEMENT (Super Admin) ====================

@api_router.get("/upgrade-requests", tags=["Upgrade Requests"])
async def get_upgrade_requests(status: Optional[str] = None, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Get all plan upgrade requests (super admin only)"""
    query = select(PlanUpgradeRequestModel)
    if status:
        query = query.where(PlanUpgradeRequestModel.status == status)
    result = await db.execute(query.order_by(PlanUpgradeRequestModel.created_at.desc()))
    return [model_to_dict(r, ["requested_tools"]) for r in result.scalars().all()]

@api_router.get("/upgrade-requests/pending", tags=["Upgrade Requests"])
async def get_pending_upgrade_requests(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Get all pending upgrade requests (super admin only)"""
    result = await db.execute(
        select(PlanUpgradeRequestModel)
        .where(PlanUpgradeRequestModel.status == "pending")
        .order_by(PlanUpgradeRequestModel.created_at.desc())
    )
    return [model_to_dict(r, ["requested_tools"]) for r in result.scalars().all()]

@api_router.post("/upgrade-requests/{request_id}/approve", tags=["Upgrade Requests"])
async def approve_upgrade_request(request_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Approve a plan upgrade request (super admin only)"""
    result = await db.execute(select(PlanUpgradeRequestModel).where(PlanUpgradeRequestModel.id == request_id))
    req = result.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="Upgrade request not found")
    if req.status != "pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    
    now = datetime.now(timezone.utc)
    
    # Update request status
    req.status = "approved"
    req.approved_at = now
    req.updated_at = now
    
    # Update organization's subscription
    sub_result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == req.organization_id)
        .where(SubscriptionModel.status == "active")
    )
    subscription = sub_result.scalar_one_or_none()
    if subscription:
        # Get new plan price
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == req.requested_plan_id))
        new_plan = plan_result.scalar_one_or_none()
        
        subscription.plan_id = req.requested_plan_id
        subscription.plan_name = req.requested_plan_name
        subscription.tools = req.requested_tools
        subscription.amount = new_plan.price_monthly if new_plan else subscription.amount
    
    # Create notification
    notif = NotificationModel(
        title="Upgrade Request Approved",
        message=f"{req.organization_name} upgraded to {req.requested_plan_name}",
        type="success"
    )
    db.add(notif)
    
    await db.commit()
    
    return {"message": "Upgrade request approved", "new_plan": req.requested_plan_name}

@api_router.post("/upgrade-requests/{request_id}/reject", tags=["Upgrade Requests"])
async def reject_upgrade_request(request_id: str, reason: str = "", payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Reject a plan upgrade request (super admin only)"""
    result = await db.execute(select(PlanUpgradeRequestModel).where(PlanUpgradeRequestModel.id == request_id))
    req = result.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="Upgrade request not found")
    if req.status != "pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    
    now = datetime.now(timezone.utc)
    req.status = "rejected"
    req.rejected_at = now
    req.updated_at = now
    req.rejection_reason = reason
    
    # Create notification
    notif = NotificationModel(
        title="Upgrade Request Rejected",
        message=f"Upgrade request from {req.organization_name} was rejected",
        type="warning"
    )
    db.add(notif)
    
    await db.commit()
    
    return {"message": "Upgrade request rejected"}

# ==================== PLAN UPGRADE REQUESTS ====================

@api_router.get("/plan-upgrade-requests", tags=["Plan Upgrade Requests"])
async def get_plan_upgrade_requests(status: Optional[str] = None, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Get all plan upgrade requests (super admin only)"""
    query = select(PlanUpgradeRequestModel)
    if status:
        query = query.where(PlanUpgradeRequestModel.status == status)
    query = query.order_by(PlanUpgradeRequestModel.created_at.desc())
    result = await db.execute(query)
    return [model_to_dict(r, ["requested_tools"]) for r in result.scalars().all()]

@api_router.get("/plan-upgrade-requests/pending", tags=["Plan Upgrade Requests"])
async def get_pending_plan_upgrade_requests(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Get pending plan upgrade requests (super admin only)"""
    result = await db.execute(
        select(PlanUpgradeRequestModel)
        .where(PlanUpgradeRequestModel.status == "pending")
        .order_by(PlanUpgradeRequestModel.created_at.desc())
    )
    return [model_to_dict(r, ["requested_tools"]) for r in result.scalars().all()]

@api_router.post("/plan-upgrade-requests", tags=["Plan Upgrade Requests"])
async def create_plan_upgrade_request(data: PlanUpgradeCreate, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Create a plan upgrade request (org admin only)"""
    # Only org_admin can request upgrades for their organization
    if payload.get("role") != "org_admin":
        raise HTTPException(status_code=403, detail="Only organization admins can request plan upgrades")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization ID not found in token")
    
    # Get organization details
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Get current subscription
    sub_result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == org_id)
        .where(SubscriptionModel.status == "active")
    )
    current_sub = sub_result.scalar_one_or_none()
    if not current_sub:
        raise HTTPException(status_code=404, detail="No active subscription found")
    
    # Validate requested plan exists
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == data.requested_plan_id))
    plan = plan_result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Requested plan not found")
    
    # Check if there's already a pending request
    existing_request = await db.execute(
        select(PlanUpgradeRequestModel)
        .where(PlanUpgradeRequestModel.organization_id == org_id)
        .where(PlanUpgradeRequestModel.status == "pending")
    )
    if existing_request.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A pending upgrade request already exists")
    
    # Create upgrade request
    upgrade_request = PlanUpgradeRequestModel(
        organization_id=org_id,
        organization_name=org.name,
        current_plan_id=current_sub.plan_id,
        current_plan_name=current_sub.plan_name,
        requested_plan_id=data.requested_plan_id,
        requested_plan_name=plan.name,
        requested_tools=json.dumps(data.requested_tools),
        reason=data.reason,
        requested_by=payload["sub"]
    )
    db.add(upgrade_request)
    
    # Create notification for super admin
    notif = NotificationModel(
        title="Plan Upgrade Request",
        message=f"{org.name} requested upgrade to {plan.name}",
        type="info",
        link=f"/plan-upgrade-requests"
    )
    db.add(notif)
    
    await db.commit()
    return model_to_dict(upgrade_request, ["requested_tools"])

@api_router.post("/plan-upgrade-requests/{request_id}/approve", tags=["Plan Upgrade Requests"])
async def approve_plan_upgrade_request(request_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Approve a plan upgrade request (super admin only)"""
    result = await db.execute(select(PlanUpgradeRequestModel).where(PlanUpgradeRequestModel.id == request_id))
    request = result.scalar_one_or_none()
    if not request:
        raise HTTPException(status_code=404, detail="Upgrade request not found")
    if request.status != "pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    
    now = datetime.now(timezone.utc)
    request.status = "approved"
    request.approved_at = now
    request.updated_at = now
    
    # Update current subscription
    sub_result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == request.organization_id)
        .where(SubscriptionModel.status == "active")
    )
    subscription = sub_result.scalar_one_or_none()
    if subscription:
        subscription.plan_id = request.requested_plan_id
        subscription.plan_name = request.requested_plan_name
        subscription.tools = request.requested_tools
        
        # Get new plan pricing
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == request.requested_plan_id))
        plan = plan_result.scalar_one_or_none()
        if plan:
            subscription.amount = plan.price_monthly
    
    # Create notification
    notif = NotificationModel(
        title="Plan Upgrade Approved",
        message=f"{request.organization_name} plan upgrade approved",
        type="success"
    )
    db.add(notif)
    
    await db.commit()
    return {"message": "Plan upgrade request approved"}

@api_router.post("/plan-upgrade-requests/{request_id}/reject", tags=["Plan Upgrade Requests"])
async def reject_plan_upgrade_request(request_id: str, reason: str = "", payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Reject a plan upgrade request (super admin only)"""
    result = await db.execute(select(PlanUpgradeRequestModel).where(PlanUpgradeRequestModel.id == request_id))
    request = result.scalar_one_or_none()
    if not request:
        raise HTTPException(status_code=404, detail="Upgrade request not found")
    if request.status != "pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    
    now = datetime.now(timezone.utc)
    request.status = "rejected"
    request.rejected_at = now
    request.rejection_reason = reason
    request.updated_at = now
    
    # Create notification
    notif = NotificationModel(
        title="Plan Upgrade Rejected",
        message=f"{request.organization_name} plan upgrade rejected",
        type="warning"
    )
    db.add(notif)
    
    await db.commit()
    return {"message": "Plan upgrade request rejected"}

# ==================== DASHBOARD ROUTES (Super Admin Only) ====================

@api_router.get("/dashboard/stats")
async def get_dashboard_stats(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    total_orgs = await db.scalar(select(func.count()).select_from(OrganizationModel))
    pending_orgs = await db.scalar(select(func.count()).select_from(OrganizationModel).where(OrganizationModel.status == "pending"))
    approved_orgs = await db.scalar(select(func.count()).select_from(OrganizationModel).where(OrganizationModel.status == "approved"))
    active_subs = await db.scalar(select(func.count()).select_from(SubscriptionModel).where(SubscriptionModel.status == "active"))
    total_users = await db.scalar(select(func.count()).select_from(UserModel))
    total_revenue = await db.scalar(select(func.sum(BillingModel.amount)).where(BillingModel.status == "paid")) or 0
    
    result = await db.execute(select(OrganizationModel).order_by(OrganizationModel.created_at.desc()).limit(5))
    recent_orgs = [model_to_dict(o, ["requested_tools", "supported_domains"]) for o in result.scalars().all()]
    
    result = await db.execute(select(SubscriptionModel).order_by(SubscriptionModel.created_at.desc()).limit(5))
    recent_subs = [model_to_dict(s, ["tools"]) for s in result.scalars().all()]
    
    # Calculate real monthly revenue from billing data for the last 6 months
    from datetime import datetime, timedelta
    from calendar import monthrange
    
    monthly_revenue = []
    now = datetime.now()
    month_names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    
    for i in range(5, -1, -1):  # Last 6 months (5 to 0)
        # Calculate the target month
        target_date = now - timedelta(days=i * 30)  # Approximate month offset
        year = target_date.year
        month = target_date.month
        
        # Get first and last day of the month
        first_day = datetime(year, month, 1)
        last_day_num = monthrange(year, month)[1]
        last_day = datetime(year, month, last_day_num, 23, 59, 59)
        
        # Query billing for this month (paid invoices only)
        month_revenue = await db.scalar(
            select(func.sum(BillingModel.amount))
            .where(BillingModel.status == "paid")
            .where(BillingModel.billing_date >= first_day)
            .where(BillingModel.billing_date <= last_day)
        ) or 0
        
        monthly_revenue.append({
            "month": month_names[month - 1],
            "revenue": float(month_revenue)
        })
    
    # Calculate tool distribution from active subscriptions
    # Count how many subscriptions include each tool
    result = await db.execute(select(SubscriptionModel).where(SubscriptionModel.status == "active"))
    active_subscriptions = result.scalars().all()
    
    api_count = 0
    ai_count = 0
    mig_count = 0
    
    for sub in active_subscriptions:
        tools = json.loads(sub.tools) if sub.tools else []
        if "api_platform" in tools:
            api_count += 1
        if "ai_agentic" in tools:
            ai_count += 1
        if "migration_tool" in tools:
            mig_count += 1
    
    sub_distribution = [
        {"name": "API Platform", "value": api_count},
        {"name": "AI Agentic", "value": ai_count},
        {"name": "Migration Tool", "value": mig_count},
    ]
    
    return {
        "total_organizations": total_orgs or 0, "pending_organizations": pending_orgs or 0,
        "approved_organizations": approved_orgs or 0, "active_subscriptions": active_subs or 0,
        "total_users": total_users or 0, "total_revenue": total_revenue,
        "recent_organizations": recent_orgs, "recent_subscriptions": recent_subs,
        "monthly_revenue": monthly_revenue, "subscription_distribution": sub_distribution
    }

# ==================== ORGANIZATION ROUTES (Super Admin Only) ====================

@api_router.get("/organizations")
async def get_organizations(status: Optional[str] = None, search: Optional[str] = None, 
                           payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    query = select(OrganizationModel)
    if status:
        query = query.where(OrganizationModel.status == status)
    if search:
        query = query.where((OrganizationModel.name.ilike(f"%{search}%")) | (OrganizationModel.email.ilike(f"%{search}%")))
    query = query.order_by(OrganizationModel.created_at.desc())
    result = await db.execute(query)
    return [model_to_dict(o, ["requested_tools", "supported_domains"]) for o in result.scalars().all()]

@api_router.get("/organizations/pending")
async def get_pending_organizations(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.status == "pending").order_by(OrganizationModel.created_at.desc()))
    return [model_to_dict(o, ["requested_tools", "supported_domains"]) for o in result.scalars().all()]

@api_router.get("/organizations/{org_id}")
async def get_organization(org_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return model_to_dict(org, ["requested_tools", "supported_domains"])

@api_router.post("/organizations")
async def create_organization(data: OrganizationCreate, db: AsyncSession = Depends(get_db)):
    org = OrganizationModel(
        name=data.name, email=data.email, domain=data.domain,
        requested_plan=data.requested_plan, requested_tools=json.dumps(data.requested_tools),
        contact_person=data.contact_person, phone=data.phone, address=data.address
    )
    db.add(org)
    
    notif = NotificationModel(
        title="New Organization Request",
        message=f"{data.name} has requested to join with {data.requested_plan} plan",
        type="info", link=f"/organizations/{org.id}"
    )
    db.add(notif)
    await db.commit()
    return model_to_dict(org, ["requested_tools", "supported_domains"])

# ==================== PUBLIC API - Organization Identification ====================

@api_router.post("/public/identify-org", tags=["Public API"])
async def identify_organization(data: IdentifyOrgRequest, db: AsyncSession = Depends(get_db)):
    """
    Public API to identify organization from email address.
    Called by external apps to determine which organization a user belongs to.
    
    - Extracts domain from email (e.g., "user@kre.com" -> "@kre.com")
    - Finds organization with matching supported_domains
    - Returns external_org_id if found
    """
    if not data.email or "@" not in data.email:
        raise HTTPException(status_code=400, detail="Invalid email format")

    # Extract domain from email (e.g., "user@kre.com" -> "@kre.com")
    email_domain = "@" + data.email.split("@")[1].lower()

    # Find organization with this domain in supported_domains
    result = await db.execute(
        select(OrganizationModel).where(
            OrganizationModel.status == "approved",
            OrganizationModel.supported_domains.isnot(None)
        )
    )
    organizations = result.scalars().all()

    for org in organizations:
        if org.supported_domains:
            try:
                supported = json.loads(org.supported_domains)
                # Check if email domain matches any supported domain (case-insensitive)
                if any(d.lower() == email_domain for d in supported):
                    return {
                        "found": True,
                        "email": data.email,
                        "domain": email_domain,
                        "organization": {
                            "external_org_id": org.external_org_id,
                            "name": org.name,
                            "id": org.id
                        }
                    }
            except json.JSONDecodeError:
                continue

    # No matching organization found
    return {
        "found": False,
        "email": data.email,
        "domain": email_domain,
        "organization": None,
        "message": "No organization found for this email domain"
    }

# ==================== PUBLIC API - Auth0 Authentication ====================

@api_router.post("/public/auth/init", tags=["Public API - Auth0"])
async def auth0_init(data: Auth0InitRequest, db: AsyncSession = Depends(get_db)):
    """
    Step 1: Initialize Auth0 authentication flow.
    
    - Takes user email
    - Identifies organization from email domain
    - Returns Auth0 authorize URL with the correct organization parameter
    
    The frontend should redirect the user to the returned authorize_url.
    """
    if not data.email or "@" not in data.email:
        raise HTTPException(status_code=400, detail="Invalid email format")

    # Extract domain from email
    email_domain = "@" + data.email.split("@")[1].lower()

    # Find organization with this domain
    result = await db.execute(
        select(OrganizationModel).where(
            OrganizationModel.status == "approved",
            OrganizationModel.supported_domains.isnot(None)
        )
    )
    organizations = result.scalars().all()

    found_org = None
    for org in organizations:
        if org.supported_domains:
            try:
                supported = json.loads(org.supported_domains)
                if any(d.lower() == email_domain for d in supported):
                    found_org = org
                    break
            except json.JSONDecodeError:
                continue

    if not found_org:
        raise HTTPException(
            status_code=404, 
            detail=f"No organization found for email domain {email_domain}"
        )

    if not found_org.auth0_org_id:
        raise HTTPException(
            status_code=400,
            detail=f"Organization {found_org.name} does not have Auth0 organization configured"
        )

    # Build Auth0 authorize URL
    auth0_params = {
        "client_id": AUTH0_CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": AUTH0_CALLBACK_URI,
        "organization": found_org.auth0_org_id,  # Auth0 org_id like org_SVFows90OrYpzdIs
    }

    # Add state if provided (for CSRF protection)
    if data.state:
        auth0_params["state"] = data.state

    authorize_url = f"https://{AUTH0_DOMAIN}/authorize?{urlencode(auth0_params)}"

    return {
        "success": True,
        "authorize_url": authorize_url,
        "organization": {
            "id": found_org.id,
            "name": found_org.name,
            "external_org_id": found_org.external_org_id,
            "auth0_org_id": found_org.auth0_org_id
        },
        "email": data.email,
        "domain": email_domain
    }

@api_router.post("/public/auth/callback", tags=["Public API - Auth0"])
async def auth0_callback(data: Auth0CallbackRequest, db: AsyncSession = Depends(get_db)):
    """
    Step 2: Exchange Auth0 authorization code for tokens.
    
    - Takes the code from Auth0 callback
    - Exchanges code for access_token, id_token
    - Decodes id_token to extract user info
    - Saves login record to database
    - Returns tokens to the frontend
    """
    if not data.code:
        raise HTTPException(status_code=400, detail="Authorization code is required")

    # Exchange code for tokens
    token_url = f"https://{AUTH0_DOMAIN}/oauth/token"
    token_payload = {
        "grant_type": "authorization_code",
        "client_id": AUTH0_CLIENT_ID,
        "client_secret": AUTH0_CLIENT_SECRET,
        "code": data.code,
        "redirect_uri": AUTH0_CALLBACK_URI
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                token_url,
                json=token_payload,
                headers={"Content-Type": "application/json"},
                timeout=30.0
            )

            if response.status_code != 200:
                error_detail = response.text
                try:
                    error_json = response.json()
                    error_detail = error_json.get("error_description", error_json.get("error", response.text))
                except:
                    pass
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Auth0 token exchange failed: {error_detail}"
                )

            tokens = response.json()
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to connect to Auth0: {str(e)}"
            )

    # Extract user info from id_token (JWT)
    id_token = tokens.get("id_token")
    user_info = {}
    auth0_org_id = None
    auth0_user_id = None

    if id_token:
        try:
            # Decode JWT without verification (we trust Auth0)
            # In production, you should verify the signature
            decoded = jwt.decode(id_token, options={"verify_signature": False})
            user_info = {
                "email": decoded.get("email"),
                "name": decoded.get("name"),
                "nickname": decoded.get("nickname"),
                "picture": decoded.get("picture"),
                "email_verified": decoded.get("email_verified"),
            }
            auth0_org_id = decoded.get("org_id")
            auth0_user_id = decoded.get("sub")
        except Exception as e:
            logging.warning(f"Failed to decode id_token: {e}")

    # Find organization by Auth0 org_id
    email = user_info.get("email") or data.email
    org = None

    if auth0_org_id:
        result = await db.execute(
            select(OrganizationModel).where(
                OrganizationModel.auth0_org_id == auth0_org_id
            )
        )
        org = result.scalar_one_or_none()

    # If not found by org_id, try to find by email domain
    if not org and email and "@" in email:
        email_domain = "@" + email.split("@")[1].lower()
        result = await db.execute(
            select(OrganizationModel).where(
                OrganizationModel.status == "approved",
                OrganizationModel.supported_domains.isnot(None)
            )
        )
        organizations = result.scalars().all()

        for o in organizations:
            if o.supported_domains:
                try:
                    supported = json.loads(o.supported_domains)
                    if any(d.lower() == email_domain for d in supported):
                        org = o
                        break
                except json.JSONDecodeError:
                    continue

    # Save login record
    expires_in = tokens.get("expires_in", 86400)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    login_record = Auth0LoginRecordModel(
        email=email or "unknown",
        organization_id=org.id if org else "unknown",
        organization_name=org.name if org else "Unknown",
        external_org_id=org.external_org_id if org else auth0_org_id,
        auth0_org_id=auth0_org_id,
        auth0_user_id=auth0_user_id,
        name=user_info.get("name"),
        picture=user_info.get("picture"),
        access_token=tokens.get("access_token"),
        id_token=id_token,
        token_type=tokens.get("token_type"),
        expires_in=expires_in,
        expires_at=expires_at
    )
    db.add(login_record)
    # Extract roles from Auth0 token (custom claim)
    auth0_roles = []
    if id_token:
        try:
            decoded = jwt.decode(id_token, options={"verify_signature": False})
            # Auth0 roles are typically in a custom claim like "https://probestack.io/claims/roles"
            auth0_roles = decoded.get("https://probestack.io/claims/roles", [])
            if not auth0_roles:
                # Try other common role claim names
                auth0_roles = decoded.get("roles", [])
                if not auth0_roles:
                    auth0_roles = decoded.get("https://auth0.com/claims/roles", [])
        except Exception as e:
            logging.warning(f"Failed to extract roles from id_token: {e}")

    # Sync user to database if organization exists
    synced_user = None
    synced_roles = []

    if org and email:
        # Check if user already exists
        result = await db.execute(
            select(UserModel).where(
                UserModel.email == email,
                UserModel.organization_id == org.id
            )
        )
        existing_user = result.scalar_one_or_none()

        # Process Auth0 roles - create if not exists
        for role_name in auth0_roles:
            if not role_name:
                continue
            # Check if role exists in the organization
            result = await db.execute(
                select(RoleModel).where(
                    RoleModel.name == role_name,
                    RoleModel.organization_id == org.id
                )
            )
            role = result.scalar_one_or_none()

            if not role:
                # Create new role
                role = RoleModel(
                    name=role_name,
                    organization_id=org.id,
                    permissions=json.dumps(["read"]),  # Default permissions
                    description=f"Auto-created from Auth0 role: {role_name}"
                )
                db.add(role)
                await db.flush()

            synced_roles.append({"id": role.id, "name": role.name})

        # Determine the primary role (first role or default)
        primary_role = synced_roles[0] if synced_roles else None

        if existing_user:
            # Update existing user
            existing_user.name = user_info.get("name") or existing_user.name
            if primary_role:
                existing_user.role_id = primary_role["id"]
                existing_user.role_name = primary_role["name"]
            existing_user.last_login = datetime.now(timezone.utc)
            synced_user = existing_user
        else:
            # Create new user
            # If no role from Auth0, create/get a default "User" role
            if not primary_role:
                result = await db.execute(
                    select(RoleModel).where(
                        RoleModel.name == "User",
                        RoleModel.organization_id == org.id
                    )
                )
                default_role = result.scalar_one_or_none()

                if not default_role:
                    default_role = RoleModel(
                        name="User",
                        organization_id=org.id,
                        permissions=json.dumps(["read"]),
                        description="Default user role"
                    )
                    db.add(default_role)
                    await db.flush()

                primary_role = {"id": default_role.id, "name": default_role.name}

            new_user = UserModel(
                email=email,
                name=user_info.get("name") or user_info.get("nickname") or email.split("@")[0],
                organization_id=org.id,
                organization_name=org.name,
                role_id=primary_role["id"],
                role_name=primary_role["name"],
                status="active",
                last_login=datetime.now(timezone.utc)
            )
            db.add(new_user)
            synced_user = new_user
    await db.commit()

    return {
        "success": True,
        "access_token": tokens.get("access_token"),
        "id_token": id_token,
        "token_type": tokens.get("token_type"),
        "expires_in": expires_in,
        "scope": tokens.get("scope"),
        "user": user_info,
        "organization": {
            "id": org.id if org else None,
            "name": org.name if org else None,
            "external_org_id": org.external_org_id if org else auth0_org_id
        },
        "login_record_id": login_record.id,
        "synced_user": {
            "id": synced_user.id if synced_user else None,
            "email": synced_user.email if synced_user else None,
            "name": synced_user.name if synced_user else None,
            "role": synced_user.role_name if synced_user else None
        } if synced_user else None,
        "synced_roles": synced_roles,
        "auth0_roles": auth0_roles
    }

@api_router.get("/auth0-logins", tags=["Admin - Auth0"])
async def get_auth0_logins(
    organization_id: Optional[str] = None,
    limit: int = 100,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get Auth0 login records (Super Admin only)"""
    query = select(Auth0LoginRecordModel).order_by(Auth0LoginRecordModel.login_at.desc())

    if organization_id:
        query = query.where(Auth0LoginRecordModel.organization_id == organization_id)

    query = query.limit(limit)
    result = await db.execute(query)
    records = result.scalars().all()

    return [
        {
            "id": r.id,
            "email": r.email,
            "organization_id": r.organization_id,
            "organization_name": r.organization_name,
            "external_org_id": r.external_org_id,
            "auth0_org_id": r.auth0_org_id,
            "auth0_user_id": r.auth0_user_id,
            "name": r.name,
            "login_at": r.login_at.isoformat() if r.login_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None
        }
        for r in records
    ]

@api_router.put("/organizations/{org_id}")
async def update_organization(org_id: str, data: OrganizationUpdate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    update_data = {k: v for k, v in data.model_dump().items() if v is not None}
    if 'supported_domains' in update_data and isinstance(update_data['supported_domains'], list):
        update_data['supported_domains'] = json.dumps(update_data['supported_domains'])

    if 'external_org_id' in update_data and update_data['external_org_id']:
        existing = await db.execute(
            select(OrganizationModel).where(
                OrganizationModel.external_org_id == update_data['external_org_id'],
                OrganizationModel.id != org_id
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="External Org ID already in use by another organization")
    for key, value in update_data.items():
        setattr(org, key, value)
    org.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return model_to_dict(org, ["requested_tools"])

@api_router.post("/organizations/{org_id}/approve")
async def approve_organization(org_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if org.status != "pending":
        raise HTTPException(status_code=400, detail="Organization is not pending")
    
    now = datetime.now(timezone.utc)
    org.status = "approved"
    org.approved_at = now
    org.updated_at = now
    
    # Get plan details
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == org.requested_plan))
    plan = plan_result.scalar_one_or_none()
    plan_name = plan.name if plan else org.requested_plan
    plan_amount = plan.price_monthly if plan else 99.0
    
    # Create subscription with explicit ID
    subscription_id = str(uuid.uuid4())
    tools = json.loads(org.requested_tools) if isinstance(org.requested_tools, str) else org.requested_tools
    subscription = SubscriptionModel(
        id=subscription_id,
        organization_id=org_id, organization_name=org.name,
        plan_id=org.requested_plan, plan_name=plan_name,
        tools=json.dumps(tools), status="active",
        start_date=now, end_date=now + timedelta(days=30), amount=plan_amount
    )
    db.add(subscription)
    
    # Flush to ensure subscription is written to DB before creating billing (needed for MySQL foreign key)
    await db.flush()
    
    # Create billing record with the known subscription ID
    billing = BillingModel(
        organization_id=org_id, organization_name=org.name,
        subscription_id=subscription_id, amount=plan_amount, status="pending",
        invoice_number=f"INV-{now.strftime('%Y%m%d')}-{org_id[:8].upper()}",
        billing_date=now, due_date=now + timedelta(days=7)
    )
    db.add(billing)
    
    notif = NotificationModel(title="Organization Approved", message=f"{org.name} has been approved", type="success")
    db.add(notif)
    await db.commit()
    return {"message": "Organization approved", "subscription_id": subscription_id}

@api_router.post("/organizations/{org_id}/reject")
async def reject_organization(org_id: str, reason: str = "", payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if org.status != "pending":
        raise HTTPException(status_code=400, detail="Organization is not pending")
    
    now = datetime.now(timezone.utc)
    org.status = "rejected"
    org.rejected_at = now
    org.rejection_reason = reason
    org.updated_at = now
    
    notif = NotificationModel(title="Organization Rejected", message=f"{org.name} has been rejected", type="warning")
    db.add(notif)
    await db.commit()
    return {"message": "Organization rejected"}

@api_router.delete("/organizations/{org_id}")
async def delete_organization(org_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(delete(OrganizationModel).where(OrganizationModel.id == org_id))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Organization not found")
    await db.commit()
    return {"message": "Organization deleted"}

# ==================== SUBSCRIPTION ROUTES (Super Admin Only) ====================

@api_router.get("/subscriptions")
async def get_subscriptions(status: Optional[str] = None, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    query = select(SubscriptionModel)
    if status:
        query = query.where(SubscriptionModel.status == status)
    result = await db.execute(query.order_by(SubscriptionModel.created_at.desc()))
    return [model_to_dict(s, ["tools"]) for s in result.scalars().all()]

@api_router.get("/subscriptions/{sub_id}")
async def get_subscription(sub_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SubscriptionModel).where(SubscriptionModel.id == sub_id))
    sub = result.scalar_one_or_none()
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return model_to_dict(sub, ["tools"])

@api_router.post("/subscriptions/{sub_id}/pause")
async def pause_subscription(sub_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(update(SubscriptionModel).where(SubscriptionModel.id == sub_id).values(status="paused"))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Subscription not found")
    await db.commit()
    return {"message": "Subscription paused"}

@api_router.post("/subscriptions/{sub_id}/resume")
async def resume_subscription(sub_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(update(SubscriptionModel).where(SubscriptionModel.id == sub_id).values(status="active"))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Subscription not found")
    await db.commit()
    return {"message": "Subscription resumed"}

@api_router.post("/subscriptions/{sub_id}/cancel")
async def cancel_subscription(sub_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(update(SubscriptionModel).where(SubscriptionModel.id == sub_id).values(status="cancelled"))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Subscription not found")
    await db.commit()
    return {"message": "Subscription cancelled"}

# ==================== PLANS ROUTES (Super Admin Only for management) ====================

@api_router.get("/plans")
async def get_plans(tool: Optional[str] = None, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get all plans - accessible by any admin (Super Admin or Org Admin)"""
    query = select(PlanModel)
    if tool:
        query = query.where(PlanModel.tool == tool)
    result = await db.execute(query.order_by(PlanModel.created_at.desc()))
    return [model_to_dict(p, ["features"]) for p in result.scalars().all()]

@api_router.get("/plans/{plan_id}")
async def get_plan(plan_id: str, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
    plan = result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    return model_to_dict(plan, ["features"])

@api_router.post("/plans")
async def create_plan(data: PlanCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    plan = PlanModel(
        name=data.name, tool=data.tool, description=data.description,
        features=json.dumps(data.features), price_monthly=data.price_monthly, price_yearly=data.price_yearly
    )
    db.add(plan)
    await db.commit()
    return model_to_dict(plan, ["features"])

@api_router.put("/plans/{plan_id}")
async def update_plan(plan_id: str, data: PlanCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
    plan = result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    
    plan.name = data.name
    plan.tool = data.tool
    plan.description = data.description
    plan.features = json.dumps(data.features)
    plan.price_monthly = data.price_monthly
    plan.price_yearly = data.price_yearly
    await db.commit()
    return model_to_dict(plan, ["features"])

@api_router.delete("/plans/{plan_id}")
async def delete_plan(plan_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(delete(PlanModel).where(PlanModel.id == plan_id))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Plan not found")
    await db.commit()
    return {"message": "Plan deleted"}

# ==================== USERS ROUTES (Super Admin Only) ====================

@api_router.get("/users")
async def get_users(organization_id: Optional[str] = None, status: Optional[str] = None,
                   payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    query = select(UserModel)
    if organization_id:
        query = query.where(UserModel.organization_id == organization_id)
    if status:
        query = query.where(UserModel.status == status)
    result = await db.execute(query.order_by(UserModel.created_at.desc()))
    return [model_to_dict(u) for u in result.scalars().all()]

@api_router.get("/users/{user_id}")
async def get_user(user_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return model_to_dict(user)

@api_router.post("/users")
async def create_user(data: UserCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == data.organization_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    role_result = await db.execute(select(RoleModel).where(RoleModel.id == data.role_id))
    role = role_result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    user = UserModel(
        email=data.email, name=data.name, organization_id=data.organization_id,
        organization_name=org.name, role_id=data.role_id, role_name=role.name
    )
    db.add(user)
    await db.commit()
    return model_to_dict(user)

@api_router.put("/users/{user_id}/status")
async def update_user_status(user_id: str, status: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(update(UserModel).where(UserModel.id == user_id).values(status=status))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")
    await db.commit()
    return {"message": f"User status updated to {status}"}

@api_router.delete("/users/{user_id}")
async def delete_user(user_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(delete(UserModel).where(UserModel.id == user_id))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")
    await db.commit()
    return {"message": "User deleted"}

# ==================== ROLES ROUTES (Super Admin Only) ====================

@api_router.get("/roles")
async def get_roles(organization_id: Optional[str] = None, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    query = select(RoleModel)
    if organization_id:
        query = query.where(RoleModel.organization_id == organization_id)
    result = await db.execute(query.order_by(RoleModel.created_at.desc()))
    return [model_to_dict(r, ["permissions"]) for r in result.scalars().all()]

@api_router.get("/roles/{role_id}")
async def get_role(role_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RoleModel).where(RoleModel.id == role_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return model_to_dict(role, ["permissions"])

@api_router.post("/roles")
async def create_role(data: RoleCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    role = RoleModel(
        name=data.name, organization_id=data.organization_id,
        permissions=json.dumps(data.permissions), description=data.description
    )
    db.add(role)
    await db.commit()
    return model_to_dict(role, ["permissions"])

@api_router.put("/roles/{role_id}")
async def update_role(role_id: str, data: RoleCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RoleModel).where(RoleModel.id == role_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    role.name = data.name
    role.organization_id = data.organization_id
    role.permissions = json.dumps(data.permissions)
    role.description = data.description
    await db.commit()
    return model_to_dict(role, ["permissions"])

@api_router.delete("/roles/{role_id}")
async def delete_role(role_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(delete(RoleModel).where(RoleModel.id == role_id))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Role not found")
    await db.commit()
    return {"message": "Role deleted"}

# ==================== BILLING ROUTES (Super Admin Only) ====================

@api_router.get("/billing")
async def get_billing_records(organization_id: Optional[str] = None, status: Optional[str] = None,
                             payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    query = select(BillingModel)
    if organization_id:
        query = query.where(BillingModel.organization_id == organization_id)
    if status:
        query = query.where(BillingModel.status == status)
    result = await db.execute(query.order_by(BillingModel.created_at.desc()))
    return [model_to_dict(b) for b in result.scalars().all()]

@api_router.get("/billing/{billing_id}")
async def get_billing_record(billing_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(BillingModel).where(BillingModel.id == billing_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Billing record not found")
    return model_to_dict(record)

@api_router.post("/billing/{billing_id}/mark-paid")
async def mark_billing_paid(billing_id: str, payment_method: str = "card", payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    result = await db.execute(update(BillingModel).where(BillingModel.id == billing_id).values(
        status="paid", paid_date=now, payment_method=payment_method
    ))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Billing record not found")
    await db.commit()
    return {"message": "Billing marked as paid"}

@api_router.post("/billing/{billing_id}/mark-unpaid")
async def mark_billing_unpaid(billing_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Mark a billing record as unpaid/pending (Super Admin only)"""
    result = await db.execute(update(BillingModel).where(BillingModel.id == billing_id).values(
        status="pending", paid_date=None, payment_method=None
    ))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Billing record not found")
    await db.commit()
    return {"message": "Billing marked as unpaid"}

@api_router.post("/billing/generate-monthly")
async def generate_monthly_bills(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """
    Generate monthly billing records for all active subscriptions.
    Creates pending invoices for subscriptions that don't have a bill for the current month.
    """
    now = datetime.now(timezone.utc)
    current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    # Get all active subscriptions
    subs_result = await db.execute(
        select(SubscriptionModel).where(SubscriptionModel.status == "active")
    )
    active_subscriptions = subs_result.scalars().all()
    
    bills_created = 0
    bills_skipped = 0
    
    for sub in active_subscriptions:
        # Check if a bill already exists for this subscription this month
        existing_bill = await db.execute(
            select(BillingModel).where(
                BillingModel.subscription_id == sub.id,
                BillingModel.billing_date >= current_month_start
            )
        )
        
        if existing_bill.scalar_one_or_none():
            bills_skipped += 1
            continue
        
        # Create new billing record
        invoice_number = f"INV-{now.strftime('%Y%m')}-{sub.organization_id[-4:].upper()}-{str(uuid.uuid4())[:4].upper()}"
        due_date = now + timedelta(days=15)
        
        billing = BillingModel(
            organization_id=sub.organization_id,
            organization_name=sub.organization_name,
            subscription_id=sub.id,
            amount=sub.amount,
            status="pending",
            invoice_number=invoice_number,
            billing_date=now,
            due_date=due_date
        )
        db.add(billing)
        bills_created += 1
    
    await db.commit()
    
    return {
        "message": f"Monthly billing generation complete",
        "bills_created": bills_created,
        "bills_skipped": bills_skipped,
        "total_active_subscriptions": len(active_subscriptions)
    }

# ==================== NOTIFICATIONS ROUTES (Super Admin Only) ====================

@api_router.get("/notifications")
async def get_notifications(unread_only: bool = False, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    query = select(NotificationModel)
    if unread_only:
        query = query.where(NotificationModel.is_read == False)
    result = await db.execute(query.order_by(NotificationModel.created_at.desc()).limit(100))
    return [model_to_dict(n) for n in result.scalars().all()]

@api_router.post("/notifications/{notif_id}/read")
async def mark_notification_read(notif_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(update(NotificationModel).where(NotificationModel.id == notif_id).values(is_read=True))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Notification not found")
    await db.commit()
    return {"message": "Notification marked as read"}

@api_router.post("/notifications/read-all")
async def mark_all_notifications_read(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(update(NotificationModel).values(is_read=True))
    await db.commit()
    return {"message": "All notifications marked as read"}

@api_router.delete("/notifications/{notif_id}")
async def delete_notification(notif_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(delete(NotificationModel).where(NotificationModel.id == notif_id))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Notification not found")
    await db.commit()
    return {"message": "Notification deleted"}

# ==================== SEED DATA ROUTE ====================

@api_router.post("/seed")
async def seed_data(db: AsyncSession = Depends(get_db)):
    """Seed initial data for testing"""
    # Clear existing data
    await db.execute(delete(NotificationModel))
    await db.execute(delete(BillingModel))
    await db.execute(delete(UserModel))
    await db.execute(delete(UserRequestModel))
    await db.execute(delete(PlanUpgradeRequestModel))
    await db.execute(delete(RoleModel))
    await db.execute(delete(SubscriptionModel))
    await db.execute(delete(OrganizationModel))
    await db.execute(delete(PlanModel))
    await db.execute(delete(AdminModel))
    await db.commit()
    
    now = datetime.now(timezone.utc)
    
    # Create default super admin (password: admin123)
    password_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
    super_admin = AdminModel(
        id="admin_super_1",
        email="superadmin@probestack.io",
        password_hash=password_hash,
        name="Super Admin",
        role="super_admin"
    )
    db.add(super_admin)
    
    # Create plans
    plans_data = [
        {"id": "plan_api_starter", "name": "Starter", "tool": "api_platform", "description": "Perfect for small teams", "features": ["5 APIs", "1000 requests/day", "Basic analytics", "Email support"], "price_monthly": 29.0, "price_yearly": 290.0},
        {"id": "plan_api_pro", "name": "Professional", "tool": "api_platform", "description": "For growing teams", "features": ["25 APIs", "10000 requests/day", "Advanced analytics", "Priority support", "Custom domains"], "price_monthly": 99.0, "price_yearly": 990.0},
        {"id": "plan_api_enterprise", "name": "Enterprise", "tool": "api_platform", "description": "Full-featured for large organizations", "features": ["Unlimited APIs", "Unlimited requests", "Enterprise analytics", "24/7 support", "SLA", "SSO"], "price_monthly": 299.0, "price_yearly": 2990.0},
        {"id": "plan_ai_starter", "name": "Starter", "tool": "ai_agentic", "description": "AI-powered basics", "features": ["5 AI agents", "100 generations/day", "Basic templates"], "price_monthly": 49.0, "price_yearly": 490.0},
        {"id": "plan_ai_pro", "name": "Professional", "tool": "ai_agentic", "description": "Advanced AI", "features": ["25 AI agents", "1000 generations/day", "Custom templates", "Fine-tuning"], "price_monthly": 149.0, "price_yearly": 1490.0},
        {"id": "plan_ai_enterprise", "name": "Enterprise", "tool": "ai_agentic", "description": "Enterprise AI", "features": ["Unlimited agents", "Unlimited generations", "Custom models", "On-premise"], "price_monthly": 449.0, "price_yearly": 4490.0},
        {"id": "plan_mig_starter", "name": "Starter", "tool": "migration_tool", "description": "Basic migrations", "features": ["10 migrations/month", "Apigee Edge to X", "Basic validation"], "price_monthly": 39.0, "price_yearly": 390.0},
        {"id": "plan_mig_pro", "name": "Professional", "tool": "migration_tool", "description": "Full migration suite", "features": ["50 migrations/month", "All platforms", "Advanced validation", "Rollback support"], "price_monthly": 129.0, "price_yearly": 1290.0},
        {"id": "plan_mig_enterprise", "name": "Enterprise", "tool": "migration_tool", "description": "Enterprise migrations", "features": ["Unlimited migrations", "Custom integrations", "Dedicated support", "SLA"], "price_monthly": 349.0, "price_yearly": 3490.0},
    ]
    for p in plans_data:
        db.add(PlanModel(id=p["id"], name=p["name"], tool=p["tool"], description=p["description"], features=json.dumps(p["features"]), price_monthly=p["price_monthly"], price_yearly=p["price_yearly"]))
    
    # Create organizations
    orgs_data = [
        {"id": "org_1", "name": "TechCorp Inc", "email": "admin@techcorp.io", "domain": "techcorp.io", "status": "approved", "requested_plan": "plan_api_pro", "requested_tools": ["api_platform"], "contact_person": "John Smith", "phone": "+1-555-0101"},
        {"id": "org_2", "name": "DataFlow Systems", "email": "hello@dataflow.dev", "domain": "dataflow.dev", "status": "approved", "requested_plan": "plan_ai_pro", "requested_tools": ["ai_agentic", "api_platform"], "contact_person": "Sarah Chen", "phone": "+1-555-0102"},
        {"id": "org_3", "name": "CloudNine Ltd", "email": "contact@cloudnine.co", "domain": "cloudnine.co", "status": "pending", "requested_plan": "plan_api_enterprise", "requested_tools": ["api_platform", "migration_tool"], "contact_person": "Mike Johnson", "phone": "+1-555-0103"},
        {"id": "org_4", "name": "StartupX", "email": "team@startupx.io", "domain": "startupx.io", "status": "pending", "requested_plan": "plan_ai_starter", "requested_tools": ["ai_agentic"], "contact_person": "Emily Davis", "phone": "+1-555-0104"},
        {"id": "org_5", "name": "Enterprise Solutions", "email": "admin@enterprise-sol.com", "domain": "enterprise-sol.com", "status": "approved", "requested_plan": "plan_mig_enterprise", "requested_tools": ["migration_tool", "api_platform"], "contact_person": "Robert Wilson", "phone": "+1-555-0105"},
        {"id": "org_6", "name": "InnovateTech", "email": "info@innovatetech.net", "domain": "innovatetech.net", "status": "pending", "requested_plan": "plan_api_pro", "requested_tools": ["api_platform"], "contact_person": "Lisa Brown", "phone": "+1-555-0106"},
    ]
    for o in orgs_data:
        db.add(OrganizationModel(id=o["id"], name=o["name"], email=o["email"], domain=o["domain"], status=o["status"], requested_plan=o["requested_plan"], requested_tools=json.dumps(o["requested_tools"]), contact_person=o["contact_person"], phone=o["phone"]))
    
    # Create subscriptions
    subs_data = [
        {"id": "sub_1", "organization_id": "org_1", "organization_name": "TechCorp Inc", "plan_id": "plan_api_pro", "plan_name": "Professional", "tools": ["api_platform"], "amount": 99.0},
        {"id": "sub_2", "organization_id": "org_2", "organization_name": "DataFlow Systems", "plan_id": "plan_ai_pro", "plan_name": "Professional", "tools": ["ai_agentic", "api_platform"], "amount": 248.0},
        {"id": "sub_3", "organization_id": "org_5", "organization_name": "Enterprise Solutions", "plan_id": "plan_mig_enterprise", "plan_name": "Enterprise", "tools": ["migration_tool", "api_platform"], "amount": 648.0},
    ]
    for s in subs_data:
        db.add(SubscriptionModel(id=s["id"], organization_id=s["organization_id"], organization_name=s["organization_name"], plan_id=s["plan_id"], plan_name=s["plan_name"], tools=json.dumps(s["tools"]), status="active", start_date=now - timedelta(days=15), end_date=now + timedelta(days=15), amount=s["amount"]))
        db.add(BillingModel(organization_id=s["organization_id"], organization_name=s["organization_name"], subscription_id=s["id"], amount=s["amount"], status="paid", invoice_number=f"INV-{now.strftime('%Y%m%d')}-{s['organization_id'][-4:].upper()}", billing_date=now - timedelta(days=15), due_date=now - timedelta(days=8), paid_date=now - timedelta(days=10), payment_method="card"))
    
    # Create roles
    roles_data = [
        {"id": "role_org1_admin", "name": "Admin", "organization_id": "org_1", "permissions": ["all"], "description": "Full access"},
        {"id": "role_org1_dev", "name": "Developer", "organization_id": "org_1", "permissions": ["read", "write", "test"], "description": "Development access"},
        {"id": "role_org2_admin", "name": "Admin", "organization_id": "org_2", "permissions": ["all"], "description": "Full access"},
        {"id": "role_org2_viewer", "name": "Viewer", "organization_id": "org_2", "permissions": ["read"], "description": "Read-only access"},
        {"id": "role_org5_admin", "name": "Admin", "organization_id": "org_5", "permissions": ["all"], "description": "Full access"},
    ]
    for r in roles_data:
        db.add(RoleModel(id=r["id"], name=r["name"], organization_id=r["organization_id"], permissions=json.dumps(r["permissions"]), description=r["description"]))
    
    # Create users
    users_data = [
        {"email": "john@techcorp.io", "name": "John Smith", "organization_id": "org_1", "organization_name": "TechCorp Inc", "role_id": "role_org1_admin", "role_name": "Admin"},
        {"email": "jane@techcorp.io", "name": "Jane Doe", "organization_id": "org_1", "organization_name": "TechCorp Inc", "role_id": "role_org1_dev", "role_name": "Developer"},
        {"email": "sarah@dataflow.dev", "name": "Sarah Chen", "organization_id": "org_2", "organization_name": "DataFlow Systems", "role_id": "role_org2_admin", "role_name": "Admin"},
        {"email": "tom@dataflow.dev", "name": "Tom Harris", "organization_id": "org_2", "organization_name": "DataFlow Systems", "role_id": "role_org2_viewer", "role_name": "Viewer"},
        {"email": "robert@enterprise-sol.com", "name": "Robert Wilson", "organization_id": "org_5", "organization_name": "Enterprise Solutions", "role_id": "role_org5_admin", "role_name": "Admin"},
    ]
    for u in users_data:
        db.add(UserModel(**u))
    
    # Create notifications
    notifs_data = [
        {"title": "New Organization Request", "message": "CloudNine Ltd has requested to join", "type": "info", "link": "/organizations/org_3"},
        {"title": "New Organization Request", "message": "StartupX has requested to join", "type": "info", "link": "/organizations/org_4"},
        {"title": "New Organization Request", "message": "InnovateTech has requested to join", "type": "info", "link": "/organizations/org_6"},
        {"title": "Subscription Renewed", "message": "TechCorp Inc subscription renewed", "type": "success"},
        {"title": "Payment Received", "message": "Payment of $648 from Enterprise Solutions", "type": "success"},
    ]
    for n in notifs_data:
        db.add(NotificationModel(**n))
    
    # Create org admins for approved organizations
    org_admins = [
        {"id": "admin_org_1", "email": "admin@techcorp.io", "name": "TechCorp Admin", "organization_id": "org_1", "organization_name": "TechCorp Inc"},
        {"id": "admin_org_2", "email": "admin@dataflow.dev", "name": "DataFlow Admin", "organization_id": "org_2", "organization_name": "DataFlow Systems"},
        {"id": "admin_org_5", "email": "admin@enterprise-sol.com", "name": "Enterprise Admin", "organization_id": "org_5", "organization_name": "Enterprise Solutions"},
    ]
    for oa in org_admins:
        db.add(AdminModel(
            id=oa["id"],
            email=oa["email"],
            password_hash=password_hash,  # Same password: admin123
            name=oa["name"],
            role="org_admin",
            organization_id=oa["organization_id"],
            organization_name=oa["organization_name"],
            created_by="admin_super_1"
        ))
    
    await db.commit()
    return {
        "message": "Seed data created successfully",
        "credentials": {
            "super_admin": {"email": "superadmin@probestack.io", "password": "admin123"},
            "org_admins": [
                {"email": "admin@techcorp.io", "password": "admin123", "organization": "TechCorp Inc"},
                {"email": "admin@dataflow.dev", "password": "admin123", "organization": "DataFlow Systems"},
                {"email": "admin@enterprise-sol.com", "password": "admin123", "organization": "Enterprise Solutions"}
            ]
        }
    }

# ==================== ROOT ROUTE ====================

@api_router.get("/")
async def root():
    return {"message": "ProbeStack Admin Dashboard API", "version": "1.0.0", "database": "MySQL"}

# ==================== PUBLIC API FOR EXTERNAL APPLICATIONS ====================

@api_router.post("/public/organizations/request", tags=["Public API"])
async def request_organization_subscription(data: OrganizationRequest, db: AsyncSession = Depends(get_db)):
    """
    Public API endpoint for external applications to submit organization subscription requests.
    
    This endpoint does NOT require authentication and is meant to be called by your main application
    when a new organization wants to subscribe to your services.
    
    **Request Body:**
    - `name`: Organization name (required)
    - `email`: Organization email (required)
    - `domain`: Company domain (optional)
    - `plan_id`: Plan ID to subscribe to (required) - e.g., 'plan_api_pro', 'plan_ai_starter'
    - `tools`: List of tools to access (required) - e.g., ['api_platform', 'ai_agentic']
    - `contact_person`: Primary contact name (required)
    - `contact_phone`: Contact phone number (optional)
    - `company_address`: Company address (optional)
    - `additional_notes`: Any additional notes (optional)
    
    **Available Tools:**
    - `api_platform` - API Development Platform
    - `ai_agentic` - AI Agentic API Development Platform
    - `migration_tool` - Migration Tool (Apigee Edge to X, etc.)
    
    **Returns:**
    - `request_id`: Unique ID for tracking the request
    - `status`: Current status ('pending')
    - `message`: Confirmation message
    """
    
    # Validate tools
    valid_tools = ['api_platform', 'ai_agentic', 'migration_tool']
    for tool in data.tools:
        if tool not in valid_tools:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid tool: {tool}. Valid tools are: {', '.join(valid_tools)}"
            )
    
    # Validate plan exists
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == data.plan_id))
    plan = plan_result.scalar_one_or_none()
    if not plan:
        # Get available plans
        plans_result = await db.execute(select(PlanModel.id, PlanModel.name, PlanModel.tool))
        available_plans = [{"id": p.id, "name": p.name, "tool": p.tool} for p in plans_result.all()]
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"Invalid plan_id: {data.plan_id}",
                "available_plans": available_plans
            }
        )
    
    # Check if organization with same email already exists
    existing = await db.execute(select(OrganizationModel).where(OrganizationModel.email == data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"An organization with email {data.email} already exists"
        )
    
    # Create organization request
    org = OrganizationModel(
        name=data.name,
        email=data.email,
        domain=data.domain,
        requested_plan=data.plan_id,
        requested_tools=json.dumps(data.tools),
        contact_person=data.contact_person,
        phone=data.contact_phone,
        address=data.company_address
    )
    db.add(org)
    
    # Create notification for admin
    notif = NotificationModel(
        title="New Organization Request",
        message=f"{data.name} has requested {plan.name} plan for {', '.join(data.tools)}",
        type="info",
        link=f"/pending-organizations"
    )
    db.add(notif)
    
    await db.commit()
    
    return {
        "request_id": org.id,
        "status": "pending",
        "message": f"Organization subscription request submitted successfully. Your request ID is {org.id}. An admin will review your request shortly.",
        "organization": {
            "name": data.name,
            "email": data.email,
            "plan": plan.name,
            "tools": data.tools
        }
    }


@api_router.get("/public/organizations/status/{request_id}", tags=["Public API"])
async def get_organization_request_status(request_id: str, db: AsyncSession = Depends(get_db)):
    """
    Check the status of an organization subscription request.
    
    **Path Parameter:**
    - `request_id`: The request ID returned when submitting the organization request
    
    **Returns:**
    - `status`: Current status ('pending', 'approved', 'rejected')
    - `organization_name`: Name of the organization
    - `requested_plan`: Plan requested
    - `rejection_reason`: Reason if rejected (only if status is 'rejected')
    """
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == request_id))
    org = result.scalar_one_or_none()
    
    if not org:
        raise HTTPException(status_code=404, detail="Organization request not found")
    
    response = {
        "request_id": org.id,
        "status": org.status,
        "organization_name": org.name,
        "requested_plan": org.requested_plan,
        "requested_tools": json.loads(org.requested_tools) if isinstance(org.requested_tools, str) else org.requested_tools,
        "submitted_at": org.created_at.isoformat() if org.created_at else None
    }
    
    if org.status == "approved":
        response["approved_at"] = org.approved_at.isoformat() if org.approved_at else None
    elif org.status == "rejected":
        response["rejected_at"] = org.rejected_at.isoformat() if org.rejected_at else None
        response["rejection_reason"] = org.rejection_reason
    
    return response


@api_router.get("/public/plans", tags=["Public API"])
async def get_available_plans(tool: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """
    Get all available subscription plans. This endpoint is public for external applications.
    
    **Query Parameter:**
    - `tool` (optional): Filter plans by tool ('api_platform', 'ai_agentic', 'migration_tool')
    
    **Returns:**
    List of available plans with pricing and features.
    """
    query = select(PlanModel).where(PlanModel.is_active == True)
    if tool:
        query = query.where(PlanModel.tool == tool)
    
    result = await db.execute(query.order_by(PlanModel.tool, PlanModel.price_monthly))
    plans = result.scalars().all()
    
    return {
        "plans": [
            {
                "id": p.id,
                "name": p.name,
                "tool": p.tool,
                "description": p.description,
                "features": json.loads(p.features) if isinstance(p.features, str) else p.features,
                "price_monthly": p.price_monthly,
                "price_yearly": p.price_yearly
            }
            for p in plans
        ],
        "tools": [
            {"id": "api_platform", "name": "API Development Platform"},
            {"id": "ai_agentic", "name": "AI Agentic API Development Platform"},
            {"id": "migration_tool", "name": "Migration Tool"}
        ]
    }


# ==================== PUBLIC API - USER REQUESTS ====================

@api_router.post("/public/users/request", tags=["Public API"])
async def request_user_addition(data: UserRequestCreate, db: AsyncSession = Depends(get_db)):
    """
    Public API endpoint for external applications to request adding a user to an organization.
    
    **Request Body:**
    - `email`: User's email address (required)
    - `name`: User's full name (required)
    - `organization_id`: Organization ID to add user to (required)
    - `requested_role`: Requested role name like 'Admin', 'Developer', 'Viewer' (required)
    - `job_title`: User's job title (optional)
    - `department`: User's department (optional)
    - `phone`: User's phone number (optional)
    - `notes`: Additional notes (optional)
    
    **Returns:**
    - `request_id`: Unique ID for tracking the request
    - `status`: Current status ('pending')
    - `message`: Confirmation message
    """
    
    # Validate organization exists and is approved
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == data.organization_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if org.status != "approved":
        raise HTTPException(status_code=400, detail="Organization is not approved yet")
    
    # Check if user with same email already exists in the organization
    existing_user = await db.execute(
        select(UserModel).where(
            UserModel.email == data.email,
            UserModel.organization_id == data.organization_id
        )
    )
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"User with email {data.email} already exists in this organization")
    
    # Check if there's already a pending request for this email in this org
    existing_request = await db.execute(
        select(UserRequestModel).where(
            UserRequestModel.email == data.email,
            UserRequestModel.organization_id == data.organization_id,
            UserRequestModel.status == "pending"
        )
    )
    if existing_request.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"A pending request for {data.email} already exists")
    
    # Create user request
    user_request = UserRequestModel(
        email=data.email,
        name=data.name,
        organization_id=data.organization_id,
        organization_name=org.name,
        requested_role=data.requested_role,
        job_title=data.job_title,
        department=data.department,
        phone=data.phone,
        notes=data.notes
    )
    db.add(user_request)
    
    # Create notification for admin
    notif = NotificationModel(
        title="New User Request",
        message=f"{data.name} ({data.email}) requested to join {org.name} as {data.requested_role}",
        type="info",
        link="/user-requests"
    )
    db.add(notif)
    
    await db.commit()
    
    return {
        "request_id": user_request.id,
        "status": "pending",
        "message": f"User addition request submitted successfully. Request ID: {user_request.id}",
        "user": {
            "name": data.name,
            "email": data.email,
            "organization": org.name,
            "requested_role": data.requested_role
        }
    }


@api_router.get("/public/users/status/{request_id}", tags=["Public API"])
async def get_user_request_status(request_id: str, db: AsyncSession = Depends(get_db)):
    """
    Check the status of a user addition request.
    
    **Path Parameter:**
    - `request_id`: The request ID returned when submitting the user request
    
    **Returns:**
    - `status`: Current status ('pending', 'approved', 'rejected')
    - `user_name`: Name of the user
    - `organization_name`: Organization name
    - `rejection_reason`: Reason if rejected (only if status is 'rejected')
    """
    result = await db.execute(select(UserRequestModel).where(UserRequestModel.id == request_id))
    req = result.scalar_one_or_none()
    
    if not req:
        raise HTTPException(status_code=404, detail="User request not found")
    
    response = {
        "request_id": req.id,
        "status": req.status,
        "user_name": req.name,
        "user_email": req.email,
        "organization_id": req.organization_id,
        "organization_name": req.organization_name,
        "requested_role": req.requested_role,
        "submitted_at": req.created_at.isoformat() if req.created_at else None
    }
    
    if req.status == "approved":
        response["approved_at"] = req.approved_at.isoformat() if req.approved_at else None
        response["assigned_role_id"] = req.approved_role_id
    elif req.status == "rejected":
        response["rejected_at"] = req.rejected_at.isoformat() if req.rejected_at else None
        response["rejection_reason"] = req.rejection_reason
    
    return response


@api_router.get("/public/organizations/{org_id}/roles", tags=["Public API"])
async def get_organization_roles(org_id: str, db: AsyncSession = Depends(get_db)):
    """
    Get available roles for an organization. External apps can use this to show role options.
    
    **Path Parameter:**
    - `org_id`: Organization ID
    
    **Returns:**
    List of available roles in the organization.
    """
    # Validate organization exists
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    result = await db.execute(select(RoleModel).where(RoleModel.organization_id == org_id))
    roles = result.scalars().all()
    
    return {
        "organization_id": org_id,
        "organization_name": org.name,
        "roles": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description
            }
            for r in roles
        ]
    }


# ==================== ADMIN API - USER REQUESTS MANAGEMENT ====================

@api_router.get("/user-requests", tags=["User Requests"])
async def get_user_requests(
    status: Optional[str] = None,
    organization_id: Optional[str] = None,
    payload: dict = Depends(verify_token),
    db: AsyncSession = Depends(get_db)
):
    """Get all user addition requests (admin only)"""
    query = select(UserRequestModel)
    if status:
        query = query.where(UserRequestModel.status == status)
    if organization_id:
        query = query.where(UserRequestModel.organization_id == organization_id)
    
    result = await db.execute(query.order_by(UserRequestModel.created_at.desc()))
    requests = result.scalars().all()
    
    return [model_to_dict(r) for r in requests]


@api_router.get("/user-requests/pending", tags=["User Requests"])
async def get_pending_user_requests(payload: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    """Get all pending user addition requests (admin only)"""
    result = await db.execute(
        select(UserRequestModel)
        .where(UserRequestModel.status == "pending")
        .order_by(UserRequestModel.created_at.desc())
    )
    return [model_to_dict(r) for r in result.scalars().all()]


@api_router.get("/user-requests/{request_id}", tags=["User Requests"])
async def get_user_request(request_id: str, payload: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    """Get a specific user request (admin only)"""
    result = await db.execute(select(UserRequestModel).where(UserRequestModel.id == request_id))
    req = result.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="User request not found")
    return model_to_dict(req)


@api_router.post("/user-requests/{request_id}/approve", tags=["User Requests"])
async def approve_user_request(
    request_id: str,
    role_id: str,
    payload: dict = Depends(verify_token),
    db: AsyncSession = Depends(get_db)
):
    """
    Approve a user addition request (admin only).
    
    **Query Parameter:**
    - `role_id`: The role ID to assign to the user
    """
    result = await db.execute(select(UserRequestModel).where(UserRequestModel.id == request_id))
    req = result.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="User request not found")
    if req.status != "pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    
    # Validate role exists and belongs to the organization
    role_result = await db.execute(
        select(RoleModel).where(RoleModel.id == role_id, RoleModel.organization_id == req.organization_id)
    )
    role = role_result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found in this organization")
    
    now = datetime.now(timezone.utc)
    
    # Update request status
    req.status = "approved"
    req.approved_at = now
    req.updated_at = now
    req.approved_role_id = role_id
    
    # Create the user
    user = UserModel(
        email=req.email,
        name=req.name,
        organization_id=req.organization_id,
        organization_name=req.organization_name,
        role_id=role_id,
        role_name=role.name
    )
    db.add(user)
    
    # Create notification
    notif = NotificationModel(
        title="User Request Approved",
        message=f"{req.name} has been added to {req.organization_name} as {role.name}",
        type="success"
    )
    db.add(notif)
    
    await db.commit()
    
    return {
        "message": "User request approved",
        "user_id": user.id,
        "user": {
            "name": user.name,
            "email": user.email,
            "organization": user.organization_name,
            "role": user.role_name
        }
    }


@api_router.post("/user-requests/{request_id}/reject", tags=["User Requests"])
async def reject_user_request(
    request_id: str,
    reason: str = "",
    payload: dict = Depends(verify_token),
    db: AsyncSession = Depends(get_db)
):
    """Reject a user addition request (admin only)"""
    result = await db.execute(select(UserRequestModel).where(UserRequestModel.id == request_id))
    req = result.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="User request not found")
    if req.status != "pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    
    now = datetime.now(timezone.utc)
    req.status = "rejected"
    req.rejected_at = now
    req.updated_at = now
    req.rejection_reason = reason
    
    # Create notification
    notif = NotificationModel(
        title="User Request Rejected",
        message=f"Request to add {req.name} to {req.organization_name} was rejected",
        type="warning"
    )
    db.add(notif)
    
    await db.commit()
    
    return {"message": "User request rejected"}


@api_router.delete("/user-requests/{request_id}", tags=["User Requests"])
async def delete_user_request(request_id: str, payload: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    """Delete a user request (admin only)"""
    result = await db.execute(delete(UserRequestModel).where(UserRequestModel.id == request_id))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="User request not found")
    await db.commit()
    return {"message": "User request deleted"}

# Include the router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

#@app.on_event("startup")
#async def startup():
#    async with engine.begin() as conn:
#        await conn.run_sync(Base.metadata.create_all)

@app.on_event("shutdown")
async def shutdown():
    await engine.dispose()
