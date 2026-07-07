from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, Text, Float, Boolean, DateTime, ForeignKey, select, delete, update, func, JSON, UniqueConstraint, text
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
import secrets
import smtplib
from email.message import EmailMessage
from html import escape

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
AUTH0_MGMT_DOMAIN = os.environ.get('AUTH0_MGMT_DOMAIN', 'probestack-usa-dev.us.auth0.com')
AUTH0_MGMT_CLIENT_ID = os.environ.get('AUTH0_MGMT_CLIENT_ID', '')
AUTH0_MGMT_CLIENT_SECRET = os.environ.get('AUTH0_MGMT_CLIENT_SECRET', '')
AUTH0_DB_CONNECTION_NAME = os.environ.get('AUTH0_DB_CONNECTION_NAME', 'Username-Password-Authentication')
AUTH0_DB_CONNECTION_ID = os.environ.get('AUTH0_DB_CONNECTION_ID', '')
AUTH0_CALLBACK_URI = "https://probestack.io/callback"
from urllib.parse import quote_plus

DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")
DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = os.environ.get("DB_PORT", "3306")
INSTANCE_CONNECTION_NAME = os.environ.get("INSTANCE_CONNECTION_NAME")

if DB_USER is None or DB_PASSWORD is None or DB_NAME is None:
    raise RuntimeError("Database environment variables not set")

DB_PASSWORD = quote_plus(DB_PASSWORD)

if INSTANCE_CONNECTION_NAME:
    DATABASE_URL = (
        f"mysql+asyncmy://{DB_USER}:{DB_PASSWORD}@/{DB_NAME}"
        f"?unix_socket=/cloudsql/{INSTANCE_CONNECTION_NAME}"
    )
else:
    DATABASE_URL = (
        f"mysql+asyncmy://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )

engine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=False,
    echo=False,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    expire_on_commit=False,
)

# JWT Config
JWT_SECRET = os.environ.get('JWT_SECRET', 'admin-dashboard-secret-key-2024')
JWT_ALGORITHM = "HS256"

# Application email config. When SMTP_HOST is not set, email sending is skipped
# and the generated setup link is returned/logged for local testing.
APP_URL = os.environ.get("APP_URL", "https://probestack.io")
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL") or SMTP_USERNAME
SMTP_FROM_NAME = os.environ.get("SMTP_FROM_NAME", "ProbeStack")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in ["1", "true", "yes"]

# Create the main app
app = FastAPI()

api_router = APIRouter(prefix="/admin-backend/api")
security = HTTPBearer()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Auth0ManagementAPI:
    """Helper class for Auth0 Management API operations"""
    if not all([
        AUTH0_MGMT_CLIENT_ID,
        AUTH0_MGMT_CLIENT_SECRET,
        AUTH0_MGMT_DOMAIN,
    ]):
        raise RuntimeError("Auth0 Management API env vars missing")
    
    def __init__(self):
        self.domain = AUTH0_MGMT_DOMAIN
        self.client_id = AUTH0_MGMT_CLIENT_ID
        self.client_secret = AUTH0_MGMT_CLIENT_SECRET
        self.connection = AUTH0_DB_CONNECTION_NAME
        self.connection_id = AUTH0_DB_CONNECTION_ID
        self._access_token = None
        self._token_expires_at = None
    
    async def _get_access_token(self) -> str:
        """Get or refresh Management API access token"""
        if self._access_token and self._token_expires_at and datetime.now() < self._token_expires_at:
            return self._access_token
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://{self.domain}/oauth/token",
                json={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "audience": f"https://{self.domain}/api/v2/",
                    "grant_type": "client_credentials"
                }
            )
            
            if response.status_code != 200:
                logger.error(f"Auth0 token error: {response.text}")
                raise HTTPException(status_code=500, detail="Failed to get Auth0 Management API token")
            
            data = response.json()
            self._access_token = data["access_token"]
            self._token_expires_at = datetime.now() + timedelta(seconds=data.get("expires_in", 86400) - 300)
            return self._access_token
    
    async def create_user(self, email: str, name: str, user_metadata: dict = None) -> dict:
        """Create a new user in Auth0 with no password (user will set it later)"""
        token = await self._get_access_token()
        
        temp_password = secrets.token_urlsafe(32) + "Aa1!"
        
        payload = {
            "email": email,
            "name": name,
            "connection": self.connection,
            "password": temp_password,
            "email_verified": False,
            "verify_email": True,
            "user_metadata": user_metadata or {}
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://{self.domain}/api/v2/users",
                headers={"Authorization": f"Bearer {token}"},
                json=payload
            )
            
            if response.status_code == 201:
                user_data = response.json()
                logger.info(f"Auth0 user created: {email}")
                return {"success": True, "auth0_user_id": user_data.get("user_id"), "data": user_data}
            elif response.status_code == 409:
                logger.warning(f"Auth0 user already exists: {email}")
                return {"success": False, "error": "User already exists in Auth0", "exists": True}
            else:
                logger.error(f"Auth0 create user error: {response.text}")
                return {"success": False, "error": response.text}
    
    async def get_user_by_email(self, email: str) -> dict:
        """Get user from Auth0 by email"""
        token = await self._get_access_token()
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://{self.domain}/api/v2/users-by-email",
                headers={"Authorization": f"Bearer {token}"},
                params={"email": email}
            )
            
            if response.status_code == 200:
                users = response.json()
                if users:
                    return {"success": True, "user": users[0]}
                return {"success": False, "error": "User not found"}
            else:
                logger.error(f"Auth0 get user error: {response.text}")
                return {"success": False, "error": response.text}
    
    async def update_user_password(self, user_id: str, password: str) -> dict:
        """Update user's password in Auth0"""
        token = await self._get_access_token()
        
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"https://{self.domain}/api/v2/users/{user_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"password": password, "connection": self.connection}
            )
            
            if response.status_code == 200:
                logger.info(f"Auth0 password updated for user: {user_id}")
                return {"success": True}
            else:
                logger.error(f"Auth0 update password error: {response.text}")
                return {"success": False, "error": response.text}
    
    async def verify_user_email(self, user_id: str) -> dict:
        """Mark user's email as verified in Auth0"""
        token = await self._get_access_token()
        
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"https://{self.domain}/api/v2/users/{user_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"email_verified": True}
            )
            
            if response.status_code == 200:
                logger.info(f"Auth0 email verified for user: {user_id}")
                return {"success": True}
            else:
                logger.error(f"Auth0 verify email error: {response.text}")
                return {"success": False, "error": response.text}
    
    async def send_verification_email(self, user_id: str) -> dict:
        """Send verification email to user"""
        token = await self._get_access_token()
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://{self.domain}/api/v2/jobs/verification-email",
                headers={"Authorization": f"Bearer {token}"},
                json={"user_id": user_id}
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Auth0 verification email sent to user: {user_id}")
                return {"success": True}
            else:
                logger.error(f"Auth0 send verification email error: {response.text}")
                return {"success": False, "error": response.text}
    
    async def send_password_reset_email(self, email: str) -> dict:
        """Send password reset email to user via Auth0"""
        # IMPORTANT: Must use the regular Auth0 application client_id (AUTH0_CLIENT_ID),
        # NOT the Management API client_id
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://{self.domain}/dbconnections/change_password",
                json={
                    "client_id": AUTH0_CLIENT_ID,  # Use regular app client ID, not management API client ID
                    "email": email,
                    "connection": self.connection
                }
            )
            
            if response.status_code == 200:
                logger.info(f"Auth0 password reset email sent to: {email}")
                return {"success": True}
            else:
                logger.error(f"Auth0 send password reset email error: {response.text}")
                return {"success": False, "error": response.text}
    
    async def authenticate_user(self, email: str, password: str) -> dict:
        """
        Authenticate a user against Auth0.
        Uses the Resource Owner Password Grant flow.
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://{self.domain}/oauth/token",
                json={
                    "grant_type": "password",
                    "username": email,
                    "password": password,
                    "client_id": AUTH0_CLIENT_ID,
                    "client_secret": AUTH0_CLIENT_SECRET,
                    "audience": "https://probestack.io/api",
                    "scope": "openid profile email",
                    "realm": self.connection
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Auth0 authentication successful for: {email}")
                return {
                    "success": True,
                    "access_token": data.get("access_token"),
                    "id_token": data.get("id_token"),
                    "token_type": data.get("token_type")
                }
            else:
                logger.warning(f"Auth0 authentication failed for {email}: {response.text}")
                return {"success": False, "error": response.text}

# Initialize Auth0 Management API helper
auth0_mgmt = Auth0ManagementAPI()

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
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    external_org_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, unique=True) 
    supported_domains: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    auth0_org_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    gateway_region: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    gateway_organization_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    gateway_environment_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    gateway_environments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class SubscriptionModel(Base):
    __tablename__ = "subscriptions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Deprecated display cache
    plan_id: Mapped[str] = mapped_column(String(100), nullable=False)
    plan_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Deprecated display cache
    tools: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    status: Mapped[str] = mapped_column(String(50), default="active")
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    billing_cycle: Mapped[str] = mapped_column(String(50), default="monthly")
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class SubscriptionToolModel(Base):
    """Normalized selected tools for a subscription."""
    __tablename__ = "subscription_tools"
    __table_args__ = (
        UniqueConstraint("subscription_id", "plan_tool_id", name="uq_subscription_tools_plan_tool"),
        UniqueConstraint("subscription_id", "tool_key", name="uq_subscription_tools_tool_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    subscription_id: Mapped[str] = mapped_column(String(36), ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False)
    plan_tool_id: Mapped[str] = mapped_column(String(36), ForeignKey("plan_tools.id", ondelete="RESTRICT"), nullable=False)
    tool_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class ProductModel(Base):
    __tablename__ = "products"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    display_order: Mapped[int] = mapped_column(default=0)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class PlanModel(Base):
    __tablename__ = "plans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    product_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    tool: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    features: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    price_monthly: Mapped[float] = mapped_column(Float, nullable=False)
    price_yearly: Mapped[float] = mapped_column(Float, nullable=False)
    price_label: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    billing_period: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    api_limit: Mapped[int] = mapped_column(default=0)
    cost: Mapped[float] = mapped_column(Float, default=0)
    is_popular: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class PlanToolModel(Base):
    """Model for individual tools within a plan."""
    __tablename__ = "plan_tools"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    plan_id: Mapped[str] = mapped_column(String(36), nullable=False)  # FK to plans
    name: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., "API Design Studio"
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    price_monthly: Mapped[float] = mapped_column(Float, default=0)  # Deprecated compatibility field
    price_yearly: Mapped[float] = mapped_column(Float, default=0)  # Deprecated compatibility field
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    display_order: Mapped[int] = mapped_column(default=0)  # For ordering tools in UI
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class UserModel(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Deprecated display cache
    role_id: Mapped[str] = mapped_column(String(36), nullable=False)
    role_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Deprecated display cache
    status: Mapped[str] = mapped_column(String(50), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    theme_preference: Mapped[str] = mapped_column(String(20), default="system")  # light, dark, system
    # Auth0 integration fields
    auth0_user_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Auth0 user ID
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)  # Email verification status
    password_set: Mapped[bool] = mapped_column(Boolean, default=False)  # Has user set their password
    first_login_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

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
    organization_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Deprecated display cache
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
    organization_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Deprecated display cache
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
    approved_business_unit_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    approved_project_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    approved_project_role: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

class IndividualUserRequestModel(Base):
    """Model for individual user requests (users without organization)"""
    __tablename__ = "individual_user_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_tools: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array of tools
    requested_plan: Mapped[str] = mapped_column(String(100), nullable=False)
    purpose: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Why they need access
    company_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Optional company name
    job_title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, approved, rejected
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # When approved, these fields are populated
    assigned_user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    assigned_subscription_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

class PlanUpgradeRequestModel(Base):
    """Model for plan upgrade requests from organization admins"""
    __tablename__ = "plan_upgrade_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Deprecated display cache
    current_plan_id: Mapped[str] = mapped_column(String(100), nullable=False)  # JSON array of current plan IDs
    current_plan_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Deprecated display cache
    # Old single-plan columns (for backward compatibility)
    requested_plan_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    requested_plan_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # New multi-plan columns
    requested_plan_ids: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array of plan IDs
    requested_plans_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: [{plan_id, plan_name, tools}]
    requested_tools: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array (all tools combined)
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, approved, rejected
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Why they want to upgrade
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    requested_by: Mapped[str] = mapped_column(String(36), nullable=False)  # Admin who requested

class PlanUpgradeRequestItemModel(Base):
    """Normalized requested plan rows for plan upgrade requests."""
    __tablename__ = "plan_upgrade_request_items"
    __table_args__ = (
        UniqueConstraint("request_id", "plan_id", name="uq_upgrade_request_items_request_plan"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id: Mapped[str] = mapped_column(String(36), ForeignKey("plan_upgrade_requests.id", ondelete="CASCADE"), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(36), ForeignKey("plans.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class PlanUpgradeRequestToolModel(Base):
    """Normalized selected tools for a requested upgrade plan."""
    __tablename__ = "plan_upgrade_request_tools"
    __table_args__ = (
        UniqueConstraint("request_item_id", "plan_tool_id", name="uq_upgrade_request_tools_plan_tool"),
        UniqueConstraint("request_item_id", "tool_key", name="uq_upgrade_request_tools_tool_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_item_id: Mapped[str] = mapped_column(String(36), ForeignKey("plan_upgrade_request_items.id", ondelete="CASCADE"), nullable=False)
    plan_tool_id: Mapped[str] = mapped_column(String(36), ForeignKey("plan_tools.id", ondelete="RESTRICT"), nullable=False)
    tool_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class OrganizationSubscriptionRequestModel(Base):
    """Normalized plan request for organization onboarding."""
    __tablename__ = "organization_subscription_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rejected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

class OrganizationSubscriptionRequestItemModel(Base):
    """Normalized requested plans for organization onboarding."""
    __tablename__ = "organization_subscription_request_items"
    __table_args__ = (
        UniqueConstraint("request_id", "plan_id", name="uq_org_subscription_request_items_request_plan"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id: Mapped[str] = mapped_column(String(36), ForeignKey("organization_subscription_requests.id", ondelete="CASCADE"), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(36), ForeignKey("plans.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class OrganizationSubscriptionRequestToolModel(Base):
    """Normalized selected tools for organization onboarding request plans."""
    __tablename__ = "organization_subscription_request_tools"
    __table_args__ = (
        UniqueConstraint("request_item_id", "plan_tool_id", name="uq_org_subscription_request_tools_plan_tool"),
        UniqueConstraint("request_item_id", "tool_key", name="uq_org_subscription_request_tools_tool_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_item_id: Mapped[str] = mapped_column(String(36), ForeignKey("organization_subscription_request_items.id", ondelete="CASCADE"), nullable=False)
    plan_tool_id: Mapped[str] = mapped_column(String(36), ForeignKey("plan_tools.id", ondelete="RESTRICT"), nullable=False)
    tool_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Auth0LoginRecordModel(Base):
    """Model for storing Auth0 login records"""
    __tablename__ = "auth0_login_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Deprecated display cache
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

class BusinessUnitModel(Base):
    """Business units owned by an approved organization."""
    __tablename__ = "business_units"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_business_units_org_name"),
        UniqueConstraint("organization_id", "code", name="uq_business_units_org_code"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    code: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    application_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    application_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    owner_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    go_live_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    members_count: Mapped[int] = mapped_column(default=0)
    consumers_count: Mapped[int] = mapped_column(default=0)
    project_sme: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tester: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    servicenow_group: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sync_status: Mapped[str] = mapped_column(String(50), default="synced")
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active")
    created_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("admins.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class ProjectModel(Base):
    """Projects owned by an approved organization, optionally under a Business unit."""
    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_projects_org_name"),
        UniqueConstraint("organization_id", "code", name="uq_projects_org_code"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    business_unit_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("business_units.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    code: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active")
    created_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("admins.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class ProjectTeamMemberModel(Base):
    """Project-scoped team invitations and memberships."""
    __tablename__ = "project_team_members"
    __table_args__ = (
        UniqueConstraint("project_id", "email", name="uq_project_team_members_project_email"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    project_role: Mapped[str] = mapped_column(String(50), default="member")
    status: Mapped[str] = mapped_column(String(50), default="invited")
    invited_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("admins.id", ondelete="SET NULL"), nullable=True)
    invited_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    accepted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

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

class PlanSelectionItem(BaseModel):
    """Schema for a single plan selection with its tools"""
    plan_id: str
    tool_ids: List[str]  # List of tool IDs/names for this plan

class PlanUpgradeCreate(BaseModel):
    """Schema for org admin to request plan upgrade - supports multiple plans"""
    requested_plans: Optional[List[PlanSelectionItem]] = None  # Multiple plans with their tools
    requested_plan_id: Optional[str] = None  # Backward-compatible single-plan payload
    requested_tools: Optional[List[str]] = None  # Backward-compatible single-plan payload
    reason: Optional[str] = None

class SubscriptionUpdateRequest(BaseModel):
    """Schema for super admin to update org/user subscription"""
    plan_selections: List[PlanSelectionItem]  # Plans with their tools
    billing_cycle: Optional[str] = "monthly"  # monthly or yearly

class OrganizationCreate(BaseModel):
    name: str
    email: str
    domain: Optional[str] = None
    requested_plans: List[str]
    requested_tools: List[str]
    contact_person: str
    phone: Optional[str] = None
    address: Optional[str] = None
    description: Optional[str] = None
    gateway_region: Optional[str] = None
    gateway_organization_name: Optional[str] = None
    gateway_environment_type: Optional[str] = None
    gateway_environments: Optional[List[str]] = None

class OrganizationRequest(BaseModel):
    """Schema for external API requests to register an organization"""
    name: str
    email: str
    domain: Optional[str] = None
    plan_ids: List[str]  # List of Plan IDs like ["plan_api_enterprise", "plan_ai_enterprise"]
    selected_tools: List[str]
    contact_person: str
    contact_phone: Optional[str] = None
    company_address: Optional[str] = None
    additional_notes: Optional[str] = None
    description: Optional[str] = None
    gateway_region: Optional[str] = None
    gateway_organization_name: Optional[str] = None
    gateway_environment_type: Optional[str] = None
    gateway_environments: Optional[List[str]] = None

class OrganizationUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    domain: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    external_org_id: Optional[str] = None
    supported_domains: Optional[List[str]] = None
    auth0_org_id: Optional[str] = None  # Auth0 organization ID
    gateway_region: Optional[str] = None
    gateway_organization_name: Optional[str] = None
    gateway_environment_type: Optional[str] = None
    gateway_environments: Optional[List[str]] = None

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

class UserContextTokenRequest(BaseModel):
    """Request to issue a ProbeStack user-context token after probestack.io login."""
    email: Optional[str] = None
    auth0_user_id: Optional[str] = None
    id_token: Optional[str] = None

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

class IndividualUserRequestCreate(BaseModel):
    """Schema for creating individual user request (no organization)"""
    email: str
    name: str
    selected_tools: List[str]
    requested_plans: List[str]  # Plan ID
    purpose: Optional[str] = None  # Why they need access
    company_name: Optional[str] = None
    job_title: Optional[str] = None
    phone: Optional[str] = None

class ProductCreate(BaseModel):
    name: str
    key: Optional[str] = None
    description: Optional[str] = None
    display_order: int = 0
    is_active: bool = True

class ProductUpdate(BaseModel):
    name: Optional[str] = None
    key: Optional[str] = None
    description: Optional[str] = None
    display_order: Optional[int] = None
    is_active: Optional[bool] = None

class PlanCreate(BaseModel):
    name: str
    product_id: str
    description: str
    features: List[str]
    price_monthly: Optional[float] = None
    price_yearly: Optional[float] = None
    price_label: Optional[str] = None
    billing_period: Optional[str] = None
    api_limit: int = 0
    cost: float = 0
    is_popular: bool = False

class PlanToolCreate(BaseModel):
    """Schema for creating a tool within a plan"""
    name: str
    description: Optional[str] = None
    price_monthly: float = 0
    price_yearly: float = 0
    display_order: int = 0

class PlanToolUpdate(BaseModel):
    """Schema for updating a tool within a plan"""
    name: Optional[str] = None
    description: Optional[str] = None
    price_monthly: Optional[float] = None
    price_yearly: Optional[float] = None
    is_active: Optional[bool] = None
    display_order: Optional[int] = None

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

class BusinessUnitCreate(BaseModel):
    name: str
    code: Optional[str] = None
    description: Optional[str] = None
    application_name: Optional[str] = None
    application_id: Optional[str] = None
    owner_name: Optional[str] = None
    go_live_date: Optional[datetime] = None
    members_count: int = 0
    consumers_count: int = 0
    project_sme: Optional[str] = None
    tester: Optional[str] = None
    servicenow_group: Optional[str] = None
    last_synced_at: Optional[datetime] = None
    sync_status: Optional[str] = "synced"
    tags: List[str] = []
    status: Optional[str] = "active"

class BusinessUnitUpdate(BaseModel):
    name: Optional[str] = None
    code: Optional[str] = None
    description: Optional[str] = None
    application_name: Optional[str] = None
    application_id: Optional[str] = None
    owner_name: Optional[str] = None
    go_live_date: Optional[datetime] = None
    members_count: Optional[int] = None
    consumers_count: Optional[int] = None
    project_sme: Optional[str] = None
    tester: Optional[str] = None
    servicenow_group: Optional[str] = None
    last_synced_at: Optional[datetime] = None
    sync_status: Optional[str] = None
    tags: Optional[List[str]] = None
    status: Optional[str] = None

class ProjectCreate(BaseModel):
    name: str
    business_unit_id: Optional[str] = None
    code: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = "active"

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    business_unit_id: Optional[str] = None
    code: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None

class ProjectTeamInviteCreate(BaseModel):
    emails: List[str]
    project_role: Optional[str] = "member"

class ExternalProjectCreate(BaseModel):
    name: str
    business_unit_id: str
    code: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = "active"

# ==================== HELPERS ====================

async def sync_user_from_auth0(
    user: UserModel,
    db: AsyncSession,
    *,
    allow_password_sync: bool = True,
    allow_status_activation: bool = True
) -> bool:
    """
    Synchronize user state from Auth0 into local DB.

    Rules:
    - Auth0 is source of truth for email_verified
    - If Auth0 has email_verified=True → DB is updated
    - If Auth0 user exists → password_set=True
    - Clears first_login_token when account becomes active
    - Safe to call multiple times (idempotent)

    Returns:
        True  -> user state was changed
        False -> no changes
    """

    # No Auth0 user → nothing to sync
    if not user.auth0_user_id:
        return False

    try:
        auth0_result = await auth0_mgmt.get_user_by_email(user.email)
    except Exception as e:
        logger.warning(f"Auth0 sync skipped for {user.email}: {e}")
        return False

    if not auth0_result.get("success"):
        return False

    auth0_user = auth0_result.get("user", {})
    updated = False

    # ----------------------------
    # Email verification sync
    # ----------------------------
    auth0_email_verified = auth0_user.get("email_verified")

    if auth0_email_verified and not user.email_verified:
        user.email_verified = True
        updated = True

    # ----------------------------
    # Password existence sync
    # ----------------------------
    # If Auth0 user exists, password must exist
    if allow_password_sync and not user.password_set:
        user.password_set = True
        updated = True

    # ----------------------------
    # Status activation
    # ----------------------------
    if (
        allow_status_activation
        and user.email_verified
        and user.password_set
        and user.status != "active"
    ):
        user.status = "active"
        updated = True

    # ----------------------------
    # Cleanup first-login token
    # ----------------------------
    if user.status == "active" and user.first_login_token:
        user.first_login_token = None
        updated = True

    if updated:
        await db.commit()

    return updated


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

async def get_organization_name(db: AsyncSession, organization_id: Optional[str], fallback: Optional[str] = None) -> Optional[str]:
    if not organization_id:
        return fallback
    result = await db.execute(select(OrganizationModel.name).where(OrganizationModel.id == organization_id))
    return result.scalar_one_or_none() or fallback

async def get_role_name(db: AsyncSession, role_id: Optional[str], fallback: Optional[str] = None) -> Optional[str]:
    if not role_id:
        return fallback
    result = await db.execute(select(RoleModel.name).where(RoleModel.id == role_id))
    return result.scalar_one_or_none() or fallback

async def get_plan_name(db: AsyncSession, plan_id: Optional[str], fallback: Optional[str] = None) -> Optional[str]:
    if not plan_id:
        return fallback
    try:
        plan_ids = json.loads(plan_id) if isinstance(plan_id, str) and plan_id.startswith("[") else [plan_id]
    except (json.JSONDecodeError, TypeError):
        plan_ids = [plan_id]
    plan_ids = [pid for pid in plan_ids if pid]
    if not plan_ids:
        return fallback
    result = await db.execute(select(PlanModel).where(PlanModel.id.in_(plan_ids)))
    names = [plan.name for plan in result.scalars().all()]
    return ", ".join(names) if names else fallback

def parse_json_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else [parsed]
        except (json.JSONDecodeError, TypeError):
            return [value] if value else []
    return [value]

DEFAULT_PRODUCTS = [
    {"id": "prod_forgeshift", "key": "forgeshift", "name": "ForgeShift - Gateway Migration", "description": "Automated migration and transformation of API proxies across disparate gateway environments.", "display_order": 10},
    {"id": "prod_forgestudio", "key": "forgestudio", "name": "ForgeStudio - API Design", "description": "Powerful API design and development studio for modern collaborative teams.", "display_order": 20},
    {"id": "prod_forgeq", "key": "forgeq", "name": "ForgeQ - API, MCP & AI Testing", "description": "Automated API, MCP & AI testing, SDK, quality assurance, and mock server generation playground.", "display_order": 30},
    {"id": "prod_forgesphere", "key": "forgesphere", "name": "ForgeSphere - API Development Lifecycle", "description": "Centralized API Lifecycle generation, observability, logging, and comprehensive analytics for your API ecosystem.", "display_order": 40},
    {"id": "prod_forgeai", "key": "forgeai", "name": "ForgeAi - AI Gateway", "description": "AI Gateway to monitor, secure, and route your LLM & AI provider traffic seamlessly.", "display_order": 50},
    {"id": "prod_agentic_ai", "key": "agentic_ai", "name": "Agentic AI Platform", "description": "End-to-end intelligent agent workflow orchestration and autonomous task execution.", "display_order": 60},
]

DEFAULT_PRICING_CATALOG = [
    {
        "product_key": "forgeshift",
        "plans": [
            {"id": "plan_forgeshift_starter", "name": "Starter", "price": "$0", "period": "/mo", "description": "Basic migration tools for small teams.", "features": ["Up to 10 migrations", "Basic UI access", "Email support"]},
            {"id": "plan_forgeshift_enterprise_plus", "name": "Enterprise - Plus", "price": "Contact Sales", "period": None, "description": "Comprehensive migration support.", "features": ["100% automated migration & cutover with ZERO DOWNTIME", "Unlimited Proxy & Resources migration", "Unlimited User & Role Migration", "Developer Portal Migration", "Integrated inbuilt Proxy Editor with AI enabled", "100% Customized product", "Migration support Env to Env & Hybrid", "Integrated Cloud Storage, Github, CICD, SSO", "Integrated with Advance complience", "Dedicated PS & migration team", "Advanced Dashbord with Report and Alert", "8*5 support + SLA", "Contact sales : info@probestack.io"]},
        ],
    },
    {
        "product_key": "forgestudio",
        "plans": [
            {"id": "plan_forgestudio_starter", "name": "Starter", "price": "$0", "period": "/month/user", "description": "Ideal for small API teams.", "features": ["1 user, 2 API (public only), 1 Project", "OpenAPI editor (YAML/JSON)", "Visual OpenAPI designer", "5 Contract Testing", "API Linting", "Interactive API documentation", "OpenAPI + JSON Schema", "Community support"]},
            {"id": "plan_forgestudio_enterprise", "name": "Enterprise", "price": "$40", "period": "/month/user", "description": "Advanced collaboration.", "popular": True, "features": ["Included Starter Features", "Private APIs & Projects", "Collaboration (multi-user editing)", "Cloning, Versioning & Governance rules", "API style validation using Linting", "Model Schema Mapping", "CICD & Connectors integrations", "Team access with 5 users", "50 Contracts Testing", "SDK / Advanced Linting", "Email support"]},
            {"id": "plan_forgestudio_enterprise_plus", "name": "Enterprise - Plus", "price": "Contact Sales", "period": None, "description": "Dedicated Enterprise for scale.", "features": ["Includes Enterprise", "Available both SaaS/Self Hosted", "Unlimited users", "Unlimited API Design", "SSO (SAML/LDAP)", "Organization, Project & Team management", "Audit logs (compliance)", "Role-based access control", "Advanced templates & governance", "Specification Library", "AI-native tools (trend): Generate APIs, CICD enabled from prompts, AI validation rules, AI security/compliance scanning, Auto-create OpenAPI specs from APIs, Auto-generate test cases", "Contract/Functional Testing", "Dedicated infrastructure", "Advanced Dashboard", "24/7 support"]},
        ],
    },
    {
        "product_key": "forgeq",
        "plans": [
            {"id": "plan_forgeq_starter", "name": "Starter", "price": "$0", "period": "/month/user", "description": "Basic testing capabilities.", "features": ["Standard API testing", "API requests (REST, GraphQL)", "Collections Testing", "Environment variables", "Basic testing scripts", "Limited collaboration", "Offline-first API testing", "Monitoring", "Email support"]},
            {"id": "plan_forgeq_enterprise", "name": "Enterprise", "price": "$30", "period": "/month/user", "description": "Comprehensive API & MCP testing.", "popular": True, "features": ["Includes Starter", "API , MCP & Collections Testing", "Web Application Testing", "Projects & Team Managemnet", "Mock servers", "Git sync", "CI/CD integration", "Monitoring + automation", "Email support"]},
            {"id": "plan_forgeq_enterprise_plus", "name": "Enterprise - Plus", "price": "Contact Sales", "period": None, "description": "Advanced API, UI, MCP & AI testing.", "features": ["Includes Enterprise", "Includes Enterprise", "SSO & Role-based access", "Enterprise sync", "Audit logs", "Unlimited runs", "Load /PerformanceTesting", "Monitoring + analytics", "API stress testing", "API governance", "API Security Testing", "AI debugging + auto-fix", "Integrated  all AI models", "AI generate Testcase", "AI updates tests automatically", "Test data generation", "Zero manual test writing", "Simulate failures", "Latency injection", "LLM Model Testing (Coming Soon)", "Agentic AI Testing (Coming Soon)", "Record & replay testing (Coming Soon)", "24/7 support", "Contact sales : info@probestack.io"]},
        ],
    },
    {
        "product_key": "forgesphere",
        "plans": [
            {"id": "plan_forgesphere_starter", "name": "Starter", "price": "$50", "period": "/month/user", "description": "Basic API Lifecycle.", "features": ["Up to 50 Microservice & APIs Proxies", "Java Springboot API Generation, View & Edit", "Python API Generation, View & Edit", "NodeJS API Generation, View & Edit", "APIGEE Proxy Generation, View & Edit", "API Deploy to GCP ", "API Design", "Mock service Generation", "Contract Testing", "TestCase generation", "Integrated CICD for API and Proxy Deployment", "Automation Functional Testing", "Automation Unit Testing", "Security Testing", "Support Artifctory Registry ", "Support Github Action ", "Integrated with Cloud connectors AWS, GCP , Azure , Github, Action, Cloud Storage, Apigee, API Linting Connectors ", "Integrated with SCM connectors Github, Github Action, API Linting Connectors ", "Integrated with Cloud Storage connectors GCS, S3, API Linting Connectors ", "Integrated with API Gateway connectors Apigee Connectors ", "15-day log retention", "Standard dashboards", "Email Support"]},
            {"id": "plan_forgesphere_enterprise", "name": "Enterprise", "price": "$150", "period": "/month/user", "description": "Advanced API Lifecycle.", "popular": True, "features": ["Includes Starter", "Java Springboot API Generation, View, Edit, Clone & Versioning", "Python API Generation, View, Edit, Clone & Versioning", "NodeJS API Generation, View, Edit, Clone & Versioning", "APIGEE Proxy Generation, View, Edit, Clone & Versioning", "KONG Service Generation, View, Edit, Clone & Versioning", "MULESOFT Api Generation, View, Edit, Clone & Versioning", "API Deploy to GCP, Azure & AWS ", "API Proxy Deploy to Apigee, Kong & Mulesoft", "API Design", "Mock service Generation", "Contract Testing", "TestCase generation", "Integrated CICD for API and Proxy Deployment", "Automation Functional Testing", "Automation Unit Testing", "Security Testing", "Support Artifctory Registry ", "Support Github Action ", "API Governance ", "Integrated CICD for API and Proxy Deployment", "Integrated with Cloud connectors AWS, GCP , Azure Connectors ", "Integrated with SCM connectors Github, Github Action, API Linting Connectors ", "Integrated with Cloud Storage connectors GCS, S3, API Linting Connectors ", "Integrated with API Gateway connectors Apigee, Kong , Mulesoft Connectors ", "30-day log retention", "Standard dashboards", "Priority support"]},
            {"id": "plan_forgesphere_enterprise_plus", "name": "Enterprise - Plus", "price": "Contact Sales", "period": None, "description": "Unlimited scaled API Lifecycle.", "features": ["Includes Enterprise ", "SSO & Role-based access", "MCP Generation, View, Edit, Clone , Versioning & Deprecation", "MCP Expose to Apigee MCP Gateway", "Audit logs", "Java Springboot API Generation, View, Edit, Clone , Versioning & Deprecation", "Python API Generation, View, Edit, Clone , Versioning & Deprecation", "NodeJS API Generation, View, Edit, Clone , Versioning & Deprecation", "APIGEE Proxy Generation, View, Edit, Clone , Versioning & Deprecation", "KONG Service Generation, View, Edit, Clone , Versioning & Deprecation", "MULESOFT Api Generation, View, Edit, Clone , Versioning & Deprecation", "Apigee Proxy Editor, Debug and Trace ", "Kong Service Editor, Debug and Trace", "One Click for higher environmnet Deployment", "API Advance Governance ", "AI-native tools (trend): Generate Microservice , Proxy & CICD enabled from prompts, AI validation rules, AI security/compliance scanning, Auto-create OpenAPI specs from APIs,Auto-generate test cases", "Advanced Dashboard", "Advanced Analytics", "8*5 Support", "Contact sales : info@probestack.io"]},
        ],
    },
    {
        "product_key": "forgeai",
        "plans": [
            {"id": "plan_forgeai_starter", "name": "Starter", "price": "$3,500", "period": "/month", "description": "Advanced AI traffic routing & observability.", "features": ["Up to 200K API Calls/mo", "Advanced AI Gateway features", "OpenAI, Anthropic, Google LLM Models", "Multi-provider LLM routing with 3 Envs", "Gateway Dashboard with 30days log.", "Rate limiting & throttling", "API key management", "Request/response logging", "Email support"]},
            {"id": "plan_forgeai_enterprise", "name": "Enterprise", "price": "$9,500", "period": "/month", "description": "Advanced AI traffic routing & observability.", "popular": True, "features": ["Up to 3M API Calls/mo & SSO / SAML integration", "Caching & semantics", "Cost allocation & per-team budgets", "PII redaction & content filtering", "Prompt injection detection", "Latency & token analytics dashboard", "Priority support"]},
            {"id": "plan_forgeai_enterprise_plus", "name": "Enterprise - Plus", "price": "Contact Sales", "period": None, "description": "Advanced AI traffic routing & observability.", "features": ["Unlimited tokens", "Dedicated Infrastructure", "Custom model adapters & self-hosted LLMs", "99.99% uptime SLA + dedicated support", "Fine-grained RBAC per team/model", "Private deployment (air-gapped available)", "Contact sales : info@probestack.io", "24/7 support"]},
        ],
    },
    {
        "product_key": "agentic_ai",
        "plans": [
            {"id": "plan_agentic_ai_starter", "name": "Starter", "price": "$0", "period": "/month/user", "description": "Explore autonomous agents.", "features": ["Up to 10 autonomous agents", "Basic RAG", "Email support"]},
            {"id": "plan_agentic_ai_enterprise", "name": "Enterprise", "price": "$100", "period": "/month/user", "description": "Explore autonomous agents.", "features": ["Up to 10 autonomous agents", "Basic RAG", "Email support"]},
            {"id": "plan_agentic_ai_enterprise_plus", "name": "Enterprise - Plus", "price": "Contact Sales", "period": "/ 200 Users", "description": "Unlimited agentic workflows.", "popular": True, "features": ["Unlimited Agents creation", "Agent Inventory, RAG, Multi Model", "24/7 support + SLA guarantee"]},
        ],
    },
]

def product_key_from_name(name: str) -> str:
    key = "".join(ch.lower() if ch.isalnum() else "_" for ch in (name or "").strip())
    key = "_".join(part for part in key.split("_") if part)
    return key or f"product_{uuid.uuid4().hex[:8]}"

def parse_price_amount(price_label: Optional[str]) -> float:
    if not price_label:
        return 0
    cleaned = "".join(ch for ch in price_label if ch.isdigit() or ch == ".")
    try:
        return float(cleaned) if cleaned else 0
    except ValueError:
        return 0

async def get_product_by_id_or_key(db: AsyncSession, value: Optional[str]) -> Optional[ProductModel]:
    if not value:
        return None
    result = await db.execute(
        select(ProductModel).where((ProductModel.id == value) | (ProductModel.key == value))
    )
    return result.scalar_one_or_none()

async def resolve_product_for_plan(db: AsyncSession, data: PlanCreate) -> ProductModel:
    product = await get_product_by_id_or_key(db, data.product_id)
    if product:
        return product
    raise HTTPException(status_code=400, detail="Valid product_id is required")

async def get_plan_product(db: AsyncSession, plan: PlanModel) -> Optional[ProductModel]:
    product = await get_product_by_id_or_key(db, plan.product_id)
    if product:
        return product
    if plan.tool:
        return await get_product_by_id_or_key(db, plan.tool)
    return None

async def plan_to_dict(db: AsyncSession, plan: PlanModel, include_tools: bool = True) -> dict:
    plan_dict = model_to_dict(plan, ["features"])
    plan_dict.pop("tool", None)
    product = await get_plan_product(db, plan)
    if product:
        plan_dict["product_id"] = product.id
        plan_dict["product_key"] = product.key
        plan_dict["product_name"] = product.name
        plan_dict["product"] = model_to_dict(product)
    if include_tools:
        tools_result = await db.execute(
            select(PlanToolModel)
            .where(PlanToolModel.plan_id == plan.id)
            .order_by(PlanToolModel.display_order, PlanToolModel.name)
        )
        plan_dict["plan_tools"] = [model_to_dict(t) for t in tools_result.scalars().all()]
    return plan_dict

def normalize_plan_selections(data: PlanUpgradeCreate) -> List[PlanSelectionItem]:
    if data.requested_plans:
        return data.requested_plans
    if data.requested_plan_id:
        return [PlanSelectionItem(plan_id=data.requested_plan_id, tool_ids=data.requested_tools or [])]
    return []

async def resolve_plan_tool(db: AsyncSession, plan_id: str, tool_value: str) -> Optional[PlanToolModel]:
    result = await db.execute(
        select(PlanToolModel).where(
            PlanToolModel.plan_id == plan_id,
            (PlanToolModel.id == tool_value) | (PlanToolModel.name == tool_value)
        )
    )
    return result.scalar_one_or_none()

async def set_subscription_tools(db: AsyncSession, subscription_id: str, plan_id: str, tools: List[str]):
    await db.execute(delete(SubscriptionToolModel).where(SubscriptionToolModel.subscription_id == subscription_id))
    seen = set()
    for tool in tools or []:
        if not tool or tool in seen:
            continue
        seen.add(tool)
        plan_tool = await resolve_plan_tool(db, plan_id, tool)
        if not plan_tool:
            raise HTTPException(
                status_code=400,
                detail=f"Tool '{tool}' is not available for plan '{plan_id}'"
            )
        db.add(SubscriptionToolModel(
            subscription_id=subscription_id,
            plan_tool_id=plan_tool.id,
            tool_key=None
        ))

async def get_subscription_tools(db: AsyncSession, subscription: SubscriptionModel) -> List[str]:
    result = await db.execute(
        select(SubscriptionToolModel)
        .where(SubscriptionToolModel.subscription_id == subscription.id)
        .order_by(SubscriptionToolModel.created_at.asc())
    )
    rows = result.scalars().all()
    if not rows:
        return parse_json_list(subscription.tools)

    tool_names = []
    for row in rows:
        if row.plan_tool_id:
            tool_result = await db.execute(select(PlanToolModel).where(PlanToolModel.id == row.plan_tool_id))
            plan_tool = tool_result.scalar_one_or_none()
            tool_names.append(plan_tool.name if plan_tool else row.plan_tool_id)
        elif row.tool_key:
            tool_names.append(row.tool_key)
    return tool_names

def is_real_organization(org: Optional[OrganizationModel]) -> bool:
    return bool(org and org.id != "no_organization" and org.name != "Individual Users")

async def get_organization_by_id(db: AsyncSession, organization_id: Optional[str]) -> Optional[OrganizationModel]:
    if not organization_id:
        return None
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == organization_id))
    return result.scalar_one_or_none()

async def cancel_active_real_org_subscription_for_plan(
    db: AsyncSession,
    organization_id: str,
    plan_id: str,
    *,
    exclude_subscription_id: Optional[str] = None,
):
    org = await get_organization_by_id(db, organization_id)
    if not is_real_organization(org):
        return 0

    stmt = (
        update(SubscriptionModel)
        .where(SubscriptionModel.organization_id == organization_id)
        .where(SubscriptionModel.plan_id == plan_id)
        .where(SubscriptionModel.status == "active")
    )
    if exclude_subscription_id:
        stmt = stmt.where(SubscriptionModel.id != exclude_subscription_id)
    result = await db.execute(stmt.values(status="cancelled"))
    return result.rowcount or 0

async def ensure_can_activate_subscription(db: AsyncSession, subscription: SubscriptionModel):
    org = await get_organization_by_id(db, subscription.organization_id)
    if not is_real_organization(org):
        return

    result = await db.execute(
        select(func.count())
        .select_from(SubscriptionModel)
        .where(SubscriptionModel.organization_id == subscription.organization_id)
        .where(SubscriptionModel.plan_id == subscription.plan_id)
        .where(SubscriptionModel.status == "active")
        .where(SubscriptionModel.id != subscription.id)
    )
    if (result.scalar() or 0) > 0:
        raise HTTPException(
            status_code=409,
            detail="Another active subscription already exists for this organization and plan"
        )

async def calculate_plan_total(db: AsyncSession, plan: PlanModel, tools: List[str], billing_cycle: str = "monthly") -> float:
    seen = set()
    for tool in tools or []:
        if not tool or tool in seen:
            continue
        seen.add(tool)
        plan_tool = await resolve_plan_tool(db, plan.id, tool)
        if not plan_tool:
            raise HTTPException(
                status_code=400,
                detail=f"Tool '{tool}' is not available for plan '{plan.id}'"
            )
    return float(getattr(plan, "cost", None) or plan.price_monthly or 0)

async def sync_organization_requested_from_active_subscriptions(db: AsyncSession, organization_id: str):
    org = await get_organization_by_id(db, organization_id)
    if not org:
        return
    result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == organization_id)
        .where(SubscriptionModel.status == "active")
        .order_by(SubscriptionModel.created_at.desc())
    )
    active_subs = result.scalars().all()
    org.requested_plan = json.dumps([sub.plan_id for sub in active_subs])
    active_tools = []
    for sub in active_subs:
        active_tools.extend(await get_subscription_tools(db, sub))
    org.requested_tools = json.dumps(active_tools)
    org.updated_at = datetime.now(timezone.utc)

async def set_upgrade_request_items(db: AsyncSession, request_id: str, selections: List[PlanSelectionItem]):
    existing = await db.execute(
        select(PlanUpgradeRequestItemModel).where(PlanUpgradeRequestItemModel.request_id == request_id)
    )
    for item in existing.scalars().all():
        await db.execute(delete(PlanUpgradeRequestToolModel).where(PlanUpgradeRequestToolModel.request_item_id == item.id))
    await db.execute(delete(PlanUpgradeRequestItemModel).where(PlanUpgradeRequestItemModel.request_id == request_id))

    for selection in selections:
        item = PlanUpgradeRequestItemModel(request_id=request_id, plan_id=selection.plan_id)
        db.add(item)
        await db.flush()
        seen = set()
        for tool in selection.tool_ids or []:
            if not tool or tool in seen:
                continue
            seen.add(tool)
            plan_tool = await resolve_plan_tool(db, selection.plan_id, tool)
            if not plan_tool:
                raise HTTPException(
                    status_code=400,
                    detail=f"Tool '{tool}' is not available for plan '{selection.plan_id}'"
                )
            db.add(PlanUpgradeRequestToolModel(
                request_item_id=item.id,
                plan_tool_id=plan_tool.id,
                tool_key=None
            ))

async def get_upgrade_request_items(db: AsyncSession, request: PlanUpgradeRequestModel) -> List[dict]:
    result = await db.execute(
        select(PlanUpgradeRequestItemModel)
        .where(PlanUpgradeRequestItemModel.request_id == request.id)
        .order_by(PlanUpgradeRequestItemModel.created_at.asc())
    )
    items = result.scalars().all()
    if items:
        details = []
        for item in items:
            plan_result = await db.execute(select(PlanModel).where(PlanModel.id == item.plan_id))
            plan = plan_result.scalar_one_or_none()
            tool_rows_result = await db.execute(
                select(PlanUpgradeRequestToolModel)
                .where(PlanUpgradeRequestToolModel.request_item_id == item.id)
                .order_by(PlanUpgradeRequestToolModel.created_at.asc())
            )
            tools = []
            for tool_row in tool_rows_result.scalars().all():
                if tool_row.plan_tool_id:
                    tool_result = await db.execute(select(PlanToolModel).where(PlanToolModel.id == tool_row.plan_tool_id))
                    plan_tool = tool_result.scalar_one_or_none()
                    tools.append(plan_tool.name if plan_tool else tool_row.plan_tool_id)
                elif tool_row.tool_key:
                    tools.append(tool_row.tool_key)
            product = await get_plan_product(db, plan) if plan else None
            details.append({
                "plan_id": item.plan_id,
                "plan_name": plan.name if plan else item.plan_id,
                "product_id": product.id if product else None,
                "product_name": product.name if product else None,
                "tools": tools,
            })
        return details

    if request.requested_plans_details:
        try:
            details = json.loads(request.requested_plans_details)
            if isinstance(details, list):
                return details
        except (json.JSONDecodeError, TypeError):
            pass

    if request.requested_plan_id:
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == request.requested_plan_id))
        plan = plan_result.scalar_one_or_none()
        product = await get_plan_product(db, plan) if plan else None
        return [{
            "plan_id": request.requested_plan_id,
            "plan_name": request.requested_plan_name,
            "product_id": product.id if product else None,
            "product_name": product.name if product else None,
            "tools": parse_json_list(request.requested_tools)
        }]
    return []

async def create_organization_subscription_request(
    db: AsyncSession,
    organization_id: str,
    plan_ids: List[str],
    tools: List[str],
    *,
    status: str = "pending"
) -> OrganizationSubscriptionRequestModel:
    request = OrganizationSubscriptionRequestModel(
        organization_id=organization_id,
        status=status
    )
    db.add(request)
    await db.flush()

    unresolved_tools = set(tools or [])
    for plan_id in plan_ids:
        item = OrganizationSubscriptionRequestItemModel(request_id=request.id, plan_id=plan_id)
        db.add(item)
        await db.flush()
        seen = set()
        for tool in tools or []:
            if not tool or tool in seen:
                continue
            seen.add(tool)
            plan_tool = await resolve_plan_tool(db, plan_id, tool)
            if not plan_tool:
                if len(plan_ids) == 1:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Tool '{tool}' is not available for plan '{plan_id}'"
                    )
                continue
            unresolved_tools.discard(tool)
            db.add(OrganizationSubscriptionRequestToolModel(
                request_item_id=item.id,
                plan_tool_id=plan_tool.id,
                tool_key=None
            ))
    if unresolved_tools:
        raise HTTPException(
            status_code=400,
            detail=f"Tools are not available for selected plans: {sorted(unresolved_tools)}"
        )
    return request

async def get_organization_requested_plan_details(db: AsyncSession, org: OrganizationModel) -> List[dict]:
    request_result = await db.execute(
        select(OrganizationSubscriptionRequestModel)
        .where(OrganizationSubscriptionRequestModel.organization_id == org.id)
        .order_by(OrganizationSubscriptionRequestModel.created_at.desc())
    )
    request = request_result.scalars().first()
    if request:
        item_result = await db.execute(
            select(OrganizationSubscriptionRequestItemModel)
            .where(OrganizationSubscriptionRequestItemModel.request_id == request.id)
            .order_by(OrganizationSubscriptionRequestItemModel.created_at.asc())
        )
        details = []
        for item in item_result.scalars().all():
            plan_result = await db.execute(select(PlanModel).where(PlanModel.id == item.plan_id))
            plan = plan_result.scalar_one_or_none()
            tool_rows_result = await db.execute(
                select(OrganizationSubscriptionRequestToolModel)
                .where(OrganizationSubscriptionRequestToolModel.request_item_id == item.id)
                .order_by(OrganizationSubscriptionRequestToolModel.created_at.asc())
            )
            tools = []
            for tool_row in tool_rows_result.scalars().all():
                if tool_row.plan_tool_id:
                    tool_result = await db.execute(select(PlanToolModel).where(PlanToolModel.id == tool_row.plan_tool_id))
                    plan_tool = tool_result.scalar_one_or_none()
                    tools.append(plan_tool.name if plan_tool else tool_row.plan_tool_id)
                elif tool_row.tool_key:
                    tools.append(tool_row.tool_key)
            product = await get_plan_product(db, plan) if plan else None
            details.append({
                "plan_id": item.plan_id,
                "plan_name": plan.name if plan else item.plan_id,
                "product_id": product.id if product else None,
                "product_name": product.name if product else None,
                "tools": tools,
            })
        if details:
            return details

    plan_ids = parse_json_list(org.requested_plan)
    tools = parse_json_list(org.requested_tools)
    details = []
    for plan_id in plan_ids:
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
        plan = plan_result.scalar_one_or_none()
        product = await get_plan_product(db, plan) if plan else None
        details.append({
            "plan_id": plan_id,
            "plan_name": plan.name if plan else await get_plan_name(db, plan_id, plan_id),
            "product_id": product.id if product else None,
            "product_name": product.name if product else None,
            "tools": tools,
        })
    return details

async def admin_to_dict(db: AsyncSession, admin: AdminModel) -> dict:
    data = model_to_dict(admin)
    data["organization_name"] = await get_organization_name(db, admin.organization_id, admin.organization_name)
    return data

async def user_to_dict(db: AsyncSession, user: UserModel) -> dict:
    data = model_to_dict(user)
    data["organization_name"] = await get_organization_name(db, user.organization_id, user.organization_name)
    data["role_name"] = await get_role_name(db, user.role_id, user.role_name)
    return data

async def subscription_to_dict(db: AsyncSession, subscription: SubscriptionModel) -> dict:
    data = model_to_dict(subscription, ["tools"])
    data["organization_name"] = await get_organization_name(db, subscription.organization_id, subscription.organization_name)
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == subscription.plan_id))
    plan = plan_result.scalar_one_or_none()
    product = await get_plan_product(db, plan) if plan else None
    data["plan_name"] = plan.name if plan else await get_plan_name(db, subscription.plan_id, subscription.plan_name)
    if product:
        data["product_id"] = product.id
        data["product_key"] = product.key
        data["product_name"] = product.name
    else:
        data["product_id"] = None
        data["product_key"] = None
        data["product_name"] = None
    data["tools"] = await get_subscription_tools(db, subscription)
    return data

async def get_active_subscriptions_for_identity(
    db: AsyncSession,
    *,
    email: str,
    organization_id: Optional[str],
) -> List[SubscriptionModel]:
    if organization_id and organization_id != "no_organization":
        result = await db.execute(
            select(SubscriptionModel)
            .where(
                SubscriptionModel.organization_id == organization_id,
                SubscriptionModel.status == "active",
            )
            .order_by(SubscriptionModel.start_date.desc())
        )
        return result.scalars().all()

    ind_req_result = await db.execute(
        select(IndividualUserRequestModel).where(
            IndividualUserRequestModel.email == email,
            IndividualUserRequestModel.status == "approved",
        )
    )
    subscription_ids = [
        req.assigned_subscription_id
        for req in ind_req_result.scalars().all()
        if req.assigned_subscription_id
    ]
    if not subscription_ids:
        return []

    result = await db.execute(
        select(SubscriptionModel)
        .where(
            SubscriptionModel.id.in_(subscription_ids),
            SubscriptionModel.status == "active",
        )
        .order_by(SubscriptionModel.start_date.desc())
    )
    return result.scalars().all()

async def build_subscription_context(db: AsyncSession, subscriptions: List[SubscriptionModel]) -> dict:
    subscription_details = []
    plans = []
    tools = []
    seen_plan_ids = set()
    seen_tools = set()

    for subscription in subscriptions:
        subscription_data = await subscription_to_dict(db, subscription)
        subscription_details.append(subscription_data)

        if subscription.plan_id and subscription.plan_id not in seen_plan_ids:
            plan_result = await db.execute(select(PlanModel).where(PlanModel.id == subscription.plan_id))
            plan = plan_result.scalar_one_or_none()
            if plan:
                plans.append(await plan_to_dict(db, plan, include_tools=False))
                seen_plan_ids.add(plan.id)

        for tool in subscription_data.get("tools") or []:
            if tool not in seen_tools:
                seen_tools.add(tool)
                tools.append(tool)

    return {
        "subscriptions": subscription_details,
        "plans": plans,
        "tools": tools,
    }

def context_project_payload(project: ProjectModel, role: str, member: Optional[ProjectTeamMemberModel] = None) -> dict:
    payload = {
        "id": project.id,
        "name": project.name,
        "code": project.code,
        "description": project.description,
        "status": project.status,
        "business_unit_id": project.business_unit_id,
        "role": role,
        "project_role": role,
    }
    if member:
        payload["membership_id"] = member.id
        payload["membership_status"] = member.status
        payload["accepted_at"] = member.accepted_at.isoformat() if member.accepted_at else None
    return payload

async def build_business_unit_context(
    db: AsyncSession,
    *,
    user: Optional[UserModel],
    admin: Optional[AdminModel],
    organization_id: Optional[str],
) -> dict:
    business_units_by_id = {}
    projects_without_business_unit = []
    project_memberships = []
    is_org_admin = bool(admin and admin.role == "org_admin")
    is_super_admin = bool(admin and admin.role == "super_admin")

    if not organization_id or organization_id == "no_organization" or is_super_admin:
        return {
            "business_units": [],
            "projects": [],
            "projects_without_business_unit": [],
        }

    if is_org_admin:
        bu_result = await db.execute(
            select(BusinessUnitModel)
            .where(BusinessUnitModel.organization_id == organization_id)
            .order_by(BusinessUnitModel.name.asc())
        )
        for business_unit in bu_result.scalars().all():
            bu_data = model_to_dict(business_unit, ["tags"])
            bu_data["role"] = "admin"
            bu_data["business_unit_role"] = "admin"
            bu_data["projects"] = []
            business_units_by_id[business_unit.id] = bu_data

        project_result = await db.execute(
            select(ProjectModel)
            .where(ProjectModel.organization_id == organization_id)
            .order_by(ProjectModel.name.asc())
        )
        for project in project_result.scalars().all():
            project_data = context_project_payload(project, "admin")
            project_memberships.append(project_data)
            if project.business_unit_id and project.business_unit_id in business_units_by_id:
                business_units_by_id[project.business_unit_id]["projects"].append(project_data)
            else:
                projects_without_business_unit.append(project_data)

        return {
            "business_units": list(business_units_by_id.values()),
            "projects": project_memberships,
            "projects_without_business_unit": projects_without_business_unit,
        }

    if not user:
        return {
            "business_units": [],
            "projects": [],
            "projects_without_business_unit": [],
        }

    member_result = await db.execute(
        select(ProjectTeamMemberModel, ProjectModel, BusinessUnitModel)
        .join(ProjectModel, ProjectTeamMemberModel.project_id == ProjectModel.id)
        .outerjoin(BusinessUnitModel, ProjectModel.business_unit_id == BusinessUnitModel.id)
        .where(
            ProjectTeamMemberModel.organization_id == organization_id,
            ((ProjectTeamMemberModel.user_id == user.id) | (ProjectTeamMemberModel.email == user.email)),
            ProjectTeamMemberModel.status == "active",
        )
        .order_by(BusinessUnitModel.name.asc(), ProjectModel.name.asc())
    )

    for member, project, business_unit in member_result.all():
        project_data = context_project_payload(project, member.project_role, member)
        project_memberships.append(project_data)

        if business_unit:
            if business_unit.id not in business_units_by_id:
                bu_data = model_to_dict(business_unit, ["tags"])
                bu_data["role"] = "member"
                bu_data["business_unit_role"] = "member"
                bu_data["projects"] = []
                business_units_by_id[business_unit.id] = bu_data
            business_units_by_id[business_unit.id]["projects"].append(project_data)
        else:
            projects_without_business_unit.append(project_data)

    return {
        "business_units": list(business_units_by_id.values()),
        "projects": project_memberships,
        "projects_without_business_unit": projects_without_business_unit,
    }

async def build_user_context(db: AsyncSession, email: Optional[str], auth0_user_id: Optional[str] = None) -> dict:
    normalized_email = email.lower().strip() if email else None
    user = None
    admin = None

    if auth0_user_id:
        result = await db.execute(select(UserModel).where(UserModel.auth0_user_id == auth0_user_id))
        user = result.scalar_one_or_none()

    if not user and normalized_email:
        result = await db.execute(select(UserModel).where(UserModel.email == normalized_email))
        user = result.scalar_one_or_none()

    if normalized_email:
        admin_result = await db.execute(select(AdminModel).where(AdminModel.email == normalized_email))
        admin = admin_result.scalar_one_or_none()

    if not user and not admin:
        raise HTTPException(status_code=404, detail="User not found")

    primary_email = normalized_email or (user.email if user else admin.email)
    organization_id = user.organization_id if user else admin.organization_id
    organization = None
    if organization_id and organization_id != "no_organization":
        org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == organization_id))
        organization = org_result.scalar_one_or_none()

    role = None
    role_permissions = []
    if user:
        role_result = await db.execute(select(RoleModel).where(RoleModel.id == user.role_id))
        role = role_result.scalar_one_or_none()
        role_permissions = parse_json_list(role.permissions) if role and role.permissions else []

    admin_permissions = []
    if admin:
        admin_permissions = ["all"] if admin.role == "super_admin" else ["read", "write", "manage_users"]

    subscriptions = await get_active_subscriptions_for_identity(
        db,
        email=primary_email,
        organization_id=organization_id,
    )
    subscription_context = await build_subscription_context(db, subscriptions)
    business_unit_context = await build_business_unit_context(
        db,
        user=user,
        admin=admin,
        organization_id=organization_id,
    )

    now = datetime.now(timezone.utc)
    if user:
        user.last_login = now
        if auth0_user_id and not user.auth0_user_id:
            user.auth0_user_id = auth0_user_id
        await db.flush()

    is_org_admin = bool(admin and admin.role == "org_admin")
    is_super_admin = bool(admin and admin.role == "super_admin")
    permissions = list(dict.fromkeys(role_permissions + admin_permissions))

    return {
        "user": {
            "id": user.id if user else admin.id,
            "email": primary_email,
            "name": user.name if user else admin.name,
            "type": "user" if user else "admin",
            "status": user.status if user else ("active" if admin.is_active else "inactive"),
            "theme_preference": getattr(user or admin, "theme_preference", "system"),
            "email_verified": user.email_verified if user else True,
            "auth0_user_id": user.auth0_user_id if user else auth0_user_id,
            "created_at": (user.created_at if user else admin.created_at).isoformat() if (user or admin) else None,
        },
        "organization": {
            "id": organization.id if organization else organization_id,
            "name": organization.name if organization else await get_organization_name(db, organization_id, None),
            "external_org_id": organization.external_org_id if organization else None,
            "auth0_org_id": organization.auth0_org_id if organization else None,
            "status": organization.status if organization else None,
            "supported_domains": parse_json_list(organization.supported_domains) if organization and organization.supported_domains else [],
        } if organization_id else None,
        "org_role": {
            "id": role.id if role else None,
            "name": role.name if role else (admin.role if admin else None),
            "permissions": role_permissions,
        },
        "admin": {
            "id": admin.id,
            "role": admin.role,
            "is_active": admin.is_active,
            "permissions": admin_permissions,
        } if admin else None,
        "is_admin": bool(admin),
        "is_org_admin": is_org_admin,
        "is_super_admin": is_super_admin,
        "permissions": permissions,
        "business_units": business_unit_context["business_units"],
        "projects": business_unit_context["projects"],
        "projects_without_business_unit": business_unit_context["projects_without_business_unit"],
        "subscriptions": subscription_context["subscriptions"],
        "plans": subscription_context["plans"],
        "tools": subscription_context["tools"],
    }

def create_user_context_token(user_context: dict) -> tuple[str, int]:
    expires_at = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
    issued_at = int(datetime.now(timezone.utc).timestamp())
    payload = {
        **user_context,
        "sub": user_context["user"]["id"],
        "email": user_context["user"]["email"],
        "token_type": "probestack_user_context",
        "iat": issued_at,
        "exp": expires_at,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM), expires_at

async def billing_to_dict(db: AsyncSession, billing: BillingModel) -> dict:
    data = model_to_dict(billing)
    data["organization_name"] = await get_organization_name(db, billing.organization_id, billing.organization_name)
    return data

async def user_request_to_dict(db: AsyncSession, request: UserRequestModel) -> dict:
    data = model_to_dict(request)
    data["organization_name"] = await get_organization_name(db, request.organization_id, request.organization_name)
    data["approved_business_unit"] = None
    data["approved_team"] = None
    if request.approved_business_unit_id:
        bu_result = await db.execute(select(BusinessUnitModel).where(BusinessUnitModel.id == request.approved_business_unit_id))
        business_unit = bu_result.scalar_one_or_none()
        data["approved_business_unit"] = model_to_dict(business_unit, ["tags"]) if business_unit else None
    if request.approved_project_id:
        project_result = await db.execute(select(ProjectModel).where(ProjectModel.id == request.approved_project_id))
        project = project_result.scalar_one_or_none()
        data["approved_team"] = model_to_dict(project) if project else None
    return data

async def organization_to_dict(db: AsyncSession, org: OrganizationModel) -> dict:
    data = model_to_dict(org, ["requested_tools", "supported_domains", "gateway_environments"])
    requested_details = await get_organization_requested_plan_details(db, org)
    if requested_details:
        data["requested_plan"] = json.dumps([detail["plan_id"] for detail in requested_details])
        data["requested_plans"] = [detail["plan_id"] for detail in requested_details]
        data["requested_tools"] = []
        for detail in requested_details:
            data["requested_tools"].extend(detail.get("tools", []))
        data["requested_plan_details"] = requested_details
    return data

async def upgrade_request_to_dict(db: AsyncSession, request: PlanUpgradeRequestModel) -> dict:
    data = model_to_dict(request, ["requested_tools"])
    request_items = await get_upgrade_request_items(db, request)
    data["organization_name"] = await get_organization_name(db, request.organization_id, request.organization_name)
    data["current_plan_name"] = await get_plan_name(db, request.current_plan_id, request.current_plan_name)
    if request.requested_plan_id:
        data["requested_plan_name"] = await get_plan_name(db, request.requested_plan_id, request.requested_plan_name)
    if request_items:
        data["requested_plans_details"] = request_items
        data["requested_plan_ids"] = [item["plan_id"] for item in request_items]
        data["requested_tools"] = []
        for item in request_items:
            data["requested_tools"].extend(item.get("tools", []))
        data["requested_plan_name"] = ", ".join([item["plan_name"] for item in request_items if item.get("plan_name")])
    return data

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

async def get_approved_org_for_admin(payload: dict, db: AsyncSession) -> OrganizationModel:
    """Return the approved organization for the current org admin."""
    if payload.get("role") != "org_admin":
        raise HTTPException(status_code=403, detail="Organization admin access required")

    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")

    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if org.status != "approved":
        raise HTTPException(status_code=400, detail="Organization is not approved")

    return org

async def assert_business_unit_unique(
    db: AsyncSession,
    *,
    organization_id: str,
    name: Optional[str] = None,
    code: Optional[str] = None,
    exclude_id: Optional[str] = None
):
    if name:
        query = select(BusinessUnitModel).where(
            BusinessUnitModel.organization_id == organization_id,
            BusinessUnitModel.name == name
        )
        if exclude_id:
            query = query.where(BusinessUnitModel.id != exclude_id)
        result = await db.execute(query)
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Business unit name already exists in this organization")

    if code:
        query = select(BusinessUnitModel).where(
            BusinessUnitModel.organization_id == organization_id,
            BusinessUnitModel.code == code
        )
        if exclude_id:
            query = query.where(BusinessUnitModel.id != exclude_id)
        result = await db.execute(query)
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Business unit code already exists in this organization")

async def assert_project_unique(
    db: AsyncSession,
    *,
    organization_id: str,
    name: Optional[str] = None,
    code: Optional[str] = None,
    exclude_id: Optional[str] = None
):
    if name:
        query = select(ProjectModel).where(
            ProjectModel.organization_id == organization_id,
            ProjectModel.name == name
        )
        if exclude_id:
            query = query.where(ProjectModel.id != exclude_id)
        result = await db.execute(query)
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Project name already exists in this organization")

    if code:
        query = select(ProjectModel).where(
            ProjectModel.organization_id == organization_id,
            ProjectModel.code == code
        )
        if exclude_id:
            query = query.where(ProjectModel.id != exclude_id)
        result = await db.execute(query)
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Project code already exists in this organization")

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()

def derive_name_from_email(email: str) -> str:
    local_part = email.split("@", 1)[0] if "@" in email else email
    return local_part.replace(".", " ").replace("_", " ").replace("-", " ").title()

def get_org_allowed_domains(org: OrganizationModel) -> List[str]:
    domains = []
    for value in parse_json_list(org.supported_domains):
        if value:
            domain = str(value).strip().lower()
            domains.append(domain if domain.startswith("@") else f"@{domain}")
    if org.domain:
        domain = org.domain.strip().lower()
        domains.append(domain if domain.startswith("@") else f"@{domain}")
    return sorted(set(domains))

def assert_email_allowed_for_org(email: str, org: OrganizationModel):
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail=f"Invalid email address: {email}")
    email_domain = "@" + email.split("@", 1)[1].lower()
    allowed_domains = get_org_allowed_domains(org)
    if not allowed_domains:
        raise HTTPException(status_code=400, detail="Organization has no supported email domains configured")
    if email_domain not in allowed_domains:
        raise HTTPException(
            status_code=400,
            detail=f"Email {email} is not allowed. Allowed domains: {', '.join(allowed_domains)}"
        )

async def get_project_for_org(db: AsyncSession, project_id: str, organization_id: str) -> ProjectModel:
    result = await db.execute(
        select(ProjectModel).where(
            ProjectModel.id == project_id,
            ProjectModel.organization_id == organization_id
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

async def get_approved_org_by_id(db: AsyncSession, organization_id: str) -> OrganizationModel:
    result = await db.execute(
        select(OrganizationModel).where(
            OrganizationModel.id == organization_id,
            OrganizationModel.status == "approved"
        )
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Approved organization not found")
    return org

async def create_business_unit_for_org(
    db: AsyncSession,
    org: OrganizationModel,
    data: BusinessUnitCreate,
    created_by: Optional[str] = None
) -> BusinessUnitModel:
    name = data.name.strip()
    code = data.code.strip() if data.code else None
    status = data.status or "active"

    if not name:
        raise HTTPException(status_code=400, detail="Business unit name is required")
    if status not in ["active", "inactive", "archived"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    if data.sync_status and data.sync_status not in ["synced", "pending", "failed"]:
        raise HTTPException(status_code=400, detail="Invalid sync status")

    await assert_business_unit_unique(db, organization_id=org.id, name=name, code=code)
    owner_name = await resolve_organization_user_label(db, org.id, data.owner_name, "Business unit owner")

    business_unit = BusinessUnitModel(
        organization_id=org.id,
        name=name,
        code=code,
        description=data.description,
        application_name=data.application_name,
        application_id=data.application_id,
        owner_name=owner_name,
        go_live_date=data.go_live_date,
        members_count=max(data.members_count or 0, 0),
        consumers_count=max(data.consumers_count or 0, 0),
        project_sme=data.project_sme,
        tester=data.tester,
        servicenow_group=data.servicenow_group,
        last_synced_at=data.last_synced_at,
        sync_status=data.sync_status or "synced",
        tags=json.dumps(data.tags or []),
        status=status,
        created_by=created_by
    )
    db.add(business_unit)
    await db.flush()
    return business_unit

async def create_project_for_org(
    db: AsyncSession,
    org: OrganizationModel,
    data: ExternalProjectCreate,
    created_by: Optional[str] = None
) -> ProjectModel:
    name = data.name.strip()
    code = data.code.strip() if data.code else None
    status = data.status or "active"

    if not name:
        raise HTTPException(status_code=400, detail="Team name is required")
    if status not in ["active", "inactive", "archived"]:
        raise HTTPException(status_code=400, detail="Invalid status")

    bu_result = await db.execute(
        select(BusinessUnitModel).where(
            BusinessUnitModel.id == data.business_unit_id,
            BusinessUnitModel.organization_id == org.id
        )
    )
    if not bu_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Business unit not found in this organization")

    await assert_project_unique(db, organization_id=org.id, name=name, code=code)

    project = ProjectModel(
        organization_id=org.id,
        business_unit_id=data.business_unit_id,
        name=name,
        code=code,
        description=data.description,
        status=status,
        created_by=created_by
    )
    db.add(project)
    await db.flush()
    return project

async def resolve_organization_user_label(
    db: AsyncSession,
    organization_id: str,
    value: Optional[str],
    field_label: str,
) -> Optional[str]:
    if not value:
        return None
    lookup = value.strip()
    if not lookup:
        return None
    result = await db.execute(
        select(UserModel).where(
            UserModel.organization_id == organization_id,
            (UserModel.id == lookup) | (UserModel.email == lookup) | (UserModel.name == lookup),
        )
    )
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=400, detail=f"{field_label} must be an existing user in this organization")
    return f"{user.name} <{user.email}>"

async def get_or_create_default_org_role(db: AsyncSession, org: OrganizationModel) -> RoleModel:
    result = await db.execute(
        select(RoleModel)
        .where(RoleModel.organization_id == org.id, RoleModel.name.in_(["User", "Member"]))
        .order_by(RoleModel.name.asc())
    )
    role = result.scalars().first()
    if role:
        return role

    role = RoleModel(
        name="User",
        organization_id=org.id,
        permissions=json.dumps(["read"]),
        description="Default project member role"
    )
    db.add(role)
    await db.flush()
    return role

async def create_invited_org_user(db: AsyncSession, org: OrganizationModel, email: str) -> UserModel:
    role = await get_or_create_default_org_role(db, org)
    user = UserModel(
        email=email,
        name=derive_name_from_email(email),
        organization_id=org.id,
        organization_name=org.name,
        role_id=role.id,
        role_name=role.name,
        status="pending_verification",
        email_verified=False,
        password_set=False,
        first_login_token=secrets.token_urlsafe(32)
    )
    db.add(user)
    await db.flush()

    auth0_result = await auth0_mgmt.create_user(
        email=email,
        name=user.name,
        user_metadata={
            "probestack_user_id": user.id,
            "organization_id": org.id,
            "organization_name": org.name
        }
    )
    if auth0_result.get("success"):
        user.auth0_user_id = auth0_result.get("auth0_user_id")
        await auth0_mgmt.send_verification_email(user.auth0_user_id)
    elif auth0_result.get("exists"):
        existing_user = await auth0_mgmt.get_user_by_email(email)
        if existing_user.get("success"):
            user.auth0_user_id = existing_user["user"]["user_id"]
            await auth0_mgmt.send_verification_email(user.auth0_user_id)
    else:
        logger.warning(f"Failed to create Auth0 user for {email}: {auth0_result.get('error')}")

    return user

def build_setup_account_url(email: str, token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    return f"{APP_URL.rstrip('/')}/setup-account?{urlencode({'email': email, 'token': token})}"

def build_login_url() -> str:
    return f"{APP_URL.rstrip('/')}/admin/login"

def send_email(to_email: str, subject: str, text_body: str, html_body: Optional[str] = None) -> dict:
    if not SMTP_HOST or not SMTP_FROM_EMAIL:
        logger.warning(
            "SMTP not configured; skipped email to %s. Subject: %s",
            to_email,
            subject
        )
        return {
            "sent": False,
            "reason": "SMTP not configured"
        }

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    message["To"] = to_email
    message.set_content(text_body)
    if html_body:
        message.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            if SMTP_USE_TLS:
                smtp.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)
        logger.info("Project invite email sent to %s", to_email)
        return {"sent": True}
    except Exception as exc:
        logger.error("Failed to send project invite email to %s: %s", to_email, exc)
        return {
            "sent": False,
            "reason": str(exc)
        }

def send_project_invite_email(
    *,
    to_email: str,
    invitee_name: str,
    organization_name: str,
    project_name: str,
    project_role: str,
    setup_url: Optional[str],
    invited_by_email: Optional[str]
) -> dict:
    action_url = setup_url or build_login_url()
    action_label = "Set up your account" if setup_url else "Open ProbeStack"
    subject = f"You're invited to {project_name} on ProbeStack"
    safe_invitee_name = escape(invitee_name)
    safe_organization_name = escape(organization_name)
    safe_project_name = escape(project_name)
    safe_project_role = escape(project_role)
    safe_invited_by = escape(invited_by_email or "your organization admin")
    safe_action_url = escape(action_url, quote=True)
    safe_action_label = escape(action_label)
    text_body = "\n".join([
        f"Hi {invitee_name},",
        "",
        f"You have been invited to the {project_name} project in {organization_name} as {project_role}.",
        f"Invited by: {invited_by_email or 'your organization admin'}",
        "",
        f"{action_label}: {action_url}",
        "",
        "If you were not expecting this invitation, you can ignore this email.",
        "",
        "ProbeStack"
    ])
    html_body = f"""
    <p>Hi {safe_invitee_name},</p>
    <p>You have been invited to the <strong>{safe_project_name}</strong> project in <strong>{safe_organization_name}</strong> as <strong>{safe_project_role}</strong>.</p>
    <p>Invited by: {safe_invited_by}</p>
    <p><a href="{safe_action_url}">{safe_action_label}</a></p>
    <p>If you were not expecting this invitation, you can ignore this email.</p>
    <p>ProbeStack</p>
    """
    result = send_email(to_email, subject, text_body, html_body)
    if setup_url:
        result["setup_url"] = setup_url
    return result

async def project_team_member_to_dict(db: AsyncSession, member: ProjectTeamMemberModel) -> dict:
    data = model_to_dict(member)
    if member.user_id:
        result = await db.execute(select(UserModel).where(UserModel.id == member.user_id))
        user = result.scalar_one_or_none()
        data["user"] = await user_to_dict(db, user) if user else None
    else:
        data["user"] = None
    return data

async def validate_user_request_team_assignment(
    db: AsyncSession,
    organization_id: str,
    project_id: Optional[str],
    business_unit_id: Optional[str] = None
) -> tuple[BusinessUnitModel, ProjectModel]:
    if not project_id:
        raise HTTPException(status_code=400, detail="Project is required when approving organization users")

    project_result = await db.execute(
        select(ProjectModel).where(
            ProjectModel.id == project_id,
            ProjectModel.organization_id == organization_id
        )
    )
    project = project_result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found in this organization")
    if not project.business_unit_id:
        raise HTTPException(status_code=400, detail="Selected Project must be linked to a Business unit")
    if business_unit_id and project.business_unit_id != business_unit_id:
        raise HTTPException(status_code=400, detail="Selected Project does not belong to selected Business unit")

    bu_result = await db.execute(
        select(BusinessUnitModel).where(
            BusinessUnitModel.id == project.business_unit_id,
            BusinessUnitModel.organization_id == organization_id
        )
    )
    business_unit = bu_result.scalar_one_or_none()
    if not business_unit:
        raise HTTPException(status_code=404, detail="Business unit not found in this organization")

    return business_unit, project

async def assign_user_to_project_team(
    db: AsyncSession,
    user: UserModel,
    project: ProjectModel,
    project_role: str,
    invited_by: Optional[str]
) -> ProjectTeamMemberModel:
    existing_result = await db.execute(
        select(ProjectTeamMemberModel).where(
            ProjectTeamMemberModel.project_id == project.id,
            ProjectTeamMemberModel.email == user.email
        )
    )
    existing_member = existing_result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if existing_member:
        existing_member.user_id = user.id
        existing_member.name = user.name
        existing_member.project_role = project_role
        existing_member.status = "active" if user.status == "active" else "invited"
        existing_member.invited_by = invited_by
        existing_member.invited_at = now
        existing_member.accepted_at = now if existing_member.status == "active" else None
        existing_member.updated_at = now
        return existing_member

    member = ProjectTeamMemberModel(
        organization_id=user.organization_id,
        project_id=project.id,
        user_id=user.id,
        email=user.email,
        name=user.name,
        project_role=project_role,
        status="active" if user.status == "active" else "invited",
        invited_by=invited_by,
        accepted_at=now if user.status == "active" else None
    )
    db.add(member)
    await db.flush()
    return member

async def activate_project_memberships_for_user(db: AsyncSession, user: UserModel):
    now = datetime.now(timezone.utc)
    await db.execute(
        update(ProjectTeamMemberModel)
        .where(
            (ProjectTeamMemberModel.user_id == user.id) | (ProjectTeamMemberModel.email == user.email),
            ProjectTeamMemberModel.organization_id == user.organization_id,
            ProjectTeamMemberModel.status == "invited"
        )
        .values(status="active", accepted_at=now, updated_at=now)
    )

# ==================== UNIQUENESS HELPERS ====================

async def assert_unique_email(db: AsyncSession, email: str):
    """
    Enforces global uniqueness of email across:
    - users
    - admins
    - user requests
    - individual user requests
    """
    checks = [
        select(UserModel).where(UserModel.email == email),
        select(AdminModel).where(AdminModel.email == email),
        select(UserRequestModel).where(
            UserRequestModel.email == email,
            UserRequestModel.status == "pending"
        ),
        select(IndividualUserRequestModel).where(
            IndividualUserRequestModel.email == email,
            IndividualUserRequestModel.status == "pending"
        ),
    ]

    for stmt in checks:
        result = await db.execute(stmt)
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=400,
                detail="An account or request with this email already exists"
            )


async def assert_unique_organization(
    db: AsyncSession,
    *,
    external_org_id: str | None = None,
    domain: str | None = None
):
    """
    Enforces one account per organization.
    Priority:
    1. external_org_id (strongest)
    2. domain (fallback)
    """

    if external_org_id:
        result = await db.execute(
            select(OrganizationModel).where(
                OrganizationModel.external_org_id == external_org_id
            )
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=400,
                detail="An organization account already exists for this organization"
            )

    if domain:
        result = await db.execute(
            select(OrganizationModel).where(
                OrganizationModel.domain == domain
            )
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=400,
                detail="An organization with this domain already exists"
            )


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
    organization_name = await get_organization_name(db, admin.organization_id, admin.organization_name)
    return {
        "token": token,
        "admin": {
            "id": admin.id,
            "email": admin.email,
            "name": admin.name,
            "role": admin.role,
            "organization_id": admin.organization_id,
            "organization_name": organization_name
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
        "organization_name": await get_organization_name(db, admin.organization_id, admin.organization_name),
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

# ==================== USER FIRST LOGIN FLOW ====================

@api_router.post("/public/user/verify-token", tags=["User First Login"])
async def verify_first_login_token(email: str, token: str, db: AsyncSession = Depends(get_db)):
    """
    Verify user's first login token and return user info.
    Used when user clicks the setup link.
    """

    result = await db.execute(
        select(UserModel).where(
            UserModel.email == email,
            UserModel.first_login_token == token
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # 🔑 Sync from Auth0 before exposing state
    await sync_user_from_auth0(user, db)

    # Block reuse after activation
    if user.status == "active":
        raise HTTPException(
            status_code=400,
            detail="Account setup already completed"
        )

    return {
        "valid": True,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "organization_name": await get_organization_name(db, user.organization_id, user.organization_name),
            "email_verified": user.email_verified,
            "password_set": user.password_set
        }
    }


@api_router.post("/public/user/verify-email", tags=["User First Login"])
async def verify_user_email(email: str, token: str, db: AsyncSession = Depends(get_db)):
    """
    Mark user's email as verified after they click the verification link.
    """
    result = await db.execute(
        select(UserModel).where(
            UserModel.email == email,
            UserModel.first_login_token == token
        )
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    user.email_verified = True
    user.first_login_token = None
    
    # Also verify in Auth0 if we have the user ID
    if user.auth0_user_id:
        await auth0_mgmt.verify_user_email(user.auth0_user_id)
    
    await db.commit()
    
    return {
        "message": "Email verified successfully",
        "email_verified": True,
        "password_set": user.password_set,
        "next_step": "set_password" if not user.password_set else "login"
    }


@api_router.post("/public/user/set-password", tags=["User First Login"])
async def set_user_password(email: str, token: str, password: str, db: AsyncSession = Depends(get_db)):
    """
    Set user's password for the first time.
    Also updates the password in Auth0.
    """
    result = await db.execute(
        select(UserModel).where(
            UserModel.email == email,
            UserModel.first_login_token == token
        )
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    # Validate password strength
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    
    # Update password in Auth0
    if user.auth0_user_id:
        auth0_result = await auth0_mgmt.update_user_password(user.auth0_user_id, password)
        if not auth0_result.get("success"):
            raise HTTPException(
                status_code=500, 
                detail=f"Failed to set password in Auth0: {auth0_result.get('error')}"
            )
    
    # Mark password as set and email as verified
    user.password_set = True
    user.email_verified = True
    user.status = "active"
    user.first_login_token = None  # Clear the token after successful setup
    await activate_project_memberships_for_user(db, user)
    
    await db.commit()
    
    return {
        "message": "Password set successfully. You can now log in.",
        "email": user.email,
        "status": "active"
    }


@api_router.post("/public/user/confirm-password-set", tags=["User First Login"])
async def confirm_password_set(email: str, db: AsyncSession = Depends(get_db)):
    """
    Confirm that user has set their password via Auth0.
    Call this after user completes Auth0 password reset flow.
    This marks the user as active and ready to login.
    """

    result = await db.execute(
        select(UserModel).where(UserModel.email == email)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 🔑 Sync authoritative state from Auth0
    await sync_user_from_auth0(
        user,
        db,
        allow_password_sync=True,
        allow_status_activation=True
    )

    # If email is STILL not verified, block activation
    if not user.email_verified:
        raise HTTPException(
            status_code=400,
            detail="Please verify your email before completing account setup"
        )

    # Ensure password_set (Auth0 password reset implies this)
    if not user.password_set:
        user.password_set = True

    # Ensure active status
    if user.status != "active":
        user.status = "active"

    # Cleanup token (idempotent)
    if user.first_login_token:
        user.first_login_token = None

    await activate_project_memberships_for_user(db, user)

    await db.commit()

    return {
        "message": "Account setup complete. You can now log in.",
        "email": user.email,
        "status": "active"
    }


@api_router.post("/public/user/forgot-password", tags=["User First Login"])
async def public_user_forgot_password(email: str, db: AsyncSession = Depends(get_db)):
    """
    Request password reset for a user (first login or forgot password).
    This triggers Auth0 to send a password reset email.
    """

    success_message = {
        "message": "If the email is registered, a password reset link will be sent."
    }

    result = await db.execute(
        select(UserModel).where(UserModel.email == email)
    )
    user = result.scalar_one_or_none()

    # Do not reveal whether user exists
    if not user:
        logger.info(f"Password reset requested for unknown email: {email}")
        return success_message

    # 🔑 Sync authoritative state from Auth0
    await sync_user_from_auth0(user, db)

    # Do not allow password reset unless email is verified
    if not user.email_verified:
        logger.info(f"Password reset blocked for unverified user: {email}")
        return success_message

    # Ensure Auth0 user exists
    if not user.auth0_user_id:
        auth0_user = await auth0_mgmt.get_user_by_email(email)
        if auth0_user.get("success"):
            user.auth0_user_id = auth0_user["user"]["user_id"]
            await db.commit()
        else:
            logger.warning(f"No Auth0 account found for {email}")
            return success_message

    # Trigger Auth0 password reset email
    reset_result = await auth0_mgmt.send_password_reset_email(email)

    if reset_result.get("success"):
        logger.info(f"Password reset email sent to: {email}")
    else:
        logger.error(
            f"Failed to send password reset email to {email}: "
            f"{reset_result.get('error')}"
        )

    return success_message

# ==================== ADMIN MANAGEMENT (Super Admin Only) ====================

@api_router.get("/admins", tags=["Admin Management"])
async def get_all_admins(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Get all admin users (super admin only)"""
    result = await db.execute(select(AdminModel).order_by(AdminModel.created_at.desc()))
    admins = result.scalars().all()
    return [await admin_to_dict(db, a) for a in admins]

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
        "organization_name": await get_organization_name(db, admin.organization_id, admin.organization_name),
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
    
    return await organization_to_dict(db, org)

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
    return [await subscription_to_dict(db, s) for s in subs]

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
    return [await user_to_dict(db, u) for u in result.scalars().all()]

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

@api_router.get("/my-organization/business-units", tags=["Org Admin - Business Units"])
async def get_my_business_units(
    include_projects: bool = False,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get Business units for the current approved organization."""
    org = await get_approved_org_for_admin(payload, db)

    result = await db.execute(
        select(BusinessUnitModel)
        .where(BusinessUnitModel.organization_id == org.id)
        .order_by(BusinessUnitModel.name.asc())
    )
    business_units = result.scalars().all()
    response = [model_to_dict(bu, ["tags"]) for bu in business_units]

    if include_projects and business_units:
        bu_ids = [bu.id for bu in business_units]
        projects_result = await db.execute(
            select(ProjectModel)
            .where(ProjectModel.organization_id == org.id, ProjectModel.business_unit_id.in_(bu_ids))
            .order_by(ProjectModel.name.asc())
        )
        projects_by_bu = {}
        for project in projects_result.scalars().all():
            projects_by_bu.setdefault(project.business_unit_id, []).append(model_to_dict(project))

        for bu_data in response:
            bu_data["projects"] = projects_by_bu.get(bu_data["id"], [])

    return response

@api_router.post("/my-organization/business-units", tags=["Org Admin - Business Units"])
async def create_my_business_unit(
    data: BusinessUnitCreate,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Onboard a Business unit for the current approved organization."""
    org = await get_approved_org_for_admin(payload, db)
    business_unit = await create_business_unit_for_org(db, org, data, created_by=payload.get("sub"))
    await db.commit()

    return {"message": "Business unit created successfully", "business_unit": model_to_dict(business_unit, ["tags"])}

@api_router.get("/my-organization/business-units/{business_unit_id}", tags=["Org Admin - Business Units"])
async def get_my_business_unit(
    business_unit_id: str,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get Business unit details and its projects for the current approved organization."""
    org = await get_approved_org_for_admin(payload, db)

    result = await db.execute(
        select(BusinessUnitModel).where(
            BusinessUnitModel.id == business_unit_id,
            BusinessUnitModel.organization_id == org.id
        )
    )
    business_unit = result.scalar_one_or_none()
    if not business_unit:
        raise HTTPException(status_code=404, detail="Business unit not found")

    projects_result = await db.execute(
        select(ProjectModel)
        .where(ProjectModel.organization_id == org.id, ProjectModel.business_unit_id == business_unit_id)
        .order_by(ProjectModel.name.asc())
    )
    response = model_to_dict(business_unit, ["tags"])
    response["projects"] = [model_to_dict(project) for project in projects_result.scalars().all()]
    return response

@api_router.put("/my-organization/business-units/{business_unit_id}", tags=["Org Admin - Business Units"])
async def update_my_business_unit(
    business_unit_id: str,
    data: BusinessUnitUpdate,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Update a Business unit for the current approved organization."""
    org = await get_approved_org_for_admin(payload, db)

    result = await db.execute(
        select(BusinessUnitModel).where(
            BusinessUnitModel.id == business_unit_id,
            BusinessUnitModel.organization_id == org.id
        )
    )
    business_unit = result.scalar_one_or_none()
    if not business_unit:
        raise HTTPException(status_code=404, detail="Business unit not found")

    update_data = data.model_dump(exclude_unset=True)
    if "name" in update_data:
        update_data["name"] = update_data["name"].strip()
        if not update_data["name"]:
            raise HTTPException(status_code=400, detail="Business unit name is required")
    if "code" in update_data:
        update_data["code"] = update_data["code"].strip() if update_data["code"] else None
    if "status" in update_data and update_data["status"] not in ["active", "inactive", "archived"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    if "sync_status" in update_data and update_data["sync_status"] not in ["synced", "pending", "failed"]:
        raise HTTPException(status_code=400, detail="Invalid sync status")
    for count_key in ["members_count", "consumers_count"]:
        if count_key in update_data and update_data[count_key] is not None:
            update_data[count_key] = max(update_data[count_key], 0)
    if "tags" in update_data:
        update_data["tags"] = json.dumps(update_data["tags"] or [])
    if "owner_name" in update_data:
        update_data["owner_name"] = await resolve_organization_user_label(
            db,
            org.id,
            update_data["owner_name"],
            "Business unit owner",
        )

    await assert_business_unit_unique(
        db,
        organization_id=org.id,
        name=update_data.get("name"),
        code=update_data.get("code"),
        exclude_id=business_unit_id
    )

    for key, value in update_data.items():
        setattr(business_unit, key, value)
    business_unit.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {"message": "Business unit updated successfully", "business_unit": model_to_dict(business_unit, ["tags"])}

@api_router.get("/my-organization/business-units/{business_unit_id}/projects", tags=["Org Admin - Projects"])
async def get_my_business_unit_projects(
    business_unit_id: str,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get projects for one Business unit in the current approved organization."""
    org = await get_approved_org_for_admin(payload, db)

    bu_result = await db.execute(
        select(BusinessUnitModel).where(
            BusinessUnitModel.id == business_unit_id,
            BusinessUnitModel.organization_id == org.id
        )
    )
    if not bu_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Business unit not found")

    result = await db.execute(
        select(ProjectModel)
        .where(ProjectModel.organization_id == org.id, ProjectModel.business_unit_id == business_unit_id)
        .order_by(ProjectModel.name.asc())
    )
    return [model_to_dict(project) for project in result.scalars().all()]

@api_router.get("/my-organization/projects", tags=["Org Admin - Projects"])
async def get_my_projects(
    business_unit_id: Optional[str] = None,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get projects for the current approved organization."""
    org = await get_approved_org_for_admin(payload, db)

    query = select(ProjectModel).where(ProjectModel.organization_id == org.id)
    if business_unit_id:
        query = query.where(ProjectModel.business_unit_id == business_unit_id)

    result = await db.execute(query.order_by(ProjectModel.name.asc()))
    return [model_to_dict(project) for project in result.scalars().all()]

@api_router.post("/my-organization/projects", tags=["Org Admin - Projects"])
async def create_my_project(
    data: ProjectCreate,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Onboard a project for the current approved organization."""
    org = await get_approved_org_for_admin(payload, db)
    if not data.business_unit_id:
        raise HTTPException(status_code=400, detail="Business unit is required when onboarding a Project")
    project = await create_project_for_org(
        db,
        org,
        ExternalProjectCreate(**data.model_dump()),
        created_by=payload.get("sub")
    )
    await db.commit()

    return {"message": "Project created successfully", "project": model_to_dict(project)}

@api_router.get("/my-organization/projects/{project_id}", tags=["Org Admin - Projects"])
async def get_my_project(
    project_id: str,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get project details for the current approved organization."""
    org = await get_approved_org_for_admin(payload, db)

    result = await db.execute(
        select(ProjectModel).where(
            ProjectModel.id == project_id,
            ProjectModel.organization_id == org.id
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    response = model_to_dict(project)
    if project.business_unit_id:
        bu_result = await db.execute(
            select(BusinessUnitModel).where(
                BusinessUnitModel.id == project.business_unit_id,
                BusinessUnitModel.organization_id == org.id
            )
        )
        business_unit = bu_result.scalar_one_or_none()
        response["business_unit"] = model_to_dict(business_unit) if business_unit else None
    else:
        response["business_unit"] = None

    return response

@api_router.put("/my-organization/projects/{project_id}", tags=["Org Admin - Projects"])
async def update_my_project(
    project_id: str,
    data: ProjectUpdate,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Update a project for the current approved organization."""
    org = await get_approved_org_for_admin(payload, db)

    result = await db.execute(
        select(ProjectModel).where(
            ProjectModel.id == project_id,
            ProjectModel.organization_id == org.id
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    update_data = data.model_dump(exclude_unset=True)
    if "name" in update_data:
        update_data["name"] = update_data["name"].strip()
        if not update_data["name"]:
            raise HTTPException(status_code=400, detail="Project name is required")
    if "code" in update_data:
        update_data["code"] = update_data["code"].strip() if update_data["code"] else None
    if "status" in update_data and update_data["status"] not in ["active", "inactive", "archived"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    if update_data.get("business_unit_id"):
        bu_result = await db.execute(
            select(BusinessUnitModel).where(
                BusinessUnitModel.id == update_data["business_unit_id"],
                BusinessUnitModel.organization_id == org.id
            )
        )
        if not bu_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Business unit not found")

    await assert_project_unique(
        db,
        organization_id=org.id,
        name=update_data.get("name"),
        code=update_data.get("code"),
        exclude_id=project_id
    )

    for key, value in update_data.items():
        setattr(project, key, value)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {"message": "Project updated successfully", "project": model_to_dict(project)}

@api_router.get("/my-organization/projects/{project_id}/team", tags=["Org Admin - Project Members"])
async def get_my_project_team(
    project_id: str,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get invited and active project members for a project in the current organization."""
    org = await get_approved_org_for_admin(payload, db)
    await get_project_for_org(db, project_id, org.id)

    result = await db.execute(
        select(ProjectTeamMemberModel)
        .where(
            ProjectTeamMemberModel.organization_id == org.id,
            ProjectTeamMemberModel.project_id == project_id
        )
        .order_by(ProjectTeamMemberModel.invited_at.desc())
    )
    return [await project_team_member_to_dict(db, member) for member in result.scalars().all()]

@api_router.get("/my-organization/project-team-members", tags=["Org Admin - Project Members"])
async def get_my_project_team_members(
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get project members across all projects and Business units."""
    org = await get_approved_org_for_admin(payload, db)

    result = await db.execute(
        select(ProjectTeamMemberModel, ProjectModel, BusinessUnitModel)
        .join(ProjectModel, ProjectTeamMemberModel.project_id == ProjectModel.id)
        .outerjoin(BusinessUnitModel, ProjectModel.business_unit_id == BusinessUnitModel.id)
        .where(
            ProjectTeamMemberModel.organization_id == org.id,
            ProjectModel.organization_id == org.id
        )
        .order_by(ProjectTeamMemberModel.invited_at.desc())
    )

    response = []
    for member, project, business_unit in result.all():
        member_data = await project_team_member_to_dict(db, member)
        member_data["project"] = model_to_dict(project)
        member_data["business_unit"] = model_to_dict(business_unit, ["tags"]) if business_unit else None
        member_data["business_unit_name"] = business_unit.name if business_unit else None
        member_data["application_name"] = business_unit.application_name if business_unit else None
        member_data["application_id"] = business_unit.application_id if business_unit else None
        response.append(member_data)

    return response

@api_router.post("/my-organization/projects/{project_id}/team/invite", tags=["Org Admin - Project Members"])
async def invite_my_project_team(
    project_id: str,
    data: ProjectTeamInviteCreate,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Invite one or more organization-domain users to a project."""
    org = await get_approved_org_for_admin(payload, db)
    project = await get_project_for_org(db, project_id, org.id)
    project_role = (data.project_role or "member").strip().lower()
    if project_role not in ["manager", "member", "viewer"]:
        raise HTTPException(status_code=400, detail="Project role must be manager, member, or viewer")

    emails = []
    seen = set()
    for raw_email in data.emails or []:
        email = normalize_email(raw_email)
        if not email or email in seen:
            continue
        assert_email_allowed_for_org(email, org)
        seen.add(email)
        emails.append(email)

    if not emails:
        raise HTTPException(status_code=400, detail="At least one email address is required")

    invited = []
    skipped = []
    for email in emails:
        user_result = await db.execute(
            select(UserModel).where(
                UserModel.email == email,
                UserModel.organization_id == org.id,
            )
        )
        user = user_result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=400, detail=f"User {email} is not present in this organization")
        if user.status != "active":
            raise HTTPException(status_code=400, detail=f"User {email} is not active")

        existing_member_result = await db.execute(
            select(ProjectTeamMemberModel).where(
                ProjectTeamMemberModel.project_id == project.id,
                ProjectTeamMemberModel.email == email
            )
        )
        existing_member = existing_member_result.scalar_one_or_none()
        if existing_member:
            if existing_member.status == "removed":
                existing_member.status = "invited"
                existing_member.project_role = project_role
                existing_member.invited_by = payload.get("sub")
                existing_member.invited_at = datetime.now(timezone.utc)
                existing_member.updated_at = datetime.now(timezone.utc)
                invited.append(existing_member)
            else:
                skipped.append({"email": email, "reason": "Already invited to this project"})
            continue

        accepted_at = datetime.now(timezone.utc)

        member = ProjectTeamMemberModel(
            organization_id=org.id,
            project_id=project.id,
            user_id=user.id,
            email=email,
            name=user.name,
            project_role=project_role,
            status="active",
            invited_by=payload.get("sub"),
            accepted_at=accepted_at
        )
        db.add(member)
        await db.flush()
        invited.append(member)

    await db.commit()

    email_results = []
    for member in invited:
        member_user = None
        if member.user_id:
            member_user_result = await db.execute(select(UserModel).where(UserModel.id == member.user_id))
            member_user = member_user_result.scalar_one_or_none()
        setup_url = build_setup_account_url(member.email, member_user.first_login_token) if member_user else None
        email_result = send_project_invite_email(
            to_email=member.email,
            invitee_name=member.name or derive_name_from_email(member.email),
            organization_name=org.name,
            project_name=project.name,
            project_role=member.project_role,
            setup_url=setup_url,
            invited_by_email=payload.get("email")
        )
        email_results.append({
            "email": member.email,
            **email_result
        })

    return {
        "message": f"Invited {len(invited)} project member(s) to {project.name}",
        "invited": [await project_team_member_to_dict(db, member) for member in invited],
        "skipped": skipped,
        "emails": email_results
    }

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
    return [await billing_to_dict(db, b) for b in result.scalars().all()]

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
    return [await user_request_to_dict(db, r) for r in result.scalars().all()]

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
async def approve_user_request_org_admin(
    request_id: str,
    role_id: str,
    project_id: str,
    business_unit_id: Optional[str] = None,
    project_role: str = "member",
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
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
    project_role = (project_role or "member").strip().lower()
    if project_role not in ["manager", "member", "viewer"]:
        raise HTTPException(status_code=400, detail="Project role must be manager, member, or viewer")
    business_unit, project = await validate_user_request_team_assignment(db, org_id, project_id, business_unit_id)
    # Check if user with this email already exists
    existing_user = await db.execute(select(UserModel).where(UserModel.email == req.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="A user with this email already exists")
    now = datetime.now(timezone.utc)
    
    # Update request
    req.status = "approved"
    req.approved_at = now
    req.updated_at = now
    req.approved_role_id = role_id
    req.approved_business_unit_id = business_unit.id
    req.approved_project_id = project.id
    req.approved_project_role = project_role
    
    # Create user with verification fields
    user = UserModel(
        email=req.email,
        name=req.name,
        organization_id=org_id,
        organization_name=req.organization_name,
        role_id=role_id,
        role_name=role.name,
        status="pending_verification",
        email_verified=False,
        password_set=False,
        first_login_token=secrets.token_urlsafe(32)
    )
    db.add(user)
    await db.flush()
    team_member = await assign_user_to_project_team(db, user, project, project_role, payload.get("sub"))
    
    # Create user in Auth0
    auth0_result = await auth0_mgmt.create_user(
        email=req.email,
        name=req.name,
        user_metadata={
            "probestack_user_id": user.id,
            "organization_id": org_id,
            "organization_name": req.organization_name
        }
    )
    
    if auth0_result.get("success"):
        user.auth0_user_id = auth0_result.get("auth0_user_id")
        logger.info(f"Auth0 user created for {req.email}: {user.auth0_user_id}")
        # Send verification email via Auth0
        await auth0_mgmt.send_verification_email(user.auth0_user_id)
    elif auth0_result.get("exists"):
        existing_user = await auth0_mgmt.get_user_by_email(req.email)
        if existing_user.get("success"):
            user.auth0_user_id = existing_user["user"]["user_id"]
            # Send verification email for existing Auth0 user
            await auth0_mgmt.send_verification_email(user.auth0_user_id)
    else:
        logger.warning(f"Failed to create Auth0 user for {req.email}: {auth0_result.get('error')}")
    
    await db.commit()
    
    # Generate setup account URL
    base_url = os.environ.get("APP_URL", "")
    setup_url = f"{base_url}/setup-account?email={req.email}&token={user.first_login_token}" if base_url else None
    
    return {
        "message": "User request approved",
        "user_id": user.id,
        "user": {
            "name": user.name,
            "email": user.email,
            "role": role.name,
            "auth0_user_id": user.auth0_user_id,
            "status": user.status
        },
        "business_unit": model_to_dict(business_unit, ["tags"]),
        "team": model_to_dict(project),
        "team_member": await project_team_member_to_dict(db, team_member),
        "setup_url": setup_url,
        "next_steps": "User will receive an email to verify their email address and set their password."
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
    return [await admin_to_dict(db, a) for a in result.scalars().all()]

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
    """Toggle organization admin active status (org admin only)"""
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
        raise HTTPException(status_code=404, detail="Organization admin not found")
    
    admin.is_active = not admin.is_active
    await db.commit()
    
    return {"message": f"Organization admin {'activated' if admin.is_active else 'deactivated'}"}

@api_router.delete("/my-organization/team/{admin_id}", tags=["Org Admin"])
async def delete_team_member(admin_id: str, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Delete an organization admin account (org admin only)"""
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
        raise HTTPException(status_code=404, detail="Organization admin not found")
    
    await db.execute(delete(AdminModel).where(AdminModel.id == admin_id))
    await db.commit()
    
    return {"message": "Organization admin removed"}

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
    return [await upgrade_request_to_dict(db, r) for r in result.scalars().all()]

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
    
    # Get active subscriptions
    sub_result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == org_id)
        .where(SubscriptionModel.status == "active")
        .order_by(SubscriptionModel.created_at.desc())
    )
    active_subscriptions = sub_result.scalars().all()
    subscriptions_data = [await subscription_to_dict(db, sub) for sub in active_subscriptions]
    
    # Counts
    user_count = await db.scalar(select(func.count()).select_from(UserModel).where(UserModel.organization_id == org_id))
    role_count = await db.scalar(select(func.count()).select_from(RoleModel).where(RoleModel.organization_id == org_id))
    business_unit_count = await db.scalar(select(func.count()).select_from(BusinessUnitModel).where(BusinessUnitModel.organization_id == org_id))
    project_count = await db.scalar(select(func.count()).select_from(ProjectModel).where(ProjectModel.organization_id == org_id))
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
        "organization": await organization_to_dict(db, org) if org else None,
        "subscription": subscriptions_data[0] if subscriptions_data else None,
        "subscriptions": subscriptions_data,
        "active_subscriptions": len(subscriptions_data),
        "total_users": user_count or 0,
        "total_roles": role_count or 0,
        "total_business_units": business_unit_count or 0,
        "total_projects": project_count or 0,
        "pending_user_requests": pending_user_requests or 0,
        "total_billed": total_billed
    }

# ==================== PLAN UPGRADE REQUESTS (Org Admin) ====================

@api_router.post("/my-organization/request-upgrade", tags=["Org Admin"])
async def request_plan_upgrade(data: PlanUpgradeCreate, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Request a plan upgrade for current organization (org admin only) - supports multiple plans"""
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
    
    # Get current subscriptions
    sub_result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == org_id)
        .where(SubscriptionModel.status == "active")
    )
    current_subs = sub_result.scalars().all()
    
    # Build current plan info
    current_plan_ids = [s.plan_id for s in current_subs]
    current_plan_names = [await get_plan_name(db, s.plan_id, s.plan_name) for s in current_subs]
    
    requested_selections = normalize_plan_selections(data)

    # Validate requested plans exist and build details
    if not requested_selections:
        raise HTTPException(status_code=400, detail="At least one plan must be selected")
    
    requested_plan_ids = []
    requested_plans_details = []
    all_tools = []
    
    for plan_selection in requested_selections:
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_selection.plan_id))
        plan = plan_result.scalar_one_or_none()
        if not plan:
            raise HTTPException(status_code=404, detail=f"Plan {plan_selection.plan_id} not found")
        product = await get_plan_product(db, plan)
        
        requested_plan_ids.append(plan_selection.plan_id)
        requested_plans_details.append({
            "plan_id": plan.id,
            "plan_name": plan.name,
            "product_id": product.id if product else None,
            "product_name": product.name if product else None,
            "tools": plan_selection.tool_ids
        })
        all_tools.extend(plan_selection.tool_ids)
    
    # Check for existing pending request
    existing = await db.execute(
        select(PlanUpgradeRequestModel)
        .where(PlanUpgradeRequestModel.organization_id == org_id)
        .where(PlanUpgradeRequestModel.status == "pending")
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="You already have a pending upgrade request")
    
    # For backward compatibility, use first plan for old columns
    first_plan_id = requested_plan_ids[0] if requested_plan_ids else ""
    first_plan_name = requested_plans_details[0]["plan_name"] if requested_plans_details else ""
    
    # Create upgrade request
    upgrade_request = PlanUpgradeRequestModel(
        organization_id=org_id,
        organization_name=org.name,
        current_plan_id=json.dumps(current_plan_ids),
        current_plan_name=", ".join(current_plan_names) if current_plan_names else "None",
        # Old columns for backward compatibility (NOT NULL in DB)
        requested_plan_id=first_plan_id,
        requested_plan_name=first_plan_name,
        # New multi-plan columns
        requested_plan_ids=json.dumps(requested_plan_ids),
        requested_plans_details=json.dumps(requested_plans_details),
        requested_tools=json.dumps(all_tools),
        reason=data.reason,
        requested_by=payload["sub"]
    )
    db.add(upgrade_request)
    await db.flush()
    await set_upgrade_request_items(db, upgrade_request.id, requested_selections)
    
    # Create notification
    plan_names = [d["plan_name"] for d in requested_plans_details]
    notif = NotificationModel(
        title="Plan Upgrade Request",
        message=f"{org.name} requested to change plans to: {', '.join(plan_names)}",
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
            "from_plans": current_plan_names,
            "to_plans": plan_names,
            "requested_tools": all_tools
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
    return [await upgrade_request_to_dict(db, r) for r in result.scalars().all()]

@api_router.get("/upgrade-requests/pending", tags=["Upgrade Requests"])
async def get_pending_upgrade_requests(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Get all pending upgrade requests (super admin only)"""
    result = await db.execute(
        select(PlanUpgradeRequestModel)
        .where(PlanUpgradeRequestModel.status == "pending")
        .order_by(PlanUpgradeRequestModel.created_at.desc())
    )
    return [await upgrade_request_to_dict(db, r) for r in result.scalars().all()]

@api_router.post("/upgrade-requests/{request_id}/approve", tags=["Upgrade Requests"])
async def approve_upgrade_request(request_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Approve a plan upgrade request (super admin only) - supports multiple plans"""
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
    
    requested_plans = await get_upgrade_request_items(db, req)
    
    # Create new subscriptions for each requested plan
    created_subs = []
    for plan_detail in requested_plans:
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_detail["plan_id"]))
        plan = plan_result.scalar_one_or_none()
        if plan:
            tools = plan_detail.get("tools", [])
            total_price = await calculate_plan_total(db, plan, tools, "monthly")
            await cancel_active_real_org_subscription_for_plan(db, req.organization_id, plan.id)
            
            new_sub = SubscriptionModel(
                organization_id=req.organization_id,
                organization_name=req.organization_name,
                plan_id=plan.id,
                plan_name=plan.name,
                tools=json.dumps(tools),
                status="active",
                start_date=now,
                end_date=now + timedelta(days=30),
                billing_cycle="monthly",
                amount=total_price
            )
            db.add(new_sub)
            await db.flush()
            await set_subscription_tools(db, new_sub.id, plan.id, tools)
            created_subs.append({"plan": plan.name, "tools": tools})
    await sync_organization_requested_from_active_subscriptions(db, req.organization_id)
    
    # Create notification
    plan_names = [p.get("plan_name", p.get("plan_id", "Unknown")) for p in requested_plans]
    notif = NotificationModel(
        title="Upgrade Request Approved",
        message=f"{req.organization_name} upgraded to: {', '.join(plan_names)}",
        type="success"
    )
    db.add(notif)
    
    await db.commit()
    
    return {"message": "Upgrade request approved", "new_plans": plan_names, "subscriptions": created_subs}

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
    return [await upgrade_request_to_dict(db, r) for r in result.scalars().all()]

@api_router.get("/plan-upgrade-requests/pending", tags=["Plan Upgrade Requests"])
async def get_pending_plan_upgrade_requests(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Get pending plan upgrade requests (super admin only)"""
    result = await db.execute(
        select(PlanUpgradeRequestModel)
        .where(PlanUpgradeRequestModel.status == "pending")
        .order_by(PlanUpgradeRequestModel.created_at.desc())
    )
    return [await upgrade_request_to_dict(db, r) for r in result.scalars().all()]

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
    
    # Get current active subscriptions
    sub_result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == org_id)
        .where(SubscriptionModel.status == "active")
        .order_by(SubscriptionModel.created_at.desc())
    )
    current_subs = sub_result.scalars().all()
    if not current_subs:
        raise HTTPException(status_code=404, detail="No active subscription found")
    
    requested_selections = normalize_plan_selections(data)
    if not requested_selections:
        raise HTTPException(status_code=400, detail="At least one plan must be selected")
    primary_selection = requested_selections[0]
    current_sub = next((sub for sub in current_subs if sub.plan_id == primary_selection.plan_id), current_subs[0])

    # Validate requested plan exists
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == primary_selection.plan_id))
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
        current_plan_name=await get_plan_name(db, current_sub.plan_id, current_sub.plan_name),
        requested_plan_id=primary_selection.plan_id,
        requested_plan_name=plan.name,
        requested_plan_ids=json.dumps([selection.plan_id for selection in requested_selections]),
        requested_plans_details=json.dumps([
            {"plan_id": selection.plan_id, "tools": selection.tool_ids} for selection in requested_selections
        ]),
        requested_tools=json.dumps([tool for selection in requested_selections for tool in selection.tool_ids]),
        reason=data.reason,
        requested_by=payload["sub"]
    )
    db.add(upgrade_request)
    await db.flush()
    await set_upgrade_request_items(db, upgrade_request.id, requested_selections)
    
    # Create notification for super admin
    notif = NotificationModel(
        title="Plan Upgrade Request",
        message=f"{org.name} requested upgrade to {plan.name}",
        type="info",
        link=f"/plan-upgrade-requests"
    )
    db.add(notif)
    
    await db.commit()
    return await upgrade_request_to_dict(db, upgrade_request)

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
    
    request_items = await get_upgrade_request_items(db, request)

    for item in request_items:
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == item["plan_id"]))
        plan = plan_result.scalar_one_or_none()
        if not plan:
            continue
        tools = item.get("tools", [])
        total_price = await calculate_plan_total(db, plan, tools, "monthly")
        await cancel_active_real_org_subscription_for_plan(db, request.organization_id, plan.id)
        subscription = SubscriptionModel(
            organization_id=request.organization_id,
            organization_name=await get_organization_name(db, request.organization_id, request.organization_name),
            plan_id=plan.id,
            plan_name=plan.name,
            tools=json.dumps(tools),
            status="active",
            start_date=now,
            end_date=now + timedelta(days=30),
            billing_cycle="monthly",
            amount=total_price
        )
        db.add(subscription)
        await db.flush()
        await set_subscription_tools(db, subscription.id, plan.id, tools)
    await sync_organization_requested_from_active_subscriptions(db, request.organization_id)
    
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
    recent_orgs = [await organization_to_dict(db, o) for o in result.scalars().all()]
    
    result = await db.execute(select(SubscriptionModel).order_by(SubscriptionModel.created_at.desc()).limit(5))
    recent_subs = [await subscription_to_dict(db, s) for s in result.scalars().all()]
    
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
        tools = await get_subscription_tools(db, sub)
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
    return [await organization_to_dict(db, o) for o in result.scalars().all()]

@api_router.get("/organizations/pending")
async def get_pending_organizations(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.status == "pending").order_by(OrganizationModel.created_at.desc()))
    return [await organization_to_dict(db, o) for o in result.scalars().all()]

@api_router.get("/organizations/{org_id}/details")
async def get_organization_details(org_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Get one organization's full Business unit, project, and project-member structure."""
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    bu_result = await db.execute(
        select(BusinessUnitModel)
        .where(BusinessUnitModel.organization_id == org_id)
        .order_by(BusinessUnitModel.name.asc())
    )
    business_units = [model_to_dict(bu, ["tags"]) for bu in bu_result.scalars().all()]

    project_result = await db.execute(
        select(ProjectModel)
        .where(ProjectModel.organization_id == org_id)
        .order_by(ProjectModel.name.asc())
    )
    teams = [model_to_dict(project) for project in project_result.scalars().all()]

    member_result = await db.execute(
        select(ProjectTeamMemberModel, ProjectModel, BusinessUnitModel)
        .join(ProjectModel, ProjectTeamMemberModel.project_id == ProjectModel.id)
        .outerjoin(BusinessUnitModel, ProjectModel.business_unit_id == BusinessUnitModel.id)
        .where(ProjectTeamMemberModel.organization_id == org_id)
        .order_by(ProjectTeamMemberModel.invited_at.desc())
    )
    team_members = []
    for member, project, business_unit in member_result.all():
        member_data = await project_team_member_to_dict(db, member)
        member_data["team"] = model_to_dict(project)
        member_data["business_unit"] = model_to_dict(business_unit, ["tags"]) if business_unit else None
        team_members.append(member_data)

    return {
        "organization": await organization_to_dict(db, org),
        "business_units": business_units,
        "teams": teams,
        "team_members": team_members
    }

@api_router.get("/organizations/{org_id}/business-units")
async def get_organization_business_units(
    org_id: str,
    include_teams: bool = True,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get all Business units for one organization, optionally including projects under each Business unit."""
    org_result = await db.execute(select(OrganizationModel.id).where(OrganizationModel.id == org_id))
    if not org_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Organization not found")

    result = await db.execute(
        select(BusinessUnitModel)
        .where(BusinessUnitModel.organization_id == org_id)
        .order_by(BusinessUnitModel.name.asc())
    )
    business_units = result.scalars().all()
    response = [model_to_dict(bu, ["tags"]) for bu in business_units]

    if include_teams and business_units:
        bu_ids = [bu.id for bu in business_units]
        projects_result = await db.execute(
            select(ProjectModel)
            .where(ProjectModel.organization_id == org_id, ProjectModel.business_unit_id.in_(bu_ids))
            .order_by(ProjectModel.name.asc())
        )
        projects_by_bu = {}
        for project in projects_result.scalars().all():
            projects_by_bu.setdefault(project.business_unit_id, []).append(model_to_dict(project))
        for bu_data in response:
            bu_data["teams"] = projects_by_bu.get(bu_data["id"], [])
            bu_data["projects"] = bu_data["teams"]

    return response

@api_router.get("/organizations/{org_id}/teams")
async def get_organization_teams(
    org_id: str,
    business_unit_id: Optional[str] = None,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get all projects for one organization, optionally filtered by Business unit."""
    org_result = await db.execute(select(OrganizationModel.id).where(OrganizationModel.id == org_id))
    if not org_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Organization not found")

    query = select(ProjectModel).where(ProjectModel.organization_id == org_id)
    if business_unit_id:
        bu_result = await db.execute(
            select(BusinessUnitModel.id).where(
                BusinessUnitModel.id == business_unit_id,
                BusinessUnitModel.organization_id == org_id
            )
        )
        if not bu_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Business unit not found")
        query = query.where(ProjectModel.business_unit_id == business_unit_id)

    result = await db.execute(query.order_by(ProjectModel.name.asc()))
    return [model_to_dict(project) for project in result.scalars().all()]

@api_router.get("/organizations/{org_id}")
async def get_organization(org_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return await organization_to_dict(db, org)

@api_router.post("/organizations")
async def create_organization(data: OrganizationCreate, db: AsyncSession = Depends(get_db)):
    org = OrganizationModel(
        name=data.name, email=data.email, domain=data.domain,
        requested_plan=json.dumps(data.requested_plans), requested_tools=json.dumps(data.requested_tools),
        contact_person=data.contact_person, phone=data.phone, address=data.address,
        description=data.description,
        gateway_region=data.gateway_region,
        gateway_organization_name=data.gateway_organization_name,
        gateway_environment_type=data.gateway_environment_type,
        gateway_environments=json.dumps(data.gateway_environments) if data.gateway_environments else None
    )
    db.add(org)
    await db.flush()
    await create_organization_subscription_request(
        db,
        org.id,
        data.requested_plans,
        data.requested_tools,
        status=org.status
    )
    
    notif = NotificationModel(
        title="New Organization Request",
        message=f"{data.name} has requested to join with {', '.join(data.requested_plans)} plan(s)",
        type="info", link=f"/organizations/{org.id}"
    )
    db.add(notif)
    await db.commit()
    return await organization_to_dict(db, org)

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

@api_router.post("/public/login/initiate", tags=["Public API - Login"])
async def initiate_login(data: IdentifyOrgRequest, db: AsyncSession = Depends(get_db)):
    """
    Initiate login flow for all users (organization employees and individual users).
    Called when user enters email in login form.
    """

    if not data.email or "@" not in data.email:
        raise HTTPException(status_code=400, detail="Invalid email format")

    email = data.email.lower().strip()
    email_domain = "@" + email.split("@")[1]

    # ------------------------------------------------------------------
    # STEP 1: Check if user exists
    # ------------------------------------------------------------------
    result = await db.execute(
        select(UserModel).where(UserModel.email == email)
    )
    user = result.scalar_one_or_none()

    if user:
        # 🔑 IMPORTANT: Sync from Auth0 BEFORE branching
        await sync_user_from_auth0(user, db)

        # Fetch org info
        org_result = await db.execute(
            select(OrganizationModel).where(OrganizationModel.id == user.organization_id)
        )
        user_org = org_result.scalar_one_or_none()
        org_name = user_org.name if user_org else user.organization_name

        # --------------------------------------------------------------
        # CASE 1: Fully active user → password login
        # --------------------------------------------------------------
        if user.status == "active" and user.password_set:
            return {
                "success": True,
                "next_step": "password",
                "message": "Please enter your password to login.",
                "user": {
                    "email": user.email,
                    "name": user.name,
                    "organization_id": user.organization_id,
                    "organization_name": org_name
                }
            }

        # --------------------------------------------------------------
        # CASE 2: Email verified but password not set → set password
        # --------------------------------------------------------------
        if user.email_verified and not user.password_set:
            if not user.first_login_token:
                user.first_login_token = secrets.token_urlsafe(32)
                await db.commit()

            return {
                "success": True,
                "next_step": "set_password",
                "message": "Please set your password to complete account setup.",
                "token": user.first_login_token,
                "user": {
                    "email": user.email,
                    "name": user.name,
                    "organization_id": user.organization_id,
                    "organization_name": org_name
                }
            }

        # --------------------------------------------------------------
        # CASE 3: Not verified → resend verification email
        # (At this point Auth0 + DB are already synced)
        # --------------------------------------------------------------
        if not user.first_login_token:
            user.first_login_token = secrets.token_urlsafe(32)

        if user.auth0_user_id:
            await auth0_mgmt.send_verification_email(user.auth0_user_id)

        await db.commit()

        return {
            "success": True,
            "next_step": "verify_email",
            "message": "Please verify your email. A verification email has been sent.",
            "token": user.first_login_token,
            "user": {
                "email": user.email,
                "name": user.name,
                "organization_id": user.organization_id,
                "organization_name": org_name,
                "email_verified": user.email_verified
            }
        }

    # ------------------------------------------------------------------
    # STEP 2: User does NOT exist → match org by domain
    # ------------------------------------------------------------------
    result = await db.execute(
        select(OrganizationModel).where(
            OrganizationModel.status == "approved",
            OrganizationModel.supported_domains.isnot(None),
            OrganizationModel.name != "Individual Users"
        )
    )
    organizations = result.scalars().all()

    matched_org = None
    for org in organizations:
        try:
            domains = json.loads(org.supported_domains or "[]")
            if any(d.lower() == email_domain.lower() for d in domains):
                matched_org = org
                break
        except json.JSONDecodeError:
            continue

    if not matched_org:
        return {
            "success": False,
            "next_step": "request_access",
            "message": f"No account found for {email}. Please submit an individual user request.",
            "action_url": "/individual-user-request"
        }

    # ------------------------------------------------------------------
    # STEP 3: Check for existing pending request
    # ------------------------------------------------------------------
    existing_request = await db.execute(
        select(UserRequestModel).where(
            UserRequestModel.email == email,
            UserRequestModel.organization_id == matched_org.id,
            UserRequestModel.status == "pending"
        )
    )
    if existing_request.scalar_one_or_none():
        return {
            "success": True,
            "next_step": "pending_approval",
            "message": "Your access request is pending admin approval.",
            "user": {
                "email": email,
                "organization_name": matched_org.name
            }
        }

    # ------------------------------------------------------------------
    # STEP 4: Create new user request
    # ------------------------------------------------------------------
    user_request = UserRequestModel(
        email=email,
        name=email.split("@")[0].replace(".", " ").title(),
        organization_id=matched_org.id,
        organization_name=matched_org.name,
        requested_role="Member",
        status="pending"
    )
    db.add(user_request)

    notification = NotificationModel(
        title="New User Request",
        message=f"{user_request.name} ({email}) is requesting access to {matched_org.name}.",
        type="info",
        link="/user-requests"
    )
    db.add(notification)

    await db.commit()

    return {
        "success": True,
        "next_step": "pending_approval",
        "message": "Access request submitted. An admin will review it.",
        "request_id": user_request.id,
        "user": {
            "email": email,
            "name": user_request.name,
            "organization_name": matched_org.name
        }
    }


# ==================== PUBLIC API - Auth0 Authentication ====================

@api_router.get("/public/auth0-config", tags=["Public API"])
async def get_auth0_config():
    """
    Get current Auth0 environment configuration (for debugging).
    Does not expose secrets.
    """
    return {
        "domain": AUTH0_MGMT_DOMAIN,
        "db_connection_name": AUTH0_DB_CONNECTION_NAME,
        "db_connection_id": AUTH0_DB_CONNECTION_ID[:10] + "..." if AUTH0_DB_CONNECTION_ID else None,
        "environment": "dev" if "dev" in AUTH0_DB_CONNECTION_NAME.lower() else 
                       "test" if "test" in AUTH0_DB_CONNECTION_NAME.lower() else 
                       "prod" if "prod" in AUTH0_DB_CONNECTION_NAME.lower() else "unknown"
    }

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

# ==================== INDIVIDUAL USER REQUESTS ====================

@api_router.post("/individual-user-requests", tags=["Public API"])
async def create_individual_user_request(data: IndividualUserRequestCreate, db: AsyncSession = Depends(get_db)):
    """
    Public API: Submit a request for individual user access (no organization).
    Supports multiple plan selection.

    **Request Body:**
    - `email`: User email (required)
    - `name`: User full name (required)
    - `requested_plans`: List of Plan IDs (required) - e.g., ['plan_api_enterprise', 'plan_ai_enterprise']
    - `selected_tools`: List of tool names from the plans (required)
    - `purpose`: Why they need access (optional)
    - `company_name`: Company name if any (optional)
    - `job_title`: Job title (optional)
    - `phone`: Phone number (optional)
    """

    await assert_unique_email(db, data.email)
    # Check if email already has a pending request
    result = await db.execute(
        select(IndividualUserRequestModel).where(
            IndividualUserRequestModel.email == data.email,
            IndividualUserRequestModel.status == "pending"
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="A pending request already exists for this email")

    # Validate all plans exist
    plans_result = await db.execute(select(PlanModel).where(PlanModel.id.in_(data.requested_plans)))
    plans = {p.id: p for p in plans_result.scalars().all()}
    
    invalid_plans = [pid for pid in data.requested_plans if pid not in plans]
    if invalid_plans:
        # Get available plans
        all_plans_result = await db.execute(select(PlanModel.id, PlanModel.name, PlanModel.tool))
        available_plans = [{"id": p.id, "name": p.name, "tool": p.tool} for p in all_plans_result.all()]
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"Invalid plan IDs: {invalid_plans}",
                "available_plans": available_plans
            }
        )

    # Get available tools from ALL selected plans
    tools_result = await db.execute(
        select(PlanToolModel).where(
            PlanToolModel.plan_id.in_(data.requested_plans),
            PlanToolModel.is_active == True
        )
    )
    available_tools = {t.name: t for t in tools_result.scalars().all()}

    # Validate selected tools exist in at least one of the selected plans
    invalid_tools = [t for t in data.selected_tools if t not in available_tools]
    if invalid_tools:
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"Invalid tools: {invalid_tools}",
                "available_tools": list(available_tools.keys())
            }
        )

    # Legacy response fields are retained; manual plan cost is now the source of truth.
    selected_tool_objects = [available_tools[t] for t in data.selected_tools]
    base_monthly = sum((getattr(plans[pid], "cost", None) or plans[pid].price_monthly or 0) for pid in data.requested_plans)
    base_yearly = base_monthly
    tools_monthly = 0
    tools_yearly = 0
    total_monthly = base_monthly
    total_yearly = base_yearly

    # Create request - store plans as JSON array
    request = IndividualUserRequestModel(
        email=data.email,
        name=data.name,
        requested_tools=json.dumps(data.selected_tools),
        requested_plan=json.dumps(data.requested_plans),  # Store as JSON array
        purpose=data.purpose,
        company_name=data.company_name,
        job_title=data.job_title,
        phone=data.phone
    )
    db.add(request)

    # Create notification
    tools_str = ', '.join(data.selected_tools[:3])
    if len(data.selected_tools) > 3:
        tools_str += f" +{len(data.selected_tools) - 3} more"
    plans_str = ', '.join([plans[pid].name for pid in data.requested_plans])
    notif = NotificationModel(
        title="New Individual User Request",
        message=f"{data.name} ({data.email}) has requested {plans_str} with tools: {tools_str}",
        type="info",
        link=f"/individual-requests/{request.id}"
    )
    db.add(notif)

    await db.commit()

    # Build response with plan details
    plan_names = [{"id": pid, "name": plans[pid].name} for pid in data.requested_plans]

    return {
        "id": request.id,
        "email": request.email,
        "name": request.name,
        "selected_tools": data.selected_tools,
        "requested_plans": plan_names,
        "purpose": request.purpose,
        "company_name": request.company_name,
        "job_title": request.job_title,
        "phone": request.phone,
        "status": request.status,
        "pricing": {
            "base_monthly": base_monthly,
            "base_yearly": base_yearly,
            "tools_monthly": tools_monthly,
            "tools_yearly": tools_yearly,
            "total_monthly": total_monthly,
            "total_yearly": total_yearly
        },
        "created_at": request.created_at.isoformat() if request.created_at else None,
        "message": "Your request has been submitted and is pending approval"
    }

@api_router.get("/individual-user-requests", tags=["Admin - Individual Users"])
async def get_individual_user_requests(
    status: Optional[str] = None,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get all individual user requests (Super Admin only)"""
    query = select(IndividualUserRequestModel).order_by(IndividualUserRequestModel.created_at.desc())

    if status:
        query = query.where(IndividualUserRequestModel.status == status)

    result = await db.execute(query)
    requests = result.scalars().all()

    return [
        {
            "id": r.id,
            "email": r.email,
            "name": r.name,
            "requested_tools": json.loads(r.requested_tools) if r.requested_tools else [],
            "requested_plan": r.requested_plan,
            "purpose": r.purpose,
            "company_name": r.company_name,
            "job_title": r.job_title,
            "phone": r.phone,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            "approved_at": r.approved_at.isoformat() if r.approved_at else None,
            "rejected_at": r.rejected_at.isoformat() if r.rejected_at else None,
            "rejection_reason": r.rejection_reason,
            "assigned_user_id": r.assigned_user_id,
            "assigned_subscription_id": r.assigned_subscription_id
        }
        for r in requests
    ]

@api_router.get("/individual-user-requests/pending", tags=["Admin - Individual Users"])
async def get_pending_individual_user_requests(
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get pending individual user requests (Super Admin only)"""
    result = await db.execute(
        select(IndividualUserRequestModel)
        .where(IndividualUserRequestModel.status == "pending")
        .order_by(IndividualUserRequestModel.created_at.desc())
    )
    requests = result.scalars().all()

    return [
        {
            "id": r.id,
            "email": r.email,
            "name": r.name,
            "requested_tools": json.loads(r.requested_tools) if r.requested_tools else [],
            "requested_plans": parse_json_list(r.requested_plan),
            "purpose": r.purpose,
            "company_name": r.company_name,
            "job_title": r.job_title,
            "phone": r.phone,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in requests
    ]

@api_router.post("/individual-user-requests/{request_id}/approve", tags=["Admin - Individual Users"])
async def approve_individual_user_request(
    request_id: str,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Approve an individual user request.
    Creates user with "No Organization" and assigns subscription.
    Also creates user in Auth0.
    """
    result = await db.execute(
        select(IndividualUserRequestModel).where(IndividualUserRequestModel.id == request_id)
    )
    request = result.scalar_one_or_none()
    
    if not request:
        raise HTTPException(status_code=404, detail="Request not found")
    if request.status != "pending":
        raise HTTPException(status_code=400, detail=f"Request is already {request.status}")
    # Check if user with this email already exists
    existing_user = await db.execute(select(UserModel).where(UserModel.email == request.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="A user with this email already exists")
    # Parse requested_plan - can be a JSON array or single string
    requested_plan_raw = request.requested_plan
    try:
        plan_ids = json.loads(requested_plan_raw) if requested_plan_raw.startswith('[') else [requested_plan_raw]
    except (json.JSONDecodeError, AttributeError):
        plan_ids = [requested_plan_raw] if requested_plan_raw else []
    
    if not plan_ids:
        raise HTTPException(status_code=400, detail="No plan specified in request")
    
    # Get the first/primary plan (for subscription)
    primary_plan_id = plan_ids[0]
    result = await db.execute(select(PlanModel).where(PlanModel.id == primary_plan_id))
    plan = result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=400, detail=f"Requested plan '{primary_plan_id}' no longer exists")
    
    # Create a "No Organization" entry if it doesn't exist
    result = await db.execute(
        select(OrganizationModel).where(OrganizationModel.id == "no_organization")
    )
    no_org = result.scalar_one_or_none()
    
    if not no_org:
        no_org = OrganizationModel(
            id="no_organization",
            name="Individual Users",
            email="individual@probestack.io",
            domain=None,
            status="approved",
            requested_plan="plan_api_starter",
            requested_tools=json.dumps(["api_platform"]),
            contact_person="System",
            approved_at=datetime.now(timezone.utc)
        )
        db.add(no_org)
        await db.flush()
    
    # Create or get a default role for individual users
    result = await db.execute(
        select(RoleModel).where(
            RoleModel.name == "Individual User",
            RoleModel.organization_id == "no_organization"
        )
    )
    role = result.scalar_one_or_none()
    
    if not role:
        role = RoleModel(
            name="Individual User",
            organization_id="no_organization",
            permissions=json.dumps(["read", "write"]),
            description="Default role for individual users"
        )
        db.add(role)
        await db.flush()
    
    # Create user with first_login_token for setup flow
    user = UserModel(
        email=request.email,
        name=request.name,
        organization_id="no_organization",
        organization_name="Individual Users",
        role_id=role.id,
        role_name=role.name,
        status="pending_verification",
        email_verified=False,
        password_set=False,
        first_login_token=secrets.token_urlsafe(32)
    )
    db.add(user)
    await db.flush()
    
    # Create user in Auth0
    auth0_result = await auth0_mgmt.create_user(
        email=request.email,
        name=request.name,
        user_metadata={
            "probestack_user_id": user.id,
            "organization_id": "no_organization",
            "organization_name": "Individual Users"
        }
    )
    
    if auth0_result.get("success"):
        user.auth0_user_id = auth0_result.get("auth0_user_id")
        logger.info(f"Auth0 user created for {request.email}: {user.auth0_user_id}")
        # Send verification email via Auth0 (user will set password via our setup page)
        await auth0_mgmt.send_verification_email(user.auth0_user_id)
    elif auth0_result.get("exists"):
        # User already exists in Auth0, try to get their ID
        existing_user = await auth0_mgmt.get_user_by_email(request.email)
        if existing_user.get("success"):
            user.auth0_user_id = existing_user["user"]["user_id"]
            logger.info(f"Auth0 user already exists for {request.email}: {user.auth0_user_id}")
    else:
        logger.warning(f"Failed to create Auth0 user for {request.email}: {auth0_result.get('error')}")
    
    # Create subscription for individual user
    requested_tools = json.loads(request.requested_tools) if request.requested_tools else []
    subscription = SubscriptionModel(
        organization_id="no_organization",
        organization_name=f"Individual: {request.name}",
        plan_id=plan.id,
        plan_name=plan.name,
        tools=json.dumps(requested_tools),
        status="active",
        start_date=datetime.now(timezone.utc),
        end_date=datetime.now(timezone.utc) + timedelta(days=30),
        billing_cycle="monthly",
        amount=plan.price_monthly
    )
    db.add(subscription)
    await db.flush()
    await set_subscription_tools(db, subscription.id, plan.id, requested_tools)
    
    # Update request
    request.status = "approved"
    request.approved_at = datetime.now(timezone.utc)
    request.assigned_user_id = user.id
    request.assigned_subscription_id = subscription.id
    request.updated_at = datetime.now(timezone.utc)
    
    await db.commit()
    
    # Generate setup account URL for the user
    setup_account_url = f"/setup-account?email={user.email}&token={user.first_login_token}"
    
    return {
        "message": f"Individual user request approved for {request.name}",
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "organization_name": "Individual Users",
            "auth0_user_id": user.auth0_user_id,
            "status": user.status,
            "setup_account_url": setup_account_url
        },
        "subscription": {
            "id": subscription.id,
            "plan": plan.name,
            "tools": requested_tools
        },
        "next_steps": "User will receive an email to verify their email address. They can complete setup at the setup account page."
    }

@api_router.post("/individual-user-requests/{request_id}/reject", tags=["Admin - Individual Users"])
async def reject_individual_user_request(
    request_id: str,
    reason: Optional[str] = None,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db)
):
    """Reject an individual user request"""
    result = await db.execute(
        select(IndividualUserRequestModel).where(IndividualUserRequestModel.id == request_id)
    )
    request = result.scalar_one_or_none()

    if not request:
        raise HTTPException(status_code=404, detail="Request not found")
    if request.status != "pending":
        raise HTTPException(status_code=400, detail=f"Request is already {request.status}")

    request.status = "rejected"
    request.rejected_at = datetime.now(timezone.utc)
    request.rejection_reason = reason
    request.updated_at = datetime.now(timezone.utc)

    await db.commit()

    return {"message": f"Individual user request rejected for {request.name}"}

@api_router.delete("/individual-user-requests/{request_id}", tags=["Admin - Individual Users"])
async def delete_individual_user_request(
    request_id: str,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db)
):
    """Delete an individual user request"""
    result = await db.execute(
        select(IndividualUserRequestModel).where(IndividualUserRequestModel.id == request_id)
    )
    request = result.scalar_one_or_none()

    if not request:
        raise HTTPException(status_code=404, detail="Request not found")

    await db.delete(request)
    await db.commit()

    return {"message": "Request deleted successfully"}

@api_router.put("/organizations/{org_id}")
async def update_organization(org_id: str, data: OrganizationUpdate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    update_data = {k: v for k, v in data.model_dump().items() if v is not None}
    if 'supported_domains' in update_data and isinstance(update_data['supported_domains'], list):
        update_data['supported_domains'] = json.dumps(update_data['supported_domains'])
    if 'gateway_environments' in update_data and isinstance(update_data['gateway_environments'], list):
        update_data['gateway_environments'] = json.dumps(update_data['gateway_environments'])

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
    return await organization_to_dict(db, org)

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
    
    requested_plan_details = await get_organization_requested_plan_details(db, org)
    subscription_ids = []

    for plan_detail in requested_plan_details:
        plan_id = plan_detail.get("plan_id")
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
        plan = plan_result.scalar_one_or_none()
        if not plan:
            continue

        tools = plan_detail.get("tools", [])
        plan_amount = await calculate_plan_total(db, plan, tools, "monthly")
        await cancel_active_real_org_subscription_for_plan(db, org_id, plan.id)
        subscription_id = str(uuid.uuid4())
        subscription = SubscriptionModel(
            id=subscription_id,
            organization_id=org_id,
            organization_name=org.name,
            plan_id=plan.id,
            plan_name=plan.name,
            tools=json.dumps(tools),
            status="active",
            start_date=now,
            end_date=now + timedelta(days=30),
            amount=plan_amount
        )
        db.add(subscription)
        await db.flush()
        await set_subscription_tools(db, subscription_id, plan.id, tools)
        subscription_ids.append(subscription_id)

        billing = BillingModel(
            organization_id=org_id,
            organization_name=org.name,
            subscription_id=subscription_id,
            amount=plan_amount,
            status="pending",
            invoice_number=f"INV-{now.strftime('%Y%m%d')}-{org_id[:8].upper()}-{len(subscription_ids)}",
            billing_date=now,
            due_date=now + timedelta(days=7)
        )
        db.add(billing)

    await db.execute(
        update(OrganizationSubscriptionRequestModel)
        .where(OrganizationSubscriptionRequestModel.organization_id == org_id)
        .where(OrganizationSubscriptionRequestModel.status == "pending")
        .values(status="approved", approved_at=now, updated_at=now)
    )
    await sync_organization_requested_from_active_subscriptions(db, org_id)
    
    notif = NotificationModel(title="Organization Approved", message=f"{org.name} has been approved", type="success")
    db.add(notif)
    await db.commit()
    return {
        "message": "Organization approved",
        "subscription_id": subscription_ids[0] if subscription_ids else None,
        "subscription_ids": subscription_ids,
        "plan_ids": [detail["plan_id"] for detail in requested_plan_details]
    }

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
    await db.execute(
        update(OrganizationSubscriptionRequestModel)
        .where(OrganizationSubscriptionRequestModel.organization_id == org_id)
        .where(OrganizationSubscriptionRequestModel.status == "pending")
        .values(status="rejected", rejected_at=now, updated_at=now)
    )
    
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


class OrganizationFullUpdate(BaseModel):
    """Schema for super admin to fully edit an organization"""
    name: Optional[str] = None
    email: Optional[str] = None
    domain: Optional[str] = None
    contact_person: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    description: Optional[str] = None
    external_org_id: Optional[str] = None
    auth0_org_id: Optional[str] = None
    supported_domains: Optional[List[str]] = None
    gateway_region: Optional[str] = None
    gateway_organization_name: Optional[str] = None
    gateway_environment_type: Optional[str] = None
    gateway_environments: Optional[List[str]] = None


@api_router.put("/organizations/{org_id}")
async def update_organization_full(org_id: str, data: OrganizationFullUpdate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Update organization details (super admin only)"""
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Update fields if provided
    if data.name is not None:
        org.name = data.name
    if data.email is not None:
        org.email = data.email
    if data.domain is not None:
        org.domain = data.domain
    if data.contact_person is not None:
        org.contact_person = data.contact_person
    if data.phone is not None:
        org.phone = data.phone
    if data.address is not None:
        org.address = data.address
    if data.description is not None:
        org.description = data.description
    if data.external_org_id is not None:
        org.external_org_id = data.external_org_id if data.external_org_id else None
    if data.auth0_org_id is not None:
        org.auth0_org_id = data.auth0_org_id if data.auth0_org_id else None
    if data.supported_domains is not None:
        org.supported_domains = json.dumps(data.supported_domains) if data.supported_domains else None
    if data.gateway_region is not None:
        org.gateway_region = data.gateway_region if data.gateway_region else None
    if data.gateway_organization_name is not None:
        org.gateway_organization_name = data.gateway_organization_name if data.gateway_organization_name else None
    if data.gateway_environment_type is not None:
        org.gateway_environment_type = data.gateway_environment_type if data.gateway_environment_type else None
    if data.gateway_environments is not None:
        org.gateway_environments = json.dumps(data.gateway_environments) if data.gateway_environments else None
    
    org.updated_at = datetime.now(timezone.utc)
    await db.commit()
    
    return {"message": "Organization updated successfully", "organization": await organization_to_dict(db, org)}


@api_router.put("/organizations/{org_id}/subscription")
async def update_organization_subscription(org_id: str, data: SubscriptionUpdateRequest, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Update organization's subscription - replace plans and tools (super admin only)"""
    # Verify org exists
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    now = datetime.now(timezone.utc)
    
    # Replace only the submitted plans; other active org plans stay active.
    created_subs = []
    for plan_selection in data.plan_selections:
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_selection.plan_id))
        plan = plan_result.scalar_one_or_none()
        if not plan:
            raise HTTPException(status_code=404, detail=f"Plan {plan_selection.plan_id} not found")
        
        total_price = await calculate_plan_total(db, plan, plan_selection.tool_ids, data.billing_cycle)
        end_date = now + timedelta(days=30) if data.billing_cycle == "monthly" else now + timedelta(days=365)
        await cancel_active_real_org_subscription_for_plan(db, org_id, plan.id)
        
        new_sub = SubscriptionModel(
            organization_id=org_id,
            organization_name=org.name,
            plan_id=plan.id,
            plan_name=plan.name,
            tools=json.dumps(plan_selection.tool_ids),
            status="active",
            start_date=now,
            end_date=end_date,
            billing_cycle=data.billing_cycle,
            amount=total_price
        )
        db.add(new_sub)
        await db.flush()
        await set_subscription_tools(db, new_sub.id, plan.id, plan_selection.tool_ids)
        created_subs.append({
            "plan_id": plan.id,
            "plan_name": plan.name,
            "tools": plan_selection.tool_ids,
            "amount": total_price
        })
    
    await sync_organization_requested_from_active_subscriptions(db, org_id)
    
    await db.commit()
    
    return {
        "message": "Organization subscription updated",
        "subscriptions": created_subs
    }


class UserFullUpdate(BaseModel):
    """Schema for super admin to edit a user"""
    name: Optional[str] = None
    email: Optional[str] = None
    role_id: Optional[str] = None
    status: Optional[str] = None
    theme_preference: Optional[str] = None


@api_router.put("/users/{user_id}")
async def update_user_full(user_id: str, data: UserFullUpdate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Update user details (super admin only) - cannot change organization"""
    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update fields if provided
    if data.name is not None:
        user.name = data.name
    if data.email is not None:
        user.email = data.email
    if data.status is not None:
        if data.status not in ["active", "inactive", "suspended", "pending_verification"]:
            raise HTTPException(status_code=400, detail="Invalid status")
        user.status = data.status
    if data.theme_preference is not None:
        if data.theme_preference not in ["light", "dark", "system"]:
            raise HTTPException(status_code=400, detail="Invalid theme preference")
        user.theme_preference = data.theme_preference
    if data.role_id is not None:
        # Validate role exists in user's organization
        role_result = await db.execute(
            select(RoleModel).where(
                RoleModel.id == data.role_id,
                RoleModel.organization_id == user.organization_id
            )
        )
        role = role_result.scalar_one_or_none()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found in user's organization")
        user.role_id = role.id
        user.role_name = role.name
    
    await db.commit()
    
    return {"message": "User updated successfully", "user": model_to_dict(user)}


@api_router.put("/users/{user_id}/subscription")
async def update_individual_user_subscription(user_id: str, data: SubscriptionUpdateRequest, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """
    Update subscription for an individual user (Super Admin only).
    Individual users have their own separate subscription, unlike org employees who share org's subscription.
    """
    # Get user
    user_result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if this is an individual user (belongs to "Individual Users" org or "no_organization")
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == user.organization_id))
    org = org_result.scalar_one_or_none()
    
    is_individual = (
        user.organization_id == "no_organization" or 
        (org and org.name == "Individual Users")
    )
    
    if not is_individual:
        raise HTTPException(
            status_code=400, 
            detail="This user belongs to an organization. Update the organization's subscription instead."
        )
    
    # Get the individual user request to find their subscription
    ind_req_result = await db.execute(
        select(IndividualUserRequestModel).where(IndividualUserRequestModel.assigned_user_id == user_id)
    )
    ind_req = ind_req_result.scalar_one_or_none()
    
    now = datetime.now(timezone.utc)
    
    if ind_req and ind_req.assigned_subscription_id:
        # Update existing subscription
        old_sub_result = await db.execute(
            select(SubscriptionModel).where(SubscriptionModel.id == ind_req.assigned_subscription_id)
        )
        old_sub = old_sub_result.scalar_one_or_none()
        if old_sub:
            old_sub.status = "cancelled"
    
    # Create new subscriptions for selected plans
    created_subs = []
    primary_sub_id = None
    
    for plan_selection in data.plan_selections:
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_selection.plan_id))
        plan = plan_result.scalar_one_or_none()
        if not plan:
            raise HTTPException(status_code=404, detail=f"Plan {plan_selection.plan_id} not found")
        
        # Validate selected tools and use the plan's manual cost.
        tools_result = await db.execute(
            select(PlanToolModel).where(
                PlanToolModel.plan_id == plan.id,
                PlanToolModel.name.in_(plan_selection.tool_ids)
            )
        )
        plan_tools = tools_result.scalars().all()
        total_price = float(getattr(plan, "cost", None) or plan.price_monthly or 0)
        
        end_date = now + timedelta(days=30) if data.billing_cycle == "monthly" else now + timedelta(days=365)
        
        new_sub = SubscriptionModel(
            organization_id=user.organization_id,
            organization_name=org.name if org else "Individual Users",
            plan_id=plan.id,
            plan_name=plan.name,
            tools=json.dumps(plan_selection.tool_ids),
            status="active",
            start_date=now,
            end_date=end_date,
            billing_cycle=data.billing_cycle,
            amount=total_price
        )
        db.add(new_sub)
        await db.flush()  # Get the ID
        await set_subscription_tools(db, new_sub.id, plan.id, plan_selection.tool_ids)
        
        if primary_sub_id is None:
            primary_sub_id = new_sub.id
        
        created_subs.append({
            "subscription_id": new_sub.id,
            "plan_id": plan.id,
            "plan_name": plan.name,
            "tools": plan_selection.tool_ids,
            "amount": total_price
        })
    
    # Update the individual user request with the primary subscription
    if ind_req and primary_sub_id:
        ind_req.assigned_subscription_id = primary_sub_id
        # Also update the requested_plan and requested_tools
        all_plan_ids = [s["plan_id"] for s in created_subs]
        all_tools = []
        for s in created_subs:
            all_tools.extend(s["tools"])
        ind_req.requested_plan = json.dumps(all_plan_ids)
        ind_req.requested_tools = json.dumps(all_tools)
    
    await db.commit()
    
    return {
        "message": "Individual user subscription updated",
        "user_id": user_id,
        "subscriptions": created_subs
    }

# ==================== SUBSCRIPTION ROUTES (Super Admin Only) ====================

@api_router.get("/subscriptions")
async def get_subscriptions(status: Optional[str] = None, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    query = select(SubscriptionModel)
    if status:
        query = query.where(SubscriptionModel.status == status)
    result = await db.execute(query.order_by(SubscriptionModel.created_at.desc()))
    return [await subscription_to_dict(db, s) for s in result.scalars().all()]

@api_router.get("/subscriptions/{sub_id}")
async def get_subscription(sub_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SubscriptionModel).where(SubscriptionModel.id == sub_id))
    sub = result.scalar_one_or_none()
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return await subscription_to_dict(db, sub)

@api_router.post("/subscriptions/{sub_id}/pause")
async def pause_subscription(sub_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(update(SubscriptionModel).where(SubscriptionModel.id == sub_id).values(status="paused"))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Subscription not found")
    await db.commit()
    return {"message": "Subscription paused"}

@api_router.post("/subscriptions/{sub_id}/resume")
async def resume_subscription(sub_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SubscriptionModel).where(SubscriptionModel.id == sub_id))
    sub = result.scalar_one_or_none()
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    await ensure_can_activate_subscription(db, sub)
    sub.status = "active"
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

@api_router.get("/products")
async def get_products(include_plans: bool = False, include_inactive: bool = False, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    query = select(ProductModel).order_by(ProductModel.display_order, ProductModel.name)
    if not include_inactive:
        query = query.where(ProductModel.is_active == True)
    result = await db.execute(query)
    products = []
    for product in result.scalars().all():
        product_dict = model_to_dict(product)
        plans_result = await db.execute(select(PlanModel).where(PlanModel.product_id == product.id))
        product_plans = plans_result.scalars().all()
        product_dict["plan_count"] = len(product_plans)
        if include_plans:
            product_dict["plans"] = [await plan_to_dict(db, plan) for plan in product_plans]
        products.append(product_dict)
    return products

@api_router.post("/products")
async def create_product(data: ProductCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    key = data.key or product_key_from_name(data.name)
    existing = await get_product_by_id_or_key(db, key)
    if existing:
        raise HTTPException(status_code=400, detail="Product key already exists")
    product = ProductModel(
        key=key,
        name=data.name,
        description=data.description,
        display_order=data.display_order,
        is_active=data.is_active,
    )
    db.add(product)
    await db.commit()
    return model_to_dict(product)

@api_router.put("/products/{product_id}")
async def update_product(product_id: str, data: ProductUpdate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    product = await get_product_by_id_or_key(db, product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    if data.key is not None and data.key != product.key:
        existing = await get_product_by_id_or_key(db, data.key)
        if existing:
            raise HTTPException(status_code=400, detail="Product key already exists")
        product.key = data.key
    if data.name is not None:
        product.name = data.name
    if data.description is not None:
        product.description = data.description
    if data.display_order is not None:
        product.display_order = data.display_order
    if data.is_active is not None:
        product.is_active = data.is_active
    await db.execute(update(PlanModel).where(PlanModel.product_id == product.id).values(tool=product.key))
    await db.commit()
    return model_to_dict(product)

@api_router.delete("/products/{product_id}")
async def delete_product(product_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    product = await get_product_by_id_or_key(db, product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    plan_count = await db.scalar(select(func.count()).select_from(PlanModel).where(PlanModel.product_id == product.id)) or 0
    if plan_count > 0:
        product.is_active = False
        await db.commit()
        return {"message": "Product has plans and was deactivated instead of deleted"}
    await db.execute(delete(ProductModel).where(ProductModel.id == product.id))
    await db.commit()
    return {"message": "Product deleted"}

@api_router.get("/plans")
async def get_plans(product_id: Optional[str] = None, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get all plans - accessible by any admin (Super Admin or Org Admin)"""
    query = select(PlanModel)
    if product_id:
        product = await get_product_by_id_or_key(db, product_id)
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        query = query.where(PlanModel.product_id == product.id)
    result = await db.execute(query.order_by(PlanModel.created_at.desc()))
    plans = result.scalars().all()

    return [await plan_to_dict(db, plan) for plan in plans]

@api_router.get("/plans/{plan_id}")
async def get_plan(plan_id: str, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
    plan = result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    return await plan_to_dict(db, plan)

@api_router.post("/plans")
async def create_plan(data: PlanCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    product = await resolve_product_for_plan(db, data)
    cost = float(data.cost or data.price_monthly or 0)
    price_label = data.price_label or (f"${cost:g}" if cost else "$0")
    plan = PlanModel(
        name=data.name, product_id=product.id, tool=product.key, description=data.description,
        features=json.dumps(data.features),
        api_limit=data.api_limit or 0,
        cost=cost,
        price_monthly=cost,
        price_yearly=cost,
        price_label=price_label,
        billing_period=data.billing_period,
        is_popular=data.is_popular
    )
    db.add(plan)
    await db.commit()
    return await plan_to_dict(db, plan)

@api_router.put("/plans/{plan_id}")
async def update_plan(plan_id: str, data: PlanCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
    plan = result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    product = await resolve_product_for_plan(db, data)
    plan.name = data.name
    plan.product_id = product.id
    plan.tool = product.key
    plan.description = data.description
    plan.features = json.dumps(data.features)
    plan.api_limit = data.api_limit or 0
    plan.cost = float(data.cost or data.price_monthly or 0)
    plan.price_monthly = plan.cost
    plan.price_yearly = plan.cost
    plan.price_label = data.price_label or (f"${plan.cost:g}" if plan.cost else "$0")
    plan.billing_period = data.billing_period
    plan.is_popular = data.is_popular
    await db.execute(
        update(SubscriptionModel)
        .where(SubscriptionModel.plan_id == plan.id)
        .values(plan_name=plan.name)
    )
    await db.commit()
    return await plan_to_dict(db, plan)

@api_router.delete("/plans/{plan_id}")
async def delete_plan(plan_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
    plan = plan_result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    dependency_count = await db.scalar(
        select(func.count()).select_from(SubscriptionModel).where(SubscriptionModel.plan_id == plan_id)
    ) or 0
    dependency_count += await db.scalar(
        select(func.count()).select_from(PlanUpgradeRequestItemModel).where(PlanUpgradeRequestItemModel.plan_id == plan_id)
    ) or 0
    dependency_count += await db.scalar(
        select(func.count()).select_from(OrganizationSubscriptionRequestItemModel).where(OrganizationSubscriptionRequestItemModel.plan_id == plan_id)
    ) or 0

    if dependency_count > 0:
        plan.is_active = False
        await db.commit()
        return {"message": "Plan is in use and was deactivated instead of deleted"}

    await db.execute(delete(PlanToolModel).where(PlanToolModel.plan_id == plan_id))
    await db.execute(delete(PlanModel).where(PlanModel.id == plan_id))
    await db.commit()
    return {"message": "Plan deleted"}

# ==================== PLAN TOOLS ROUTES (Super Admin Only) ====================

@api_router.get("/plans/{plan_id}/tools", tags=["Plans"])
async def get_plan_tools(plan_id: str, payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get all tools for a specific plan"""
    # Verify plan exists
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
    plan = plan_result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    result = await db.execute(
        select(PlanToolModel)
        .where(PlanToolModel.plan_id == plan_id)
        .order_by(PlanToolModel.display_order, PlanToolModel.name)
    )
    return [model_to_dict(t) for t in result.scalars().all()]

@api_router.post("/plans/{plan_id}/tools", tags=["Plans"])
async def create_plan_tool(plan_id: str, data: PlanToolCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Add a new tool to a plan"""
    # Verify plan exists
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
    plan = plan_result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    tool = PlanToolModel(
        plan_id=plan_id,
        name=data.name,
        description=data.description,
        price_monthly=data.price_monthly,
        price_yearly=data.price_yearly,
        display_order=data.display_order
    )
    db.add(tool)
    await db.commit()
    return model_to_dict(tool)

@api_router.put("/plans/{plan_id}/tools/{tool_id}", tags=["Plans"])
async def update_plan_tool(plan_id: str, tool_id: str, data: PlanToolUpdate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Update a tool within a plan"""
    result = await db.execute(
        select(PlanToolModel).where(
            PlanToolModel.id == tool_id,
            PlanToolModel.plan_id == plan_id
        )
    )
    tool = result.scalar_one_or_none()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")

    if data.name is not None:
        tool.name = data.name
    if data.description is not None:
        tool.description = data.description
    if data.price_monthly is not None:
        tool.price_monthly = data.price_monthly
    if data.price_yearly is not None:
        tool.price_yearly = data.price_yearly
    if data.is_active is not None:
        tool.is_active = data.is_active
    if data.display_order is not None:
        tool.display_order = data.display_order

    await db.commit()
    return model_to_dict(tool)

@api_router.delete("/plans/{plan_id}/tools/{tool_id}", tags=["Plans"])
async def delete_plan_tool(plan_id: str, tool_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Delete a tool from a plan"""
    dependency_count = await db.scalar(
        select(func.count()).select_from(SubscriptionToolModel).where(SubscriptionToolModel.plan_tool_id == tool_id)
    ) or 0
    dependency_count += await db.scalar(
        select(func.count()).select_from(PlanUpgradeRequestToolModel).where(PlanUpgradeRequestToolModel.plan_tool_id == tool_id)
    ) or 0
    dependency_count += await db.scalar(
        select(func.count()).select_from(OrganizationSubscriptionRequestToolModel).where(OrganizationSubscriptionRequestToolModel.plan_tool_id == tool_id)
    ) or 0

    if dependency_count > 0:
        result = await db.execute(
            update(PlanToolModel)
            .where(PlanToolModel.id == tool_id, PlanToolModel.plan_id == plan_id)
            .values(is_active=False)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Tool not found")
        await db.commit()
        return {"message": "Tool is in use and was deactivated instead of deleted"}

    result = await db.execute(
        delete(PlanToolModel).where(
            PlanToolModel.id == tool_id,
            PlanToolModel.plan_id == plan_id
        )
    )
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Tool not found")
    await db.commit()
    return {"message": "Tool deleted"}

@api_router.get("/plans/{plan_id}/calculate-price", tags=["Plans"])
async def calculate_plan_price(plan_id: str, tool_ids: str = "", payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """
    Calculate total price for a plan based on selected tools.
    tool_ids: Comma-separated list of tool IDs
    """
    # Verify plan exists
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
    plan = plan_result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    # Get selected tools
    selected_tool_ids = [t.strip() for t in tool_ids.split(",") if t.strip()]

    plan_cost = float(getattr(plan, "cost", None) or plan.price_monthly or 0)
    if not selected_tool_ids:
        return {
            "plan_id": plan_id,
            "plan_name": plan.name,
            "api_limit": getattr(plan, "api_limit", 0),
            "cost": plan_cost,
            "price": p.price_label or (f"${plan_cost:g}" if plan_cost else "$0"),
            "price_label": p.price_label or (f"${plan_cost:g}" if plan_cost else "$0"),
            "period": p.billing_period,
            "billing_period": p.billing_period,
            "popular": bool(p.is_popular),
            "base_price_monthly": plan_cost,
            "base_price_yearly": plan_cost,
            "tools_price_monthly": 0,
            "tools_price_yearly": 0,
            "total_price_monthly": plan_cost,
            "total_price_yearly": plan_cost,
            "selected_tools": []
        }

    result = await db.execute(
        select(PlanToolModel).where(
            PlanToolModel.plan_id == plan_id,
            PlanToolModel.id.in_(selected_tool_ids),
            PlanToolModel.is_active == True
        )
    )
    tools = result.scalars().all()

    return {
        "plan_id": plan_id,
        "plan_name": plan.name,
        "api_limit": getattr(plan, "api_limit", 0),
        "cost": plan_cost,
        "base_price_monthly": plan_cost,
        "base_price_yearly": plan_cost,
        "tools_price_monthly": 0,
        "tools_price_yearly": 0,
        "total_price_monthly": plan_cost,
        "total_price_yearly": plan_cost,
        "selected_tools": [{"id": t.id, "name": t.name} for t in tools]
    }

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
    return [await user_to_dict(db, u) for u in result.scalars().all()]

@api_router.get("/users/{user_id}")
async def get_user(user_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return await user_to_dict(db, user)

@api_router.post("/users")
async def create_user(data: UserCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    # Check if email already exists
    existing_user = await db.execute(select(UserModel).where(UserModel.email == data.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="A user with this email already exists")
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
    return await user_to_dict(db, user)

@api_router.put("/users/{user_id}/status")
async def update_user_status(user_id: str, status: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(update(UserModel).where(UserModel.id == user_id).values(status=status))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")
    await db.commit()
    return {"message": f"User status updated to {status}"}

@api_router.delete("/users/{user_id}")
async def delete_user(user_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    # First get the user to check if it's an individual user
    user_result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = user_result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # If user is from no_organization, delete their individual subscription
    if user.organization_id == "no_organization":
        # Find the individual user request to get the subscription ID
        ind_req_result = await db.execute(
            select(IndividualUserRequestModel).where(
                IndividualUserRequestModel.email == user.email
            )
        )
        ind_req = ind_req_result.scalar_one_or_none()
        
        if ind_req:
            # Delete the subscription if it exists
            if ind_req.assigned_subscription_id:
                await db.execute(
                    delete(SubscriptionModel).where(
                        SubscriptionModel.id == ind_req.assigned_subscription_id
                    )
                )
            # Delete the individual user request
            await db.execute(
                delete(IndividualUserRequestModel).where(
                    IndividualUserRequestModel.email == user.email
                )
            )
    
    # Delete the user
    await db.execute(delete(UserModel).where(UserModel.id == user_id))
    
    # Also delete admin record if exists
    await db.execute(delete(AdminModel).where(AdminModel.email == user.email))
    
    await db.commit()
    return {"message": "User deleted successfully"}

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
    return [await billing_to_dict(db, b) for b in result.scalars().all()]

@api_router.get("/billing/{billing_id}")
async def get_billing_record(billing_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(BillingModel).where(BillingModel.id == billing_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Billing record not found")
    return await billing_to_dict(db, record)

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
            organization_name=await get_organization_name(db, sub.organization_id, sub.organization_name),
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
    await db.execute(delete(OrganizationSubscriptionRequestToolModel))
    await db.execute(delete(OrganizationSubscriptionRequestItemModel))
    await db.execute(delete(OrganizationSubscriptionRequestModel))
    await db.execute(delete(PlanUpgradeRequestToolModel))
    await db.execute(delete(PlanUpgradeRequestItemModel))
    await db.execute(delete(SubscriptionToolModel))
    await db.execute(delete(BillingModel))
    await db.execute(delete(ProjectTeamMemberModel))
    await db.execute(delete(ProjectModel))
    await db.execute(delete(BusinessUnitModel))
    await db.execute(delete(UserModel))
    await db.execute(delete(UserRequestModel))
    await db.execute(delete(PlanUpgradeRequestModel))
    await db.execute(delete(RoleModel))
    await db.execute(delete(SubscriptionModel))
    await db.execute(delete(OrganizationModel))
    await db.execute(delete(PlanModel))
    await db.execute(delete(ProductModel))
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
    
    # Create products and plans
    product_by_key = {}
    for product_data in DEFAULT_PRODUCTS:
        product = ProductModel(**product_data)
        product_by_key[product.key] = product
        db.add(product)

    plans_data = []
    for catalog_item in DEFAULT_PRICING_CATALOG:
        for plan_item in catalog_item["plans"]:
            plan_copy = dict(plan_item)
            plan_copy["tool"] = catalog_item["product_key"]
            plan_copy["price_monthly"] = parse_price_amount(plan_item.get("price"))
            plans_data.append(plan_copy)
    for p in plans_data:
        product = product_by_key.get(p["tool"])
        db.add(PlanModel(
            id=p["id"],
            name=p["name"],
            product_id=product.id if product else None,
            tool=p["tool"],
            description=p["description"],
            features=json.dumps(p["features"]),
            price_monthly=p["price_monthly"],
            price_yearly=p["price_monthly"],
            price_label=p.get("price"),
            billing_period=p.get("period"),
            api_limit=0,
            cost=p["price_monthly"],
            is_popular=bool(p.get("popular", False)),
        ))
    
    # Create organizations
    orgs_data = [
        {"id": "org_1", "name": "TechCorp Inc", "email": "admin@techcorp.io", "domain": "techcorp.io", "status": "approved", "requested_plan": "plan_forgestudio_enterprise", "requested_tools": ["Private APIs & Projects"], "contact_person": "John Smith", "phone": "+1-555-0101"},
        {"id": "org_2", "name": "DataFlow Systems", "email": "hello@dataflow.dev", "domain": "dataflow.dev", "status": "approved", "requested_plan": "plan_forgeq_enterprise", "requested_tools": ["API , MCP & Collections Testing"], "contact_person": "Sarah Chen", "phone": "+1-555-0102"},
        {"id": "org_3", "name": "CloudNine Ltd", "email": "contact@cloudnine.co", "domain": "cloudnine.co", "status": "pending", "requested_plan": "plan_forgesphere_enterprise", "requested_tools": ["API Governance "], "contact_person": "Mike Johnson", "phone": "+1-555-0103"},
        {"id": "org_4", "name": "StartupX", "email": "team@startupx.io", "domain": "startupx.io", "status": "pending", "requested_plan": "plan_agentic_ai_starter", "requested_tools": ["Basic RAG"], "contact_person": "Emily Davis", "phone": "+1-555-0104"},
        {"id": "org_5", "name": "Enterprise Solutions", "email": "admin@enterprise-sol.com", "domain": "enterprise-sol.com", "status": "approved", "requested_plan": "plan_forgeai_enterprise", "requested_tools": ["PII redaction & content filtering"], "contact_person": "Robert Wilson", "phone": "+1-555-0105"},
        {"id": "org_6", "name": "InnovateTech", "email": "info@innovatetech.net", "domain": "innovatetech.net", "status": "pending", "requested_plan": "plan_forgeshift_enterprise_plus", "requested_tools": ["Unlimited Proxy & Resources migration"], "contact_person": "Lisa Brown", "phone": "+1-555-0106"},
    ]
    for o in orgs_data:
        db.add(OrganizationModel(id=o["id"], name=o["name"], email=o["email"], domain=o["domain"], status=o["status"], requested_plan=o["requested_plan"], requested_tools=json.dumps(o["requested_tools"]), contact_person=o["contact_person"], phone=o["phone"]))
    
    # Create subscriptions
    subs_data = [
        {"id": "sub_1", "organization_id": "org_1", "organization_name": "TechCorp Inc", "plan_id": "plan_forgestudio_enterprise", "plan_name": "Enterprise", "tools": ["Private APIs & Projects"], "amount": 40.0},
        {"id": "sub_2", "organization_id": "org_2", "organization_name": "DataFlow Systems", "plan_id": "plan_forgeq_enterprise", "plan_name": "Enterprise", "tools": ["API , MCP & Collections Testing"], "amount": 30.0},
        {"id": "sub_3", "organization_id": "org_5", "organization_name": "Enterprise Solutions", "plan_id": "plan_forgeai_enterprise", "plan_name": "Enterprise", "tools": ["PII redaction & content filtering"], "amount": 9500.0},
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
async def root(db: AsyncSession = Depends(get_db)):
    active_database = None
    try:
        result = await db.execute(text("SELECT DATABASE()"))
        active_database = result.scalar()
    except Exception as e:
        logger.warning(f"Could not read active database name: {e}")

    return {
        "message": "ProbeStack Admin Dashboard API",
        "version": "1.0.0",
        "database": "MySQL",
        "configured_database": DB_NAME,
        "active_database": active_database,
    }

# ==================== PUBLIC API FOR EXTERNAL APPLICATIONS ====================

@api_router.post("/public/organizations/request", tags=["Public API"])
async def request_organization_subscription(data: OrganizationRequest, db: AsyncSession = Depends(get_db)):
    """
    Public API endpoint for external applications to submit organization subscription requests.
    Supports multiple plan selection.
    
    **Request Body:**
    - `name`: Organization name (required)
    - `email`: Organization email (required)
    - `domain`: Company domain (optional)
    - `plan_ids`: List of Plan IDs to subscribe to (required) - e.g., ['plan_api_enterprise', 'plan_ai_enterprise']
    - `selected_tools`: List of tool names from the plans (required)
    - `contact_person`: Primary contact name (required)
    - `contact_phone`: Contact phone number (optional)
    - `company_address`: Company address (optional)
    - `additional_notes`: Any additional notes (optional)
    - `description`: Optional description (optional)
    
    **Flow:**
    1. Call GET /api/public/pricing to see products and plans
    2. Submit this request with selected plan_ids and tools
    """

    # Validate all plans exist
    plans_result = await db.execute(select(PlanModel).where(PlanModel.id.in_(data.plan_ids)))
    plans = {p.id: p for p in plans_result.scalars().all()}
    
    invalid_plans = [pid for pid in data.plan_ids if pid not in plans]
    if invalid_plans:
        # Get available plans
        all_plans_result = await db.execute(select(PlanModel).where(PlanModel.is_active == True))
        available_plans = [
            await plan_to_dict(db, plan, include_tools=False)
            for plan in all_plans_result.scalars().all()
        ]
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"Invalid plan_ids: {invalid_plans}",
                "available_plans": available_plans
            }
        )
    
    # Get available tools from ALL selected plans
    tools_result = await db.execute(
        select(PlanToolModel).where(
            PlanToolModel.plan_id.in_(data.plan_ids),
            PlanToolModel.is_active == True
        )
    )
    available_tools = {t.name: t for t in tools_result.scalars().all()}

    # Validate selected tools exist in at least one of the selected plans
    invalid_tools = [t for t in data.selected_tools if t not in available_tools]
    if invalid_tools:
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"Invalid tools for selected plans: {invalid_tools}",
                "available_tools": list(available_tools.keys())
            }
        )

    selected_tool_objects = [available_tools[t] for t in data.selected_tools]
    base_monthly = sum((getattr(plans[pid], "cost", None) or plans[pid].price_monthly or 0) for pid in data.plan_ids)
    base_yearly = base_monthly
    tools_monthly = 0
    tools_yearly = 0
    total_monthly = base_monthly
    total_yearly = base_yearly
    
    # Check if organization with same email already exists
    existing = await db.execute(select(OrganizationModel).where(OrganizationModel.email == data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"An organization with email {data.email} already exists"
        )
    
    # Create organization request - store plan_ids as JSON array
    org = OrganizationModel(
        name=data.name,
        email=data.email,
        domain=data.domain,
        requested_plan=json.dumps(data.plan_ids),  # Store as JSON array
        requested_tools=json.dumps(data.selected_tools),
        contact_person=data.contact_person,
        phone=data.contact_phone,
        address=data.company_address,
        description=data.description,
        gateway_region=data.gateway_region,
        gateway_organization_name=data.gateway_organization_name,
        gateway_environment_type=data.gateway_environment_type,
        gateway_environments=json.dumps(data.gateway_environments) if data.gateway_environments else None
    )
    db.add(org)
    await db.flush()
    await create_organization_subscription_request(
        db,
        org.id,
        data.plan_ids,
        data.selected_tools,
        status=org.status
    )
    
    # Create notification for admin
    tools_str = ', '.join(data.selected_tools[:3])
    if len(data.selected_tools) > 3:
        tools_str += f" +{len(data.selected_tools) - 3} more"
    plans_str = ', '.join([plans[pid].name for pid in data.plan_ids])
    notif = NotificationModel(
        title="New Organization Request",
        message=f"{data.name} has requested {plans_str} with tools: {tools_str}",
        type="info",
        link=f"/pending-organizations"
    )
    db.add(notif)
    
    await db.commit()
    
    # Build response with plan details
    plan_names = [{"id": pid, "name": plans[pid].name} for pid in data.plan_ids]
    
    return {
        "request_id": org.id,
        "status": "pending",
        "message": f"Organization subscription request submitted successfully. Your request ID is {org.id}. An admin will review your request shortly.",
        "organization": {
            "name": org.name,
            "email": org.email,
            "plans": plan_names,
            "selected_tools": data.selected_tools,
            "pricing": {
                "base_monthly": base_monthly,
                "base_yearly": base_yearly,
                "tools_monthly": tools_monthly,
                "tools_yearly": tools_yearly,
                "total_monthly": total_monthly,
                "total_yearly": total_yearly
            }
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

@api_router.post("/public/onboarding/organizations/request", tags=["External Onboarding"])
async def external_create_organization_request(data: OrganizationRequest, db: AsyncSession = Depends(get_db)):
    """Create an organization onboarding request with the latest organization metadata."""
    return await request_organization_subscription(data, db)

@api_router.get("/public/onboarding/organizations/{organization_id}", tags=["External Onboarding"])
async def external_get_organization(organization_id: str, db: AsyncSession = Depends(get_db)):
    """Fetch one organization request/record by ID."""
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == organization_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return await organization_to_dict(db, org)

@api_router.get("/public/onboarding/organizations/{organization_id}/details", tags=["External Onboarding"])
async def external_get_organization_details(organization_id: str, db: AsyncSession = Depends(get_db)):
    """Fetch organization details, Business units, projects, and project members for another app."""
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == organization_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    bu_result = await db.execute(
        select(BusinessUnitModel)
        .where(BusinessUnitModel.organization_id == organization_id)
        .order_by(BusinessUnitModel.name.asc())
    )
    business_units = [model_to_dict(bu, ["tags"]) for bu in bu_result.scalars().all()]

    project_result = await db.execute(
        select(ProjectModel)
        .where(ProjectModel.organization_id == organization_id)
        .order_by(ProjectModel.name.asc())
    )
    teams = [model_to_dict(project) for project in project_result.scalars().all()]

    member_result = await db.execute(
        select(ProjectTeamMemberModel, ProjectModel, BusinessUnitModel)
        .join(ProjectModel, ProjectTeamMemberModel.project_id == ProjectModel.id)
        .outerjoin(BusinessUnitModel, ProjectModel.business_unit_id == BusinessUnitModel.id)
        .where(ProjectTeamMemberModel.organization_id == organization_id)
        .order_by(ProjectTeamMemberModel.invited_at.desc())
    )
    team_members = []
    for member, project, business_unit in member_result.all():
        member_data = await project_team_member_to_dict(db, member)
        member_data["team"] = model_to_dict(project)
        member_data["business_unit"] = model_to_dict(business_unit, ["tags"]) if business_unit else None
        team_members.append(member_data)

    return {
        "organization": await organization_to_dict(db, org),
        "business_units": business_units,
        "teams": teams,
        "team_members": team_members
    }

@api_router.get("/public/onboarding/organizations/{organization_id}/business-units", tags=["External Onboarding"])
async def external_get_business_units(organization_id: str, include_teams: bool = True, db: AsyncSession = Depends(get_db)):
    """Fetch Business units for an approved organization."""
    org = await get_approved_org_by_id(db, organization_id)
    result = await db.execute(
        select(BusinessUnitModel)
        .where(BusinessUnitModel.organization_id == org.id)
        .order_by(BusinessUnitModel.name.asc())
    )
    business_units = result.scalars().all()
    response = [model_to_dict(bu, ["tags"]) for bu in business_units]

    if include_teams and business_units:
        bu_ids = [bu.id for bu in business_units]
        projects_result = await db.execute(
            select(ProjectModel)
            .where(ProjectModel.organization_id == org.id, ProjectModel.business_unit_id.in_(bu_ids))
            .order_by(ProjectModel.name.asc())
        )
        projects_by_bu = {}
        for project in projects_result.scalars().all():
            projects_by_bu.setdefault(project.business_unit_id, []).append(model_to_dict(project))
        for bu_data in response:
            bu_data["teams"] = projects_by_bu.get(bu_data["id"], [])

    return response

@api_router.post("/public/onboarding/organizations/{organization_id}/business-units", tags=["External Onboarding"])
async def external_create_business_unit(organization_id: str, data: BusinessUnitCreate, db: AsyncSession = Depends(get_db)):
    """Onboard a Business unit for an approved organization."""
    org = await get_approved_org_by_id(db, organization_id)
    business_unit = await create_business_unit_for_org(db, org, data)
    await db.commit()
    return {"message": "Business unit created successfully", "business_unit": model_to_dict(business_unit, ["tags"])}

@api_router.get("/public/onboarding/organizations/{organization_id}/business-units/{business_unit_id}", tags=["External Onboarding"])
async def external_get_business_unit(organization_id: str, business_unit_id: str, db: AsyncSession = Depends(get_db)):
    """Fetch one Business unit and its projects."""
    org = await get_approved_org_by_id(db, organization_id)
    result = await db.execute(
        select(BusinessUnitModel).where(
            BusinessUnitModel.id == business_unit_id,
            BusinessUnitModel.organization_id == org.id
        )
    )
    business_unit = result.scalar_one_or_none()
    if not business_unit:
        raise HTTPException(status_code=404, detail="Business unit not found")
    response = model_to_dict(business_unit, ["tags"])
    teams_result = await db.execute(
        select(ProjectModel)
        .where(ProjectModel.organization_id == org.id, ProjectModel.business_unit_id == business_unit_id)
        .order_by(ProjectModel.name.asc())
    )
    response["teams"] = [model_to_dict(project) for project in teams_result.scalars().all()]
    return response

@api_router.get("/public/onboarding/organizations/{organization_id}/teams", tags=["External Onboarding"])
async def external_get_teams(organization_id: str, business_unit_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """Fetch projects for an approved organization, optionally filtered by Business unit."""
    org = await get_approved_org_by_id(db, organization_id)
    query = select(ProjectModel).where(ProjectModel.organization_id == org.id)
    if business_unit_id:
        query = query.where(ProjectModel.business_unit_id == business_unit_id)
    result = await db.execute(query.order_by(ProjectModel.name.asc()))
    return [model_to_dict(project) for project in result.scalars().all()]

@api_router.post("/public/onboarding/organizations/{organization_id}/teams", tags=["External Onboarding"])
async def external_create_team(organization_id: str, data: ExternalProjectCreate, db: AsyncSession = Depends(get_db)):
    """Onboard a Project for an approved organization. The Project must belong to a Business unit."""
    org = await get_approved_org_by_id(db, organization_id)
    project = await create_project_for_org(db, org, data)
    await db.commit()
    return {"message": "Project created successfully", "team": model_to_dict(project)}

@api_router.get("/public/onboarding/organizations/{organization_id}/teams/{team_id}", tags=["External Onboarding"])
async def external_get_team(organization_id: str, team_id: str, db: AsyncSession = Depends(get_db)):
    """Fetch one Project with its Business unit and members."""
    org = await get_approved_org_by_id(db, organization_id)
    project = await get_project_for_org(db, team_id, org.id)
    response = model_to_dict(project)
    response["business_unit"] = None
    if project.business_unit_id:
        bu_result = await db.execute(
            select(BusinessUnitModel).where(
                BusinessUnitModel.id == project.business_unit_id,
                BusinessUnitModel.organization_id == org.id
            )
        )
        business_unit = bu_result.scalar_one_or_none()
        response["business_unit"] = model_to_dict(business_unit, ["tags"]) if business_unit else None
    members_result = await db.execute(
        select(ProjectTeamMemberModel)
        .where(ProjectTeamMemberModel.organization_id == org.id, ProjectTeamMemberModel.project_id == project.id)
        .order_by(ProjectTeamMemberModel.invited_at.desc())
    )
    response["members"] = [await project_team_member_to_dict(db, member) for member in members_result.scalars().all()]
    return response

@api_router.get("/public/pricing", tags=["Public API"])
async def get_public_pricing(db: AsyncSession = Depends(get_db)):
    """
    Public pricing catalog for probestack.io.
    Returns products grouped with subscription plans, display prices, periods, and features.
    """
    products_result = await db.execute(
        select(ProductModel)
        .where(ProductModel.is_active == True)
        .where(ProductModel.key.in_([item["key"] for item in DEFAULT_PRODUCTS]))
        .order_by(ProductModel.display_order, ProductModel.name)
    )
    product_order = {item["key"]: index for index, item in enumerate(DEFAULT_PRODUCTS)}
    plan_name_order = {"starter": 0, "enterprise": 1, "enterprise - plus": 2, "enterprise plus": 2}
    products = []
    for product in products_result.scalars().all():
        plans_result = await db.execute(
            select(PlanModel).where(
                PlanModel.product_id == product.id,
                PlanModel.is_active == True,
            )
        )
        plan_models = sorted(
            plans_result.scalars().all(),
            key=lambda plan: (plan_name_order.get(plan.name.lower(), 99), plan.cost or 0, plan.name),
        )
        plans = []
        for plan in plan_models:
            price_label = plan.price_label or (f"${plan.cost:g}" if plan.cost else "$0")
            plans.append({
                "id": plan.id,
                "name": plan.name,
                "price": price_label,
                "price_label": price_label,
                "period": plan.billing_period,
                "billing_period": plan.billing_period,
                "description": plan.description,
                "features": parse_json_list(plan.features),
                "cost": float(plan.cost or 0),
                "price_monthly": float(plan.price_monthly or plan.cost or 0),
                "price_yearly": float(plan.price_yearly or plan.cost or 0),
                "popular": bool(plan.is_popular),
                "is_contact_sales": price_label.lower() == "contact sales",
            })
        products.append({
            "id": product.id,
            "key": product.key,
            "name": product.name,
            "description": product.description,
            "display_order": product.display_order,
            "plans": plans,
        })
    products.sort(key=lambda product: (product_order.get(product["key"], 99), product["display_order"], product["name"]))
    return {
        "source": "probestack-admin-backend",
        "products": products,
        "product_types": [{"id": product["key"], "name": product["name"]} for product in products],
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
    await assert_unique_email(db, data.email)
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


@api_router.post("/public/users/context-token", tags=["Public API"])
async def issue_user_context_token(data: UserContextTokenRequest, db: AsyncSession = Depends(get_db)):
    """
    Issue a signed ProbeStack context token after probestack.io login.

    The JWT payload contains user, organization, org role, Business unit/project roles,
    admin flags, subscriptions, plans, and tools.
    """
    email = data.email.lower().strip() if data.email else None
    auth0_user_id = data.auth0_user_id

    if data.id_token:
        try:
            decoded = jwt.decode(data.id_token, options={"verify_signature": False})
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid id_token")

        token_email = decoded.get("email")
        token_auth0_user_id = decoded.get("sub")
        if email and token_email and email != token_email.lower():
            raise HTTPException(status_code=400, detail="email does not match id_token")
        email = email or (token_email.lower() if token_email else None)
        auth0_user_id = auth0_user_id or token_auth0_user_id

    if not email and not auth0_user_id:
        raise HTTPException(status_code=400, detail="email, auth0_user_id, or id_token is required")

    user_context = await build_user_context(db, email=email, auth0_user_id=auth0_user_id)
    token, expires_at = create_user_context_token(user_context)
    await db.commit()

    return {
        "success": True,
        "token": token,
        "token_type": "Bearer",
        "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
        "user": user_context,
    }


@api_router.get("/public/users/{email}", tags=["Public API"])
async def get_user_by_email(email: str, db: AsyncSession = Depends(get_db)):
    """
    Get user details by email (public endpoint).
    Returns user info including role, permissions, plans, tools, and admin status.
    """
    # Check in users table
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    user = result.scalar_one_or_none()
    
    if user:
        # Get role permissions
        role_result = await db.execute(select(RoleModel).where(RoleModel.id == user.role_id))
        role = role_result.scalar_one_or_none()
        permissions = json.loads(role.permissions) if role and role.permissions else []
        
        # Check if user is also an admin
        admin_result = await db.execute(select(AdminModel).where(AdminModel.email == email))
        admin = admin_result.scalar_one_or_none()
        
        # Get subscription details (plans and tools) based on organization type
        subscriptions = []
        plans = []
        tools = []
        user_type = "individual" if user.organization_id == "no_organization" else "organization"
        
        if user_type == "individual":
            # For individual users, get all approved requests
            ind_req_result = await db.execute(
                select(IndividualUserRequestModel).where(
                    IndividualUserRequestModel.email == user.email,
                    IndividualUserRequestModel.status == "approved"
                )
            )
            ind_reqs = ind_req_result.scalars().all()
            sub_ids = [req.assigned_subscription_id for req in ind_reqs if req.assigned_subscription_id]
            
            if sub_ids:
                sub_result = await db.execute(
                    select(SubscriptionModel).where(
                        SubscriptionModel.id.in_(sub_ids),
                        SubscriptionModel.status == "active"
                    )
                )
                subscriptions = sub_result.scalars().all()
        else:
            # For organization users, get all active org subscriptions
            sub_result = await db.execute(
                select(SubscriptionModel).where(
                    SubscriptionModel.organization_id == user.organization_id,
                    SubscriptionModel.status == "active"
                ).order_by(SubscriptionModel.start_date.desc())
            )
            subscriptions = sub_result.scalars().all()
        
        for sub in subscriptions:
            # Parse plan_id - could be JSON array or single string
            plan_id_raw = sub.plan_id
            try:
                plan_ids = json.loads(plan_id_raw) if plan_id_raw.startswith('[') else [plan_id_raw]
            except (json.JSONDecodeError, AttributeError, TypeError):
                plan_ids = [plan_id_raw] if plan_id_raw else []
            
            # Get plan details and avoid duplicates
            if plan_ids:
                plans_result = await db.execute(select(PlanModel).where(PlanModel.id.in_(plan_ids)))
                for p in plans_result.scalars().all():
                    if not any(existing_plan["id"] == p.id for existing_plan in plans):
                        plans.append({"id": p.id, "name": p.name, "tool": p.tool})
            
            # Parse tools and avoid duplicates
            try:
                sub_tools = await get_subscription_tools(db, sub)
                for tool in sub_tools:
                    if tool not in tools:
                        tools.append(tool)
            except (json.JSONDecodeError, TypeError):
                pass
        
        # Build response with admin details if user is also an admin
        response = {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "organization_id": user.organization_id,
            "organization_name": await get_organization_name(db, user.organization_id, user.organization_name),
            "user_type": user_type,
            "role_id": user.role_id,
            "role_name": await get_role_name(db, user.role_id, user.role_name),
            "role": admin.role if admin else (await get_role_name(db, user.role_id, user.role_name) or "user").lower().replace(" ", "_"),
            "permissions": permissions,
            "is_admin": admin is not None,
            "status": user.status,
            "theme_preference": getattr(user, 'theme_preference', 'light'),
            "plans": plans,
            "tools": tools,
            "subscriptions": [
                {
                    "id": sub.id,
                    "plan_name": await get_plan_name(db, sub.plan_id, sub.plan_name),
                    "status": sub.status,
                    "start_date": sub.start_date.isoformat() if sub.start_date else None,
                    "end_date": sub.end_date.isoformat() if sub.end_date else None
                } for sub in subscriptions
            ],
            "created_at": user.created_at.isoformat() if user.created_at else None
        }
        
        # Add admin details if user is also an admin
        if admin:
            response["admin"] = {
                "id": admin.id,
                "email": admin.email,
                "name": admin.name,
                "role": admin.role,
                "organization_id": admin.organization_id,
                "organization_name": await get_organization_name(db, admin.organization_id, admin.organization_name),
                "theme_preference": getattr(admin, 'theme_preference', 'light'),
                "is_active": admin.is_active,
                "created_at": admin.created_at.isoformat() if admin.created_at else None
            }
        
        return response
    
    # Check in admins table
    result = await db.execute(select(AdminModel).where(AdminModel.email == email))
    admin = result.scalar_one_or_none()
    
    if admin:
        # Get subscription based on organization type
        subscriptions = []
        plans = []
        tools = []
        user_type = "individual" if admin.organization_id == "no_organization" else "organization"
        
        if admin.organization_id and admin.organization_id != "no_organization":
            # For organization admins, get all active org subscriptions
            sub_result = await db.execute(
                select(SubscriptionModel).where(
                    SubscriptionModel.organization_id == admin.organization_id,
                    SubscriptionModel.status == "active"
                ).order_by(SubscriptionModel.start_date.desc())
            )
            subscriptions = sub_result.scalars().all()
        elif admin.organization_id == "no_organization":
            # For individual admins, get from their individual request
            ind_req_result = await db.execute(
                select(IndividualUserRequestModel).where(
                    IndividualUserRequestModel.email == admin.email,
                    IndividualUserRequestModel.status == "approved"
                )
            )
            ind_reqs = ind_req_result.scalars().all()
            sub_ids = [req.assigned_subscription_id for req in ind_reqs if req.assigned_subscription_id]
            
            if sub_ids:
                sub_result = await db.execute(
                    select(SubscriptionModel).where(
                        SubscriptionModel.id.in_(sub_ids),
                        SubscriptionModel.status == "active"
                    )
                )
                subscriptions = sub_result.scalars().all()
        
        for sub in subscriptions:
            # Parse plan_id
            plan_id_raw = sub.plan_id
            try:
                plan_ids = json.loads(plan_id_raw) if plan_id_raw.startswith('[') else [plan_id_raw]
            except (json.JSONDecodeError, AttributeError, TypeError):
                plan_ids = [plan_id_raw] if plan_id_raw else []
            
            if plan_ids:
                plans_result = await db.execute(select(PlanModel).where(PlanModel.id.in_(plan_ids)))
                for p in plans_result.scalars().all():
                    if not any(existing_plan["id"] == p.id for existing_plan in plans):
                        plans.append({"id": p.id, "name": p.name, "tool": p.tool})
            
            try:
                sub_tools = await get_subscription_tools(db, sub)
                for tool in sub_tools:
                    if tool not in tools:
                        tools.append(tool)
            except (json.JSONDecodeError, TypeError):
                pass
        
        return {
            "id": admin.id,
            "email": admin.email,
            "name": admin.name,
            "organization_id": admin.organization_id,
            "organization_name": await get_organization_name(db, admin.organization_id, admin.organization_name),
            "user_type": user_type,
            "role": admin.role,
            "permissions": ["all"] if admin.role == "super_admin" else ["read", "write", "manage_users"],
            "is_admin": True,
            "status": "active" if admin.is_active else "inactive",
            "theme_preference": getattr(admin, 'theme_preference', 'light'),
            "plans": plans,
            "tools": tools,
            "subscriptions": [
                {
                    "id": sub.id,
                    "plan_name": await get_plan_name(db, sub.plan_id, sub.plan_name),
                    "status": sub.status,
                    "start_date": sub.start_date.isoformat() if sub.start_date else None,
                    "end_date": sub.end_date.isoformat() if sub.end_date else None
                } for sub in subscriptions
            ],
            "created_at": admin.created_at.isoformat() if admin.created_at else None
        }
    
    raise HTTPException(status_code=404, detail="User not found")


@api_router.post("/public/users/lookup", tags=["Public API"])
async def lookup_users(data: dict, db: AsyncSession = Depends(get_db)):
    """
    Bulk lookup users by email addresses.
    Returns user info including plans and tools for each user.
    """
    emails = data.get("emails", [])
    if not emails:
        raise HTTPException(status_code=400, detail="No emails provided")
    
    found_users = []
    not_found = []
    
    for email in emails:
        # Check users table
        result = await db.execute(select(UserModel).where(UserModel.email == email))
        user = result.scalar_one_or_none()
        
        if user:
            # Get role permissions
            role_result = await db.execute(select(RoleModel).where(RoleModel.id == user.role_id))
            role = role_result.scalar_one_or_none()
            permissions = json.loads(role.permissions) if role and role.permissions else []
            
            # Check if also admin
            admin_result = await db.execute(select(AdminModel).where(AdminModel.email == email))
            admin = admin_result.scalar_one_or_none()
            
            # Get subscription details based on organization type
            plans = []
            tools = []
            subscriptions = []
            user_type = "individual" if user.organization_id == "no_organization" else "organization"
            
            if user_type == "individual":
                # For individual users, get all approved requests
                ind_req_result = await db.execute(
                    select(IndividualUserRequestModel).where(
                        IndividualUserRequestModel.email == user.email,
                        IndividualUserRequestModel.status == "approved"
                    )
                )
                ind_reqs = ind_req_result.scalars().all()
                sub_ids = [req.assigned_subscription_id for req in ind_reqs if req.assigned_subscription_id]
                
                if sub_ids:
                    sub_result = await db.execute(
                        select(SubscriptionModel).where(
                            SubscriptionModel.id.in_(sub_ids),
                            SubscriptionModel.status == "active"
                        )
                    )
                    subscriptions = sub_result.scalars().all()
            else:
                # For organization users, get all active org subscriptions
                sub_result = await db.execute(
                    select(SubscriptionModel).where(
                        SubscriptionModel.organization_id == user.organization_id,
                        SubscriptionModel.status == "active"
                    ).order_by(SubscriptionModel.start_date.desc())
                )
                subscriptions = sub_result.scalars().all()
            
            for sub in subscriptions:
                plan_id_raw = sub.plan_id
                try:
                    plan_ids = json.loads(plan_id_raw) if plan_id_raw.startswith('[') else [plan_id_raw]
                except (json.JSONDecodeError, AttributeError, TypeError):
                    plan_ids = [plan_id_raw] if plan_id_raw else []
                
                if plan_ids:
                    plans_result = await db.execute(select(PlanModel).where(PlanModel.id.in_(plan_ids)))
                    for p in plans_result.scalars().all():
                        if not any(existing_plan["id"] == p.id for existing_plan in plans):
                            plans.append({"id": p.id, "name": p.name, "tool": p.tool})
                
                try:
                    sub_tools = await get_subscription_tools(db, sub)
                    for tool in sub_tools:
                        if tool not in tools:
                            tools.append(tool)
                except (json.JSONDecodeError, TypeError):
                    pass
            
            user_data = {
                "email": user.email,
                "name": user.name,
                "organization_id": user.organization_id,
                "organization_name": await get_organization_name(db, user.organization_id, user.organization_name),
                "user_type": user_type,
                "role_id": user.role_id,
                "role_name": await get_role_name(db, user.role_id, user.role_name),
                "role": admin.role if admin else (await get_role_name(db, user.role_id, user.role_name) or "user").lower().replace(" ", "_"),
                "permissions": permissions,
                "is_admin": admin is not None,
                "status": user.status,
                "theme_preference": getattr(user, 'theme_preference', 'light'),
                "plans": plans,
                "tools": tools,
                "subscriptions": [
                    {
                        "id": sub.id,
                        "plan_name": await get_plan_name(db, sub.plan_id, sub.plan_name),
                        "status": sub.status,
                        "start_date": sub.start_date.isoformat() if sub.start_date else None,
                        "end_date": sub.end_date.isoformat() if sub.end_date else None
                    } for sub in subscriptions
                ],
                "created_at": user.created_at.isoformat() if user.created_at else None
            }
            
            # Add admin details if user is also an admin
            if admin:
                user_data["admin"] = {
                    "id": admin.id,
                    "email": admin.email,
                    "name": admin.name,
                    "role": admin.role,
                    "organization_id": admin.organization_id,
                    "organization_name": await get_organization_name(db, admin.organization_id, admin.organization_name),
                    "is_active": admin.is_active
                }
            
            found_users.append(user_data)
            continue
        
        # Check admins table
        result = await db.execute(select(AdminModel).where(AdminModel.email == email))
        admin = result.scalar_one_or_none()
        
        if admin:
            plans = []
            tools = []
            subscriptions = []
            user_type = "individual" if admin.organization_id == "no_organization" else "organization"
            
            if admin.organization_id and admin.organization_id != "no_organization":
                # For organization admins, get all active org subscriptions
                sub_result = await db.execute(
                    select(SubscriptionModel).where(
                        SubscriptionModel.organization_id == admin.organization_id,
                        SubscriptionModel.status == "active"
                    ).order_by(SubscriptionModel.start_date.desc())
                )
                subscriptions = sub_result.scalars().all()
            elif admin.organization_id == "no_organization":
                # For individual admins, get from their individual request
                ind_req_result = await db.execute(
                    select(IndividualUserRequestModel).where(
                        IndividualUserRequestModel.email == admin.email,
                        IndividualUserRequestModel.status == "approved"
                    )
                )
                ind_reqs = ind_req_result.scalars().all()
                sub_ids = [req.assigned_subscription_id for req in ind_reqs if req.assigned_subscription_id]
                
                if sub_ids:
                    sub_result = await db.execute(
                        select(SubscriptionModel).where(
                            SubscriptionModel.id.in_(sub_ids),
                            SubscriptionModel.status == "active"
                        )
                    )
                    subscriptions = sub_result.scalars().all()
            
            for sub in subscriptions:
                plan_id_raw = sub.plan_id
                try:
                    plan_ids = json.loads(plan_id_raw) if plan_id_raw.startswith('[') else [plan_id_raw]
                except (json.JSONDecodeError, AttributeError, TypeError):
                    plan_ids = [plan_id_raw] if plan_id_raw else []
                
                if plan_ids:
                    plans_result = await db.execute(select(PlanModel).where(PlanModel.id.in_(plan_ids)))
                    for p in plans_result.scalars().all():
                        if not any(existing_plan["id"] == p.id for existing_plan in plans):
                            plans.append({"id": p.id, "name": p.name, "tool": p.tool})
                
                try:
                    sub_tools = await get_subscription_tools(db, sub)
                    for tool in sub_tools:
                        if tool not in tools:
                            tools.append(tool)
                except (json.JSONDecodeError, TypeError):
                    pass
            
            found_users.append({
                "email": admin.email,
                "name": admin.name,
                "organization_id": admin.organization_id,
                "organization_name": await get_organization_name(db, admin.organization_id, admin.organization_name),
                "user_type": user_type,
                "role": admin.role,
                "permissions": ["all"] if admin.role == "super_admin" else ["read", "write", "manage_users"],
                "is_admin": True,
                "status": "active" if admin.is_active else "inactive",
                "theme_preference": getattr(admin, 'theme_preference', 'light'),
                "plans": plans,
                "tools": tools,
                "subscriptions": [
                    {
                        "id": sub.id,
                        "plan_name": await get_plan_name(db, sub.plan_id, sub.plan_name),
                        "status": sub.status,
                        "start_date": sub.start_date.isoformat() if sub.start_date else None,
                        "end_date": sub.end_date.isoformat() if sub.end_date else None
                    } for sub in subscriptions
                ],
                "created_at": admin.created_at.isoformat() if admin.created_at else None
            })
            continue
        
        not_found.append(email)
    
    return {
        "users": found_users,
        "not_found": not_found
    }


@api_router.put("/public/users/{email}/preferences", tags=["Public API"])
async def update_user_preferences(email: str, data: dict, db: AsyncSession = Depends(get_db)):
    """
    Update user preferences (theme preference).
    """
    theme = data.get("theme_preference", "light")
    if theme not in ["light", "dark"]:
        raise HTTPException(status_code=400, detail="Invalid theme preference. Must be 'light' or 'dark'")
    
    # Try to update in users table
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    user = result.scalar_one_or_none()
    
    if user:
        if hasattr(user, 'theme_preference'):
            user.theme_preference = theme
        await db.commit()
        return {"message": "Preferences updated", "theme_preference": theme}
    
    # Try to update in admins table
    result = await db.execute(select(AdminModel).where(AdminModel.email == email))
    admin = result.scalar_one_or_none()
    
    if admin:
        if hasattr(admin, 'theme_preference'):
            admin.theme_preference = theme
        await db.commit()
        return {"message": "Preferences updated", "theme_preference": theme}
    
    raise HTTPException(status_code=404, detail="User not found")
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
    
    return [await user_request_to_dict(db, r) for r in requests]


@api_router.get("/user-requests/pending", tags=["User Requests"])
async def get_pending_user_requests(payload: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    """Get all pending user addition requests (admin only)"""
    result = await db.execute(
        select(UserRequestModel)
        .where(UserRequestModel.status == "pending")
        .order_by(UserRequestModel.created_at.desc())
    )
    return [await user_request_to_dict(db, r) for r in result.scalars().all()]


@api_router.get("/user-requests/{request_id}", tags=["User Requests"])
async def get_user_request(request_id: str, payload: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    """Get a specific user request (admin only)"""
    result = await db.execute(select(UserRequestModel).where(UserRequestModel.id == request_id))
    req = result.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="User request not found")
    return await user_request_to_dict(db, req)


@api_router.post("/user-requests/{request_id}/approve", tags=["User Requests"])
async def approve_user_request(
    request_id: str,
    role_id: str,
    project_id: str,
    business_unit_id: Optional[str] = None,
    project_role: str = "member",
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
    # Check if user with this email already exists
    existing_user = await db.execute(select(UserModel).where(UserModel.email == req.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="A user with this email already exists")
    # Validate role exists and belongs to the organization
    role_result = await db.execute(
        select(RoleModel).where(RoleModel.id == role_id, RoleModel.organization_id == req.organization_id)
    )
    role = role_result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found in this organization")
    project_role = (project_role or "member").strip().lower()
    if project_role not in ["manager", "member", "viewer"]:
        raise HTTPException(status_code=400, detail="Project role must be manager, member, or viewer")
    business_unit, project = await validate_user_request_team_assignment(db, req.organization_id, project_id, business_unit_id)
    
    now = datetime.now(timezone.utc)
    
    # Update request status
    req.status = "approved"
    req.approved_at = now
    req.updated_at = now
    req.approved_role_id = role_id
    req.approved_business_unit_id = business_unit.id
    req.approved_project_id = project.id
    req.approved_project_role = project_role
    
    # Create the user
    user = UserModel(
        email=req.email,
        name=req.name,
        organization_id=req.organization_id,
        organization_name=req.organization_name,
        role_id=role_id,
        role_name=role.name,
        status="pending_verification",
        email_verified=False,
        password_set=False,
        first_login_token=secrets.token_urlsafe(32)
    )
    db.add(user)
    await db.flush()
    team_member = await assign_user_to_project_team(db, user, project, project_role, payload.get("sub"))
    
    # Create user in Auth0
    auth0_result = await auth0_mgmt.create_user(
        email=req.email,
        name=req.name,
        user_metadata={
            "probestack_user_id": user.id,
            "organization_id": req.organization_id,
            "organization_name": req.organization_name
        }
    )
    
    if auth0_result.get("success"):
        user.auth0_user_id = auth0_result.get("auth0_user_id")
        logger.info(f"Auth0 user created for {req.email}: {user.auth0_user_id}")
        # Send verification email via Auth0
        await auth0_mgmt.send_verification_email(user.auth0_user_id)
    elif auth0_result.get("exists"):
        existing_user = await auth0_mgmt.get_user_by_email(req.email)
        if existing_user.get("success"):
            user.auth0_user_id = existing_user["user"]["user_id"]
            # Send verification email for existing Auth0 user
            await auth0_mgmt.send_verification_email(user.auth0_user_id)
    else:
        logger.warning(f"Failed to create Auth0 user for {req.email}: {auth0_result.get('error')}")
    
    # Create notification
    notif = NotificationModel(
        title="User Request Approved",
        message=f"{req.name} has been added to {req.organization_name} as {role.name}",
        type="success"
    )
    db.add(notif)
    
    await db.commit()
    
    # Generate setup account URL
    base_url = os.environ.get("APP_URL", "")
    setup_url = f"{base_url}/setup-account?email={req.email}&token={user.first_login_token}" if base_url else None
    
    return {
        "message": "User request approved",
        "user_id": user.id,
        "user": {
            "name": user.name,
            "email": user.email,
            "organization": user.organization_name,
            "role": user.role_name,
            "auth0_user_id": user.auth0_user_id,
            "status": user.status
        },
        "business_unit": model_to_dict(business_unit, ["tags"]),
        "team": model_to_dict(project),
        "team_member": await project_team_member_to_dict(db, team_member),
        "setup_url": setup_url,
        "next_steps": "User will receive an email to verify their email address and set their password."
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


@api_router.get("/health", tags=["Health"])
async def api_health_check():
    """
    Check the API health.
    """
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@api_router.get("/health/db", tags=["Health"])
async def db_health_check(db: AsyncSession = Depends(get_db)):
    """
    Check the database connection health.
    """
    try:
        result = await db.execute(text("SELECT DATABASE()"))
        active_database = result.scalar()
        return {
            "status": "healthy",
            "database": "connected",
            "configured_database": DB_NAME,
            "active_database": active_database,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

# Include the router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

async def mysql_column_exists(conn, table_name: str, column_name: str) -> bool:
    result = await conn.execute(
        text(
            """
            SELECT COUNT(*)
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = :schema
              AND TABLE_NAME = :table_name
              AND COLUMN_NAME = :column_name
            """
        ),
        {"schema": DB_NAME, "table_name": table_name, "column_name": column_name},
    )
    return bool(result.scalar())

async def ensure_runtime_schema(conn):
    if not await mysql_column_exists(conn, "plans", "product_id"):
        await conn.execute(text("ALTER TABLE plans ADD COLUMN product_id VARCHAR(36) NULL AFTER name"))
    if not await mysql_column_exists(conn, "plans", "price_label"):
        await conn.execute(text("ALTER TABLE plans ADD COLUMN price_label VARCHAR(100) NULL AFTER price_yearly"))
    if not await mysql_column_exists(conn, "plans", "billing_period"):
        await conn.execute(text("ALTER TABLE plans ADD COLUMN billing_period VARCHAR(100) NULL AFTER price_label"))
    if not await mysql_column_exists(conn, "plans", "is_popular"):
        await conn.execute(text("ALTER TABLE plans ADD COLUMN is_popular BOOL NOT NULL DEFAULT FALSE AFTER cost"))

async def ensure_default_products():
    async with AsyncSessionLocal() as db:
        products_by_key = {}
        active_product_keys = {item["key"] for item in DEFAULT_PRODUCTS}
        for item in DEFAULT_PRODUCTS:
            result = await db.execute(select(ProductModel).where(ProductModel.key == item["key"]))
            product = result.scalar_one_or_none()
            if not product:
                product = ProductModel(**item)
                db.add(product)
                await db.flush()
            else:
                product.name = item["name"]
                product.description = item["description"]
                product.display_order = item["display_order"]
                product.is_active = True
            products_by_key[product.key] = product
        legacy_products = await db.execute(select(ProductModel).where(~ProductModel.key.in_(active_product_keys)))
        for product in legacy_products.scalars().all():
            product.is_active = False
        await db.flush()
        for catalog_item in DEFAULT_PRICING_CATALOG:
            product = products_by_key.get(catalog_item["product_key"])
            if not product:
                continue
            for index, plan_data in enumerate(catalog_item["plans"]):
                cost = parse_price_amount(plan_data.get("price"))
                plan = await db.get(PlanModel, plan_data["id"])
                if not plan:
                    plan = PlanModel(
                        id=plan_data["id"],
                        name=plan_data["name"],
                        product_id=product.id,
                        tool=product.key,
                        description=plan_data["description"],
                        features=json.dumps(plan_data["features"]),
                        price_monthly=cost,
                        price_yearly=cost,
                        price_label=plan_data.get("price"),
                        billing_period=plan_data.get("period"),
                        api_limit=0,
                        cost=cost,
                        is_popular=bool(plan_data.get("popular", False)),
                        is_active=True,
                    )
                    db.add(plan)
                else:
                    plan.name = plan_data["name"]
                    plan.product_id = product.id
                    plan.tool = product.key
                    plan.description = plan_data["description"]
                    plan.features = json.dumps(plan_data["features"])
                    plan.price_monthly = cost
                    plan.price_yearly = cost
                    plan.price_label = plan_data.get("price")
                    plan.billing_period = plan_data.get("period")
                    plan.cost = cost
                    plan.is_popular = bool(plan_data.get("popular", False))
                    plan.is_active = True
        plans_result = await db.execute(select(PlanModel))
        for plan in plans_result.scalars().all():
            product = products_by_key.get(plan.tool)
            if product and not plan.product_id:
                plan.product_id = product.id
        await db.commit()

@app.on_event("startup")
async def startup():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await ensure_runtime_schema(conn)
        await ensure_default_products()
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        logger.warning("Server is starting without a successful database connection.")

@app.on_event("shutdown")
async def shutdown():
    await engine.dispose()
