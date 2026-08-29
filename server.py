from fastapi import FastAPI, APIRouter, HTTPException, Depends, Response, Request
from fastapi.responses import StreamingResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, Text, Float, Boolean, DateTime, ForeignKey, select, delete, update, func, JSON, UniqueConstraint, text, or_
from sqlalchemy.dialects.mysql import LONGTEXT

import os
import logging
import io
import zipfile
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import Any, List, Optional
import uuid
import calendar
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import json
import httpx
import base64
import hashlib
from urllib.parse import urlencode
import secrets
import smtplib
from email.message import EmailMessage
from html import escape
from xml.sax.saxutils import escape as xml_escape
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

ROOT_DIR = Path(__file__).parent
if os.path.exists(ROOT_DIR / ".env"):
    load_dotenv(ROOT_DIR / ".env")

# Auth0 Config
AUTH0_ENABLED = os.environ.get("AUTH0_ENABLED", "false").lower() in ["1", "true", "yes"]
AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN', 'probestack-usa-dev.us.auth0.com')
AUTH0_CLIENT_ID = os.environ.get('AUTH0_CLIENT_ID', '')
AUTH0_CLIENT_SECRET = os.environ.get('AUTH0_CLIENT_SECRET', '')
AUTH0_CALLBACK_URI = os.environ.get('AUTH0_CALLBACK_URI', 'https://probestack.io/callback')
AUTH0_MGMT_DOMAIN = os.environ.get('AUTH0_MGMT_DOMAIN', 'probestack-usa-dev.us.auth0.com')
AUTH0_MGMT_CLIENT_ID = os.environ.get('AUTH0_MGMT_CLIENT_ID', '')
AUTH0_MGMT_CLIENT_SECRET = os.environ.get('AUTH0_MGMT_CLIENT_SECRET', '')
AUTH0_DB_CONNECTION_NAME = os.environ.get('AUTH0_DB_CONNECTION_NAME', 'Username-Password-Authentication')
AUTH0_DB_CONNECTION_ID = os.environ.get('AUTH0_DB_CONNECTION_ID', '')
AUTH0_REDIRECT_URIS = {
    "probestack": os.environ.get("AUTH0_PROBESTACK_CALLBACK_URI", AUTH0_CALLBACK_URI),
    "forgecatalog": os.environ.get("AUTH0_FORGECATALOG_CALLBACK_URI", "https://forgecatalog.com/auth/auth0/callback"),
    "forgefuzz": os.environ.get("AUTH0_FORGEFUZZ_CALLBACK_URI", "https://forgefuzz.com/auth/auth0/callback"),
    "local": os.environ.get("AUTH0_LOCAL_CALLBACK_URI", "http://localhost:3000/admin/zitadel-test"),
}
AUTH0_POST_LOGOUT_URIS = {
    "probestack": os.environ.get("AUTH0_PROBESTACK_POST_LOGOUT_URI", "https://probestack.io"),
    "forgecatalog": os.environ.get("AUTH0_FORGECATALOG_POST_LOGOUT_URI", "https://forgecatalog.com"),
    "forgefuzz": os.environ.get("AUTH0_FORGEFUZZ_POST_LOGOUT_URI", "https://forgefuzz.com"),
    "console": os.environ.get("AUTH0_CONSOLE_POST_LOGOUT_URI", "https://console.probestack.io"),
    "local": os.environ.get("AUTH0_LOCAL_POST_LOGOUT_URI", "http://localhost:3000/admin/zitadel-test"),
}
PRODUCT_AUTH_RETURN_URLS = {
    "probestack": os.environ.get(
        "PROBESTACK_PRODUCT_RETURN_URL",
        os.environ.get("CONSOLE_PRODUCT_RETURN_URL", "https://console.probestack.io"),
    ),
    "console": os.environ.get("CONSOLE_PRODUCT_RETURN_URL", "https://console.probestack.io"),
    "forgecatalog": os.environ.get("FORGECATALOG_PRODUCT_RETURN_URL", "https://forgecatalog.com"),
    "forgefuzz": os.environ.get("FORGEFUZZ_PRODUCT_RETURN_URL", "https://forgefuzz.com"),
    "local": os.environ.get("LOCAL_PRODUCT_RETURN_URL", "http://localhost:3000"),
}

SUPPORTED_IDENTITY_PROVIDERS = {"auth0", "zitadel"}
DEFAULT_IDENTITY_PROVIDER = os.environ.get(
    "ACTIVE_IDENTITY_PROVIDER",
    os.environ.get("IDENTITY_PROVIDER", "zitadel"),
).strip().lower()
if DEFAULT_IDENTITY_PROVIDER not in SUPPORTED_IDENTITY_PROVIDERS:
    DEFAULT_IDENTITY_PROVIDER = "zitadel"
IDENTITY_PROVIDER_SETTING_KEY = "active_identity_provider"
INDIVIDUAL_USERS_ORG_ID_SETTING_KEY = "individual_users_org_id"
INDIVIDUAL_USERS_ORG_NAME_SETTING_KEY = "individual_users_org_name"
INDIVIDUAL_USERS_ORG_EMAIL_SETTING_KEY = "individual_users_org_email"
INDIVIDUAL_USERS_CONTACT_PERSON_SETTING_KEY = "individual_users_contact_person"
INDIVIDUAL_DEFAULT_PLAN_IDS_SETTING_KEY = "individual_default_plan_ids"
INDIVIDUAL_USERS_ORG_ID_FALLBACK = os.environ.get("INDIVIDUAL_USERS_ORG_ID")
INDIVIDUAL_USERS_ORG_NAME_FALLBACK = os.environ.get("INDIVIDUAL_USERS_ORG_NAME")
INDIVIDUAL_USERS_ORG_EMAIL_FALLBACK = os.environ.get("INDIVIDUAL_USERS_ORG_EMAIL")
INDIVIDUAL_USERS_CONTACT_PERSON_FALLBACK = os.environ.get("INDIVIDUAL_USERS_CONTACT_PERSON")

# Zitadel Config
ZITADEL_DOMAIN = os.environ.get('ZITADEL_DOMAIN', '')
ZITADEL_CLIENT_ID = os.environ.get('ZITADEL_CLIENT_ID', '')
ZITADEL_CLIENT_SECRET = os.environ.get('ZITADEL_CLIENT_SECRET', '')
ZITADEL_CALLBACK_URI = os.environ.get('ZITADEL_CALLBACK_URI', AUTH0_CALLBACK_URI)
ZITADEL_SHARED_CALLBACK_URI = os.environ.get(
    "ZITADEL_SHARED_CALLBACK_URI",
    os.environ.get("ZITADEL_PROBESTACK_CALLBACK_URI", ZITADEL_CALLBACK_URI),
)
ZITADEL_API_TOKEN = os.environ.get('ZITADEL_API_TOKEN', '')
ZITADEL_DEFAULT_ORG_ID = os.environ.get('ZITADEL_DEFAULT_ORG_ID', '')
ZITADEL_PROJECT_ID = os.environ.get('ZITADEL_PROJECT_ID', '')
ZITADEL_REDIRECT_URIS = {
    "probestack": os.environ.get("ZITADEL_PROBESTACK_CALLBACK_URI", ZITADEL_SHARED_CALLBACK_URI),
    "forgecatalog": os.environ.get("ZITADEL_FORGECATALOG_CALLBACK_URI", AUTH0_REDIRECT_URIS["forgecatalog"]),
    "forgefuzz": os.environ.get("ZITADEL_FORGEFUZZ_CALLBACK_URI", AUTH0_REDIRECT_URIS["forgefuzz"]),
    "console": os.environ.get("ZITADEL_CONSOLE_CALLBACK_URI", ZITADEL_SHARED_CALLBACK_URI),
    "local": os.environ.get("ZITADEL_LOCAL_CALLBACK_URI", AUTH0_REDIRECT_URIS["local"]),
}
ZITADEL_POST_LOGOUT_URIS = {
    "probestack": os.environ.get("ZITADEL_PROBESTACK_POST_LOGOUT_URI", "https://probestack.io"),
    "forgecatalog": os.environ.get("ZITADEL_FORGECATALOG_POST_LOGOUT_URI", "https://forgecatalog.com"),
    "forgefuzz": os.environ.get("ZITADEL_FORGEFUZZ_POST_LOGOUT_URI", "https://forgefuzz.com"),
    "console": os.environ.get("ZITADEL_CONSOLE_POST_LOGOUT_URI", "https://console.probestack.io"),
    "local": os.environ.get("ZITADEL_LOCAL_POST_LOGOUT_URI", "http://localhost:3000/admin/zitadel-test"),
}

# Onboarding MongoDB role lookup. Used when creating local users so existing
# onboarding roles remain the source of truth when a matching developer exists.
MONGODB_ROLE_LOOKUP_ENABLED = os.environ.get("MONGODB_ROLE_LOOKUP_ENABLED", "false").lower() in ["1", "true", "yes"]
MONGODB_URI = os.environ.get("MONGODB_URI", "")
MONGODB_DATABASE = os.environ.get("MONGODB_DATABASE", "onboard-prod")
MONGODB_DEVELOPERS_COLLECTION = os.environ.get("MONGODB_DEVELOPERS_COLLECTION", "onboarding_developers")
MONGODB_ROLE_LOOKUP_EMAIL_ONLY = os.environ.get("MONGODB_ROLE_LOOKUP_EMAIL_ONLY", "true").lower() in ["1", "true", "yes"]
_mongodb_client = None
ALLOW_CONTEXT_TOKEN_EMAIL_FALLBACK = os.environ.get("ALLOW_CONTEXT_TOKEN_EMAIL_FALLBACK", "false").lower() in ["1", "true", "yes"]
_jwks_clients = {}

from urllib.parse import quote_plus

DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")
DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = os.environ.get("DB_PORT", "3306")
INSTANCE_CONNECTION_NAME = os.environ.get("INSTANCE_CONNECTION_NAME")
RUN_RUNTIME_SCHEMA_MIGRATIONS = os.environ.get("RUN_RUNTIME_SCHEMA_MIGRATIONS", "true").lower() in ["1", "true", "yes"]
REQUIRE_RUNTIME_SCHEMA_MIGRATIONS = os.environ.get("REQUIRE_RUNTIME_SCHEMA_MIGRATIONS", "false").lower() in ["1", "true", "yes"]

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
ADMIN_BACKEND_PUBLIC_URL = (
    os.environ.get("ADMIN_BACKEND_PUBLIC_URL")
    or os.environ.get("PROBESTACK_ADMIN_BACKEND_HOST")
    or "https://probestack.io/admin-backend"
).rstrip("/")
PROBESTACK_TOKEN_ISSUER = os.environ.get("PROBESTACK_TOKEN_ISSUER", "https://auth.probestack.io")
_PROBESTACK_TOKEN_AUDIENCE_RAW = os.environ.get("PROBESTACK_TOKEN_AUDIENCE", '["probestack-api", "probestack-ui"]')
try:
    PROBESTACK_TOKEN_AUDIENCE = json.loads(_PROBESTACK_TOKEN_AUDIENCE_RAW)
except json.JSONDecodeError:
    PROBESTACK_TOKEN_AUDIENCE = [
        value.strip() for value in _PROBESTACK_TOKEN_AUDIENCE_RAW.split(",") if value.strip()
    ] or ["probestack-api", "probestack-ui"]
PROBESTACK_CONTEXT_TOKEN_ALGORITHM = "RS256"
PROBESTACK_CONTEXT_TOKEN_KID = os.environ.get("PROBESTACK_CONTEXT_TOKEN_KID", "probestack-context-rs256-1")
PROBESTACK_CONTEXT_TOKEN_PRIVATE_KEY = os.environ.get("PROBESTACK_CONTEXT_TOKEN_PRIVATE_KEY", "")
PROBESTACK_CONTEXT_TOKEN_PRIVATE_KEY_PASSPHRASE = os.environ.get("PROBESTACK_CONTEXT_TOKEN_PRIVATE_KEY_PASSPHRASE")
PROBESTACK_CONTEXT_TOKEN_JWKS_URI = os.environ.get(
    "PROBESTACK_CONTEXT_TOKEN_JWKS_URI",
    f"{ADMIN_BACKEND_PUBLIC_URL}/api/public/users/context-token/jwks",
)
_context_token_private_key = None

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
SENDGRID_API_URL = os.environ.get("SENDGRID_API_URL", "https://api.sendgrid.com/v3/mail/send")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
SENDGRID_FROM_EMAIL = os.environ.get("SENDGRID_FROM_EMAIL") or SMTP_FROM_EMAIL or "info@probestack.io"
SENDGRID_FROM_NAME = os.environ.get("SENDGRID_FROM_NAME", SMTP_FROM_NAME)
DEFAULT_ADMIN_NOTIFICATION_EMAILS = "admin@forgecrux.com,admin@probestack.io,saili.jaguste@probestack.io,saili.jaguste@gmail.com"
ORG_REQUEST_NOTIFICATION_EMAILS = ",".join(
    value for value in [
        DEFAULT_ADMIN_NOTIFICATION_EMAILS,
        os.environ.get("ORG_REQUEST_NOTIFICATION_EMAILS"),
        os.environ.get("ORG_REQUEST_NOTIFICATION_EMAIL"),
    ]
    if value
)
ORG_APPROVAL_CC_EMAILS = ",".join(
    value for value in [
        ORG_REQUEST_NOTIFICATION_EMAILS,
        os.environ.get("ORG_APPROVAL_CC_EMAILS"),
        os.environ.get("ORG_APPROVAL_CC_EMAIL"),
    ]
    if value
)
ZITADEL_PASSWORD_RESET_URL_TEMPLATE = os.environ.get(
    "ZITADEL_PASSWORD_RESET_URL_TEMPLATE",
    f"{APP_URL.rstrip('/')}/password-reset?userID={{.UserID}}&code={{.Code}}&orgID={{.OrgID}}",
)

DEFAULT_CORS_ORIGINS = [
    "https://probestack.io",
    "https://www.probestack.io",
    "https://community.probestack.io",
    "http://community.probestack.io",
]
CORS_ORIGINS = sorted({
    origin.strip().rstrip("/")
    for origin in os.environ.get("CORS_ORIGINS", ",".join(DEFAULT_CORS_ORIGINS)).split(",")
    if origin.strip()
} | set(DEFAULT_CORS_ORIGINS))
CORS_ORIGIN_REGEX = os.environ.get(
    "CORS_ORIGIN_REGEX",
    r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
)

# Create the main app
app = FastAPI()

api_router = APIRouter(prefix="/admin-backend/api")
security = HTTPBearer()
optional_security = HTTPBearer(auto_error=False)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Auth0ManagementAPI:
    """Helper class for Auth0 Management API operations"""
    def __init__(self):
        self.domain = AUTH0_MGMT_DOMAIN
        self.client_id = AUTH0_MGMT_CLIENT_ID
        self.client_secret = AUTH0_MGMT_CLIENT_SECRET
        self.connection = AUTH0_DB_CONNECTION_NAME
        self.connection_id = AUTH0_DB_CONNECTION_ID
        self.enabled = bool(AUTH0_ENABLED and self.client_id and self.client_secret and self.domain)
        self._access_token = None
        self._token_expires_at = None

    def _disabled_result(self, action: str) -> dict:
        logger.info(f"Auth0 {action} skipped: Auth0 is disabled")
        return {"success": False, "skipped": True, "error": "Auth0 is disabled"}
    
    async def _get_access_token(self) -> str:
        """Get or refresh Management API access token"""
        if not self.enabled:
            raise HTTPException(status_code=410, detail="Auth0 is disabled")
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
        if not self.enabled:
            return self._disabled_result("create user")
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

    async def create_organization(self, name: str, metadata: dict = None) -> dict:
        """Create an Auth0 organization and return its generated organization ID."""
        if not self.enabled:
            return self._disabled_result("create organization")
        token = await self._get_access_token()

        slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in (name or "").strip())
        slug = "-".join(part for part in slug.split("-") if part)[:50] or f"org-{uuid.uuid4().hex[:8]}"
        if len(slug) < 3:
            slug = f"org-{slug}"[:50]
        payload = {
            "name": slug,
            "display_name": name,
            "metadata": {key: value for key, value in (metadata or {}).items() if value not in [None, ""]},
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://{self.domain}/api/v2/organizations",
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
                timeout=30.0,
            )

        if response.status_code in [200, 201]:
            data = response.json()
            logger.info(f"Auth0 organization created: {name}")
            return {"success": True, "auth0_org_id": data.get("id"), "data": data}
        if response.status_code == 409:
            logger.warning(f"Auth0 organization already exists: {name}")
            return {"success": False, "exists": True, "error": response.text}

        logger.error(f"Auth0 create organization error: {response.text}")
        return {"success": False, "error": response.text, "status_code": response.status_code}

    async def delete_organization(self, organization_id: str) -> dict:
        """Delete an Auth0 organization by ID."""
        if not self.enabled:
            return self._disabled_result("delete organization")
        if not organization_id:
            return {"success": True, "skipped": True}
        token = await self._get_access_token()

        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"https://{self.domain}/api/v2/organizations/{organization_id}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0,
            )

        if response.status_code in [200, 202, 204]:
            logger.info(f"Auth0 organization deleted: {organization_id}")
            return {"success": True}
        if response.status_code == 404:
            logger.info(f"Auth0 organization already missing: {organization_id}")
            return {"success": True, "missing": True}

        logger.error(f"Auth0 delete organization error: {response.text}")
        return {"success": False, "error": response.text, "status_code": response.status_code}

    async def add_connection_to_organization(self, organization_id: str) -> dict:
        """Enable the configured database connection for an Auth0 organization."""
        if not self.enabled:
            return self._disabled_result("enable organization connection")
        if not self.connection_id:
            return {"success": False, "skipped": True, "error": "AUTH0_DB_CONNECTION_ID is not configured"}
        token = await self._get_access_token()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://{self.domain}/api/v2/organizations/{organization_id}/enabled_connections",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "connection_id": self.connection_id,
                    "assign_membership_on_login": False,
                },
                timeout=30.0,
            )

        if response.status_code in [200, 201]:
            return {"success": True}
        if response.status_code == 409 or "already" in response.text.lower():
            return {"success": True, "exists": True}

        logger.error(f"Auth0 enable organization connection error: {response.text}")
        return {"success": False, "error": response.text, "status_code": response.status_code}

    async def add_user_to_organization(self, organization_id: str, user_id: str) -> dict:
        """Add an Auth0 user as a member of an Auth0 organization."""
        if not self.enabled:
            return self._disabled_result("add organization member")
        token = await self._get_access_token()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://{self.domain}/api/v2/organizations/{organization_id}/members",
                headers={"Authorization": f"Bearer {token}"},
                json={"members": [user_id]},
                timeout=30.0,
            )

        if response.status_code in [200, 204]:
            return {"success": True}
        if response.status_code == 409 or "already" in response.text.lower():
            return {"success": True, "exists": True}

        logger.error(f"Auth0 add organization member error: {response.text}")
        return {"success": False, "error": response.text, "status_code": response.status_code}
    
    async def get_user_by_email(self, email: str) -> dict:
        """Get user from Auth0 by email"""
        if not self.enabled:
            return self._disabled_result("get user")
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
        if not self.enabled:
            return self._disabled_result("update password")
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
        if not self.enabled:
            return self._disabled_result("verify email")
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
        if not self.enabled:
            return self._disabled_result("send verification email")
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
        if not self.enabled:
            return self._disabled_result("send password reset email")
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
        if not self.enabled:
            return self._disabled_result("authenticate user")
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

class ZitadelManagementAPI:
    """Helper class for Zitadel user-management operations."""

    def __init__(self):
        raw_domain = (ZITADEL_DOMAIN or "").strip().rstrip("/")
        if raw_domain and not raw_domain.startswith(("http://", "https://")):
            raw_domain = f"https://{raw_domain}"
        self.base_url = raw_domain
        self.client_id = ZITADEL_CLIENT_ID
        self.client_secret = ZITADEL_CLIENT_SECRET
        self.api_token = ZITADEL_API_TOKEN
        self.default_org_id = ZITADEL_DEFAULT_ORG_ID

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.api_token)

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _connect_headers(self) -> dict:
        headers = self._headers()
        headers["Connect-Protocol-Version"] = "1"
        return headers

    @staticmethod
    def _name_parts(name: str) -> tuple[str, str]:
        cleaned = (name or "").strip()
        if not cleaned:
            return "", ""
        parts = cleaned.split()
        if len(parts) == 1:
            return parts[0], parts[0]
        return parts[0], " ".join(parts[1:])

    @staticmethod
    def _metadata_entries(metadata: Optional[dict]) -> list[dict]:
        entries = []
        for key, value in (metadata or {}).items():
            raw_value = value if isinstance(value, str) else json.dumps(value)
            encoded = base64.b64encode(raw_value.encode("utf-8")).decode("ascii")
            entries.append({"key": str(key), "value": encoded})
        return entries

    @staticmethod
    def _extract_user_id(user_payload: dict) -> Optional[str]:
        if not user_payload:
            return None
        return (
            user_payload.get("userId")
            or user_payload.get("id")
            or user_payload.get("user", {}).get("userId")
            or user_payload.get("human", {}).get("userId")
        )

    @staticmethod
    def _extract_human(user_payload: dict) -> dict:
        if not user_payload:
            return {}
        if user_payload.get("human"):
            return user_payload["human"]
        return user_payload.get("user", {}).get("human", {})

    async def create_user(
        self,
        email: str,
        name: str,
        user_metadata: dict = None,
        organization_id: Optional[str] = None,
    ) -> dict:
        """Create a human user in Zitadel and request email verification."""
        if not self.enabled:
            return {"success": False, "skipped": True, "error": "Zitadel is not configured"}

        given_name, family_name = self._name_parts(name)
        target_org_id = organization_id or self.default_org_id
        payload = {
            "username": email,
            "human": {
                "profile": {
                    "givenName": given_name,
                    "familyName": family_name,
                    "displayName": name or email,
                },
                "email": {
                    "email": email,
                    "sendCode": {},
                },
                "metadata": self._metadata_entries(user_metadata),
            },
        }
        if target_org_id:
            payload["organizationId"] = target_org_id

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/v2/users/new",
                headers=self._headers(),
                json=payload,
                timeout=30.0,
            )

        if response.status_code in [200, 201]:
            data = response.json()
            logger.info(f"Zitadel user created: {email}")
            return {
                "success": True,
                "zitadel_user_id": data.get("id") or data.get("userId"),
                "verification_email_sent": True,
                "data": data,
            }

        error_text = response.text
        if response.status_code == 409 or "already" in error_text.lower():
            logger.warning(f"Zitadel user already exists: {email}")
            return {"success": False, "error": "User already exists in Zitadel", "exists": True}

        logger.error(f"Zitadel create user error: {error_text}")
        return {"success": False, "error": error_text}

    async def create_organization(self, name: str, organization_id: Optional[str] = None) -> dict:
        """Create a Zitadel organization and return its generated organization ID."""
        if not self.enabled:
            return {"success": False, "skipped": True, "error": "Zitadel is not configured"}

        payload = {"name": name}
        if organization_id:
            payload["organizationId"] = organization_id

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/v2/organizations",
                headers=self._headers(),
                json=payload,
                timeout=30.0,
            )

        if response.status_code in [200, 201]:
            data = response.json()
            return {
                "success": True,
                "zitadel_org_id": data.get("organizationId") or data.get("orgId") or data.get("id"),
                "data": data,
            }

        logger.error(f"Zitadel create organization error: {response.text}")
        return {"success": False, "error": response.text, "status_code": response.status_code}

    async def add_organization_domain(self, organization_id: str, domain: str) -> dict:
        """Register an organization domain in Zitadel."""
        if not self.enabled:
            return {"success": False, "skipped": True, "error": "Zitadel is not configured"}
        cleaned_domain = (domain or "").strip().lower().lstrip("@")
        if not cleaned_domain:
            return {"success": False, "skipped": True, "error": "No organization domain provided"}

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/v2/organizations/{organization_id}/domains",
                headers=self._headers(),
                json={"domain": cleaned_domain},
                timeout=30.0,
            )

        if response.status_code in [200, 201]:
            return {"success": True, "domain": cleaned_domain}
        if response.status_code == 409 or "already" in response.text.lower():
            return {"success": True, "exists": True, "domain": cleaned_domain}

        logger.warning(f"Zitadel add organization domain error: {response.text}")
        return {"success": False, "error": response.text, "status_code": response.status_code}

    async def set_user_metadata(self, user_id: str, metadata: dict) -> dict:
        """Set ProbeStack metadata on a Zitadel user for token action custom claims."""
        if not self.enabled:
            return {"success": False, "skipped": True, "error": "Zitadel is not configured"}
        if not user_id:
            return {"success": False, "skipped": True, "error": "Zitadel user ID is required"}

        entries = self._metadata_entries({k: v for k, v in (metadata or {}).items() if v is not None})
        if not entries:
            return {"success": True, "skipped": True, "metadata": []}

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/v2/users/{user_id}/metadata",
                headers=self._headers(),
                json={"metadata": entries},
                timeout=30.0,
            )

        if response.status_code == 200:
            return {"success": True, "metadata_keys": [entry["key"] for entry in entries]}

        logger.warning(f"Zitadel set user metadata error: {response.text}")
        return {"success": False, "error": response.text, "status_code": response.status_code}

    async def set_organization_metadata(self, organization_id: str, metadata: dict) -> dict:
        """Set ProbeStack metadata on a Zitadel organization for token action custom claims."""
        if not self.enabled:
            return {"success": False, "skipped": True, "error": "Zitadel is not configured"}
        if not organization_id:
            return {"success": False, "skipped": True, "error": "Zitadel organization ID is required"}

        entries = self._metadata_entries({k: v for k, v in (metadata or {}).items() if v is not None})
        if not entries:
            return {"success": True, "skipped": True, "metadata": []}

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/v2/organizations/{organization_id}/metadata",
                headers=self._headers(),
                json={"metadata": entries},
                timeout=30.0,
            )

        if response.status_code == 200:
            return {"success": True, "metadata_keys": [entry["key"] for entry in entries]}

        logger.warning(f"Zitadel set organization metadata error: {response.text}")
        return {"success": False, "error": response.text, "status_code": response.status_code}

    async def assign_user_roles(
        self,
        user_id: str,
        organization_id: str,
        role_keys: list[str],
        project_id: Optional[str] = None,
    ) -> dict:
        """Create a Zitadel role assignment for a user in the configured project."""
        if not self.enabled:
            return {"success": False, "skipped": True, "error": "Zitadel is not configured"}
        target_project_id = (project_id or ZITADEL_PROJECT_ID or "").strip()
        cleaned_role_keys = [key for key in role_keys if key]
        if not target_project_id:
            return {"success": False, "skipped": True, "error": "ZITADEL_PROJECT_ID is not configured"}
        if not user_id or not organization_id or not cleaned_role_keys:
            return {"success": False, "skipped": True, "error": "user_id, organization_id, and role_keys are required"}

        payload = {
            "userId": user_id,
            "projectId": target_project_id,
            "organizationId": organization_id,
            "roleKeys": cleaned_role_keys,
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/zitadel.authorization.v2.AuthorizationService/CreateAuthorization",
                headers=self._connect_headers(),
                json=payload,
                timeout=30.0,
            )

        if response.status_code in [200, 201]:
            data = response.json()
            return {"success": True, "authorization_id": data.get("id"), "role_keys": cleaned_role_keys, "data": data}
        if response.status_code == 409 or "already" in response.text.lower():
            return {"success": True, "exists": True, "role_keys": cleaned_role_keys}

        logger.warning(f"Zitadel role assignment error: {response.text}")
        return {"success": False, "error": response.text, "status_code": response.status_code, "role_keys": cleaned_role_keys}

    async def get_user_by_email(
        self,
        email: str,
        organization_id: Optional[str] = None,
        use_default_org: bool = True,
    ) -> dict:
        """Get a Zitadel user by exact email match."""
        if not self.enabled:
            return {"success": False, "skipped": True, "error": "Zitadel is not configured"}

        queries = [{"emailQuery": {"emailAddress": email, "method": 1}}]
        target_org_id = organization_id if organization_id is not None else (self.default_org_id if use_default_org else None)
        if target_org_id:
            queries.insert(0, {"organizationIdQuery": {"organizationId": target_org_id}})
        payload = {
            "query": {"offset": "0", "limit": 1, "asc": True},
            "sortingColumn": "USER_FIELD_NAME_UNSPECIFIED",
            "queries": queries,
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/v2/users",
                headers=self._headers(),
                json=payload,
                timeout=30.0,
            )

        if response.status_code == 200:
            data = response.json()
            users = data.get("result", [])
            if users:
                return {"success": True, "user": users[0]}
            return {"success": False, "error": "User not found"}

        logger.error(f"Zitadel get user error: {response.text}")
        return {"success": False, "error": response.text}

    async def get_user_by_id(self, user_id: str) -> dict:
        if not self.enabled:
            return {"success": False, "skipped": True, "error": "Zitadel is not configured"}
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/v2/users/{user_id}",
                headers=self._headers(),
                timeout=30.0,
            )
        if response.status_code == 200:
            return {"success": True, "user": response.json().get("user", response.json())}
        logger.error(f"Zitadel get user by ID error: {response.text}")
        return {"success": False, "error": response.text}

    async def update_user_password(self, user_id: str, password: str) -> dict:
        """Set a user's password in Zitadel."""
        if not self.enabled:
            return {"success": False, "skipped": True, "error": "Zitadel is not configured"}
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/users/{user_id}/password",
                headers=self._headers(),
                json={"password": password, "noChangeRequired": True},
                timeout=30.0,
            )
        if response.status_code == 200:
            logger.info(f"Zitadel password updated for user: {user_id}")
            return {"success": True}
        logger.error(f"Zitadel update password error: {response.text}")
        return {"success": False, "error": response.text}

    async def verify_user_email(self, user_id: str) -> dict:
        """Mark a user's email as verified in Zitadel."""
        user_result = await self.get_user_by_id(user_id)
        if not user_result.get("success"):
            return user_result
        human = self._extract_human(user_result.get("user", {}))
        email = human.get("email", {}).get("email")
        if not email:
            return {"success": False, "error": "Zitadel user email not found"}

        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"{self.base_url}/v2/users/{user_id}",
                headers=self._headers(),
                json={"human": {"email": {"email": email, "isVerified": True}}},
                timeout=30.0,
            )
        if response.status_code == 200:
            logger.info(f"Zitadel email verified for user: {user_id}")
            return {"success": True}
        logger.error(f"Zitadel verify email error: {response.text}")
        return {"success": False, "error": response.text}

    async def send_verification_email(self, user_id: str) -> dict:
        """Send or resend the Zitadel email verification code."""
        if not self.enabled:
            return {"success": False, "skipped": True, "error": "Zitadel is not configured"}
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/v2/users/{user_id}/email/send",
                headers=self._headers(),
                json={"sendCode": {}},
                timeout=30.0,
            )
        if response.status_code == 200:
            logger.info(f"Zitadel verification email sent to user: {user_id}")
            return {"success": True}
        logger.error(f"Zitadel send verification email error: {response.text}")
        return {"success": False, "error": response.text}

    async def send_password_reset_email(self, email: str) -> dict:
        """Send a Zitadel password reset email."""
        user_result = await self.get_user_by_email(email)
        if not user_result.get("success"):
            return user_result
        user_id = self._extract_user_id(user_result.get("user", {}))
        if not user_id:
            return {"success": False, "error": "Zitadel user ID not found"}
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/v2/users/{user_id}/password_reset",
                headers=self._headers(),
                json={
                    "sendLink": {
                        "notificationType": "NOTIFICATION_TYPE_Email",
                        "urlTemplate": ZITADEL_PASSWORD_RESET_URL_TEMPLATE,
                    }
                },
                timeout=30.0,
            )
        if response.status_code == 200:
            logger.info(f"Zitadel password reset email sent to: {email}")
            return {"success": True}
        logger.error(f"Zitadel send password reset email error: {response.text}")
        return {"success": False, "error": response.text}

    async def send_password_reset_email_by_user_id(self, user_id: str) -> dict:
        """Send a Zitadel password reset email for a known user id."""
        if not self.enabled:
            return {"success": False, "skipped": True, "error": "Zitadel is not configured"}
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/v2/users/{user_id}/password_reset",
                headers=self._headers(),
                json={
                    "sendLink": {
                        "notificationType": "NOTIFICATION_TYPE_Email",
                        "urlTemplate": ZITADEL_PASSWORD_RESET_URL_TEMPLATE,
                    }
                },
                timeout=30.0,
            )
        if response.status_code == 200:
            logger.info(f"Zitadel password reset email sent to user id: {user_id}")
            return {"success": True}
        logger.error(f"Zitadel send password reset email by ID error: {response.text}")
        return {"success": False, "error": response.text}

zitadel_mgmt = ZitadelManagementAPI()

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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)  # Who created this admin

class SystemSettingModel(Base):
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    updated_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

class OrganizationModel(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")
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
    zitadel_org_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    organization_code: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    legal_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    industry: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    business_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(2), nullable=True)
    region: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    time_zone: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    headquarters: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    default_currency: Mapped[Optional[str]] = mapped_column(String(3), nullable=True)
    billing_account: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    cost_center: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    tax_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    website: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    logo_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    primary_contact_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    executive_sponsor_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    technical_contact_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    security_contact_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    identity_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    sso_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    scim_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False)
    default_api_gateway: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    default_ai_gateway: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    default_mcp_gateway: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    default_api_design_tool: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    default_api_testing_tool: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    api_agent_lifecycle_stage: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    default_api_inventory: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    cloud_provider: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    kubernetes_platform: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    default_environment_strategy: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    compliance_standards: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    encryption_standard: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    data_residency: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    gateway_region: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    gateway_organization_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    gateway_environment_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    gateway_environments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class SubscriptionModel(Base):
    __tablename__ = "subscriptions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="active")
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    billing_cycle: Mapped[str] = mapped_column(String(50), default="monthly")
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    api_count: Mapped[Optional[int]] = mapped_column(nullable=True)
    quota: Mapped[Optional[int]] = mapped_column(nullable=True)
    used_quota: Mapped[int] = mapped_column(default=0)
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
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    display_order: Mapped[int] = mapped_column(default=0)  # For ordering tools in UI
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class UserModel(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    role_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    theme_preference: Mapped[str] = mapped_column(String(20), default="system")  # light, dark, system
    # Auth0 integration fields
    auth0_user_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Auth0 user ID
    zitadel_user_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Zitadel user ID
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)  # Email verification status
    password_set: Mapped[bool] = mapped_column(Boolean, default=False)  # Has user set their password
    first_login_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

class RoleModel(Base):
    __tablename__ = "roles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    permissions: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class UserRoleAssignmentModel(Base):
    __tablename__ = "user_role_assignments"
    __table_args__ = (
        UniqueConstraint("user_id", "role_id", name="uq_user_role_assignments_user_role"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_id: Mapped[str] = mapped_column(String(36), ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class BillingModel(Base):
    __tablename__ = "billing"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
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

class NotificationGroupEmailModel(Base):
    __tablename__ = "notification_group_emails"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class UserRequestModel(Base):
    """Model for user addition requests from external applications"""
    __tablename__ = "user_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
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
    current_plan_id: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array of current plan IDs
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

class ZitadelLoginRecordModel(Base):
    """Model for storing Zitadel login records"""
    __tablename__ = "zitadel_login_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    external_org_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    zitadel_org_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    zitadel_user_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    picture: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    access_token: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    refresh_token: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    id_token: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    token_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    expires_in: Mapped[Optional[int]] = mapped_column(nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    login_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class IdentitySessionRevocationModel(Base):
    """Provider token/session revocations checked by all products."""
    __tablename__ = "identity_session_revocations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    identity_provider: Mapped[str] = mapped_column(String(50), nullable=False)
    issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    session_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    token_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    login_record_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

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
    display_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    parent_business_unit_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    division: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    line_of_business: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    business_executive_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    business_owner_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    product_owner_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    technical_owner_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    enterprise_architect_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    platform_owner_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    security_owner_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    compliance_officer_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    support_team: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    operations_team: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    cost_center: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    budget: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    chargeback_model: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    billing_account: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    monthly_budget: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    annual_budget: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ai_budget: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    api_budget: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cloud_provider: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    region: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    kubernetes_cluster: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    namespace: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    api_gateway: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ai_gateway: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    logging_platform: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    monitoring_platform: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    secret_manager: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approval_workflow: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    risk_classification: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    business_criticality: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    data_classification: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    regulatory_standards: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retention_policy: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    backup_policy: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    dr_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    sla_tier: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
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
    project_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    portfolio: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    project_manager_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    product_manager_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    scrum_master_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    technical_lead_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    security_lead_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    devops_lead_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    methodology: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    sprint_duration: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    repository: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    cicd_tool: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    issue_tracker: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    documentation_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    authentication_method: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    authorization_method: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    oauth_provider: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mtls_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    jwt_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    api_key_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    secrets_vault: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    pci_applicable: Mapped[bool] = mapped_column(Boolean, default=False)
    standard_rules: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    custom_rules: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owasp_top10_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    linting_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(50), default="active")
    created_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("admins.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class ProjectEnvironmentModel(Base):
    __tablename__ = "project_environments"
    __table_args__ = (
        UniqueConstraint("project_id", "environment_type", name="uq_project_environments_project_type"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    environment_type: Mapped[str] = mapped_column(String(50), nullable=False)
    endpoint_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class ApplicationModel(Base):
    __tablename__ = "applications"
    __table_args__ = (
        UniqueConstraint("project_id", "application_name", name="uq_applications_project_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    application_name: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    business_capability: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    application_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    criticality: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    runtime: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    language: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    framework: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    container_image: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    kubernetes_namespace: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    cluster: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    api_count: Mapped[int] = mapped_column(default=0)
    api_gateway: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    base_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    openapi_spec_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    asyncapi_spec_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    graphql_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    webhooks_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    llm_provider: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    default_model: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    embedding_model: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ai_gateway: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    vector_database: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    prompt_registry: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mcp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mcp_server: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mcp_resources: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mcp_tools: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mcp_prompts: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("admins.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class ApplicationAgentModel(Base):
    __tablename__ = "application_agents"
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True)
    agent_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    planner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    executor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    memory: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    knowledge_base: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    multi_agent_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    workflow: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

class ApplicationMonitoringModel(Base):
    __tablename__ = "application_monitoring"
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True)
    logging: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    metrics: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tracing: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    alerts: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    dashboards: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

class ApplicationSecurityModel(Base):
    __tablename__ = "application_security"
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True)
    oauth_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    jwt_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    api_key_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mtls_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    dlp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    waf_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    encryption_standard: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

class ApplicationBillingModel(Base):
    __tablename__ = "application_billing"
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True)
    cost_center: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    monthly_budget: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    token_budget: Mapped[Optional[int]] = mapped_column(nullable=True)
    api_budget: Mapped[Optional[int]] = mapped_column(nullable=True)

class QuotaModel(Base):
    __tablename__ = "quotas"
    __table_args__ = (
        UniqueConstraint("entity_type", "entity_id", "quota_type", name="uq_quotas_entity_type"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    quota_type: Mapped[str] = mapped_column(String(100), nullable=False)
    quota_limit: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    quota_used: Mapped[float] = mapped_column(Float, default=0)
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

class SubscriptionApiCountUpdate(BaseModel):
    api_count: Optional[int] = None

class SubscriptionQuotaUpdate(BaseModel):
    quota: Optional[int] = None
    used_quota: Optional[int] = None
    usage_delta: Optional[int] = None
    remaining_quota: Optional[int] = None

class OrganizationSubscriptionApiCountUpdate(BaseModel):
    subscription_id: str
    api_count: Optional[int] = None

class OrganizationSubscriptionQuotaUpdate(BaseModel):
    subscription_id: str
    quota: Optional[int] = None
    used_quota: Optional[int] = None

class OrganizationApiCountUpdate(BaseModel):
    api_count: Optional[int] = None
    subscription_id: Optional[str] = None
    subscriptions: Optional[List[OrganizationSubscriptionApiCountUpdate]] = None

class OrganizationQuotaUpdate(BaseModel):
    quota: Optional[int] = None
    used_quota: Optional[int] = None
    subscription_id: Optional[str] = None
    subscriptions: Optional[List[OrganizationSubscriptionQuotaUpdate]] = None

class SubscriptionBillingSettingsUpdate(BaseModel):
    api_count: Optional[int] = None
    quota: Optional[int] = None
    used_quota: Optional[int] = None
    amount: Optional[float] = None

class NotificationGroupEmailCreate(BaseModel):
    email: str
    name: Optional[str] = None
    is_active: Optional[bool] = True

class NotificationGroupEmailUpdate(BaseModel):
    email: Optional[str] = None
    name: Optional[str] = None
    is_active: Optional[bool] = None

class BillingInvoiceEmailRequest(BaseModel):
    emails: List[str]

class OrganizationCreate(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    email: str
    domain: str
    requested_plans: Optional[List[Any]] = None
    requested_tools: Optional[List[str]] = None
    plans: Optional[List[Any]] = None
    contact_person: str
    phone: str
    address: str
    description: str
    gateway_region: Optional[str] = None
    gateway_organization_name: Optional[str] = None
    gateway_environment_type: Optional[str] = None
    gateway_environments: Optional[List[str]] = None

class OrganizationRequest(BaseModel):
    """Schema for external API requests to register an organization"""
    model_config = ConfigDict(extra="allow")

    name: str
    email: str
    domain: str
    plan_ids: Optional[List[str]] = None  # Legacy list of Plan IDs like ["plan_forgeq_enterprise"]
    selected_tools: Optional[List[str]] = None  # Legacy flat list of selected tool IDs/names
    plans: Optional[List[Any]] = None  # New product-plan payload from /public/plans
    requested_plans: Optional[List[Any]] = None  # Alternate product-plan payload key
    contact_person: str
    contact_phone: str
    company_address: str
    additional_notes: Optional[str] = None
    description: str
    gateway_region: Optional[str] = None
    gateway_organization_name: Optional[str] = None
    gateway_environment_type: Optional[str] = None
    gateway_environments: Optional[List[str]] = None
    identity_provider: Optional[str] = None
    skip_auth0: Optional[bool] = False

class OrganizationUpdate(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: Optional[str] = None
    email: Optional[str] = None
    domain: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    external_org_id: Optional[str] = None
    supported_domains: Optional[List[str]] = None
    auth0_org_id: Optional[str] = None  # Auth0 organization ID
    zitadel_org_id: Optional[str] = None  # Zitadel organization ID
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
    product: Optional[str] = "probestack"
    redirect_uri: Optional[str] = None
    
class Auth0CallbackRequest(BaseModel):
    """Request to exchange Auth0 code for tokens"""
    code: str
    email: Optional[str] = None  # Original email for logging purposes
    product: Optional[str] = "probestack"
    redirect_uri: Optional[str] = None

class ZitadelInitRequest(BaseModel):
    """Request to initiate Zitadel authentication with one shared app."""
    email: str
    state: Optional[str] = None
    product: Optional[str] = "probestack"
    redirect_uri: Optional[str] = None

class ZitadelCallbackRequest(BaseModel):
    """Request to exchange Zitadel code for tokens."""
    code: str
    email: Optional[str] = None
    product: Optional[str] = "probestack"
    redirect_uri: Optional[str] = None

class ZitadelRefreshTokenRequest(BaseModel):
    """Request to refresh Zitadel user tokens."""
    refresh_token: str

class IdentityLogoutRequest(BaseModel):
    """Request to clear product auth and start provider logout."""
    token: Optional[str] = None
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    identity_provider: Optional[str] = None
    login_record_id: Optional[str] = None
    product: Optional[str] = None
    post_logout_redirect_uri: Optional[str] = None
    state: Optional[str] = None
    logout_hint: Optional[str] = None

class IdentitySessionValidateRequest(BaseModel):
    """Request to verify provider token and central logout status."""
    token: Optional[str] = None
    id_token: Optional[str] = None
    identity_provider: Optional[str] = None

class UserContextTokenRequest(BaseModel):
    """Request to issue a ProbeStack user-context token after probestack.io login."""
    email: Optional[str] = None
    auth0_user_id: Optional[str] = None
    zitadel_user_id: Optional[str] = None
    identity_provider: Optional[str] = None
    id_token: Optional[str] = None

class IdentityProviderUpdate(BaseModel):
    provider: str

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
    display_order: int = 0

class PlanToolUpdate(BaseModel):
    """Schema for updating a tool within a plan"""
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    display_order: Optional[int] = None

class UserCreate(BaseModel):
    email: str
    name: str
    organization_id: str
    role_id: str

class RoleCreate(BaseModel):
    name: str
    organization_id: Optional[str] = None
    permissions: List[str]
    description: Optional[str] = None

class UserRequestCreate(BaseModel):
    """Schema for external API requests to add a user to an organization"""
    email: str
    name: str
    organization_id: str
    requested_role: str  # Role name from the global roles table
    job_title: Optional[str] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    notes: Optional[str] = None
    identity_provider: Optional[str] = None
    skip_auth0: Optional[bool] = False

class BusinessUnitCreate(BaseModel):
    model_config = ConfigDict(extra="allow")

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
    model_config = ConfigDict(extra="allow")

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
    model_config = ConfigDict(extra="allow")

    name: str
    business_unit_id: Optional[str] = None
    code: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = "active"

class ProjectUpdate(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: Optional[str] = None
    business_unit_id: Optional[str] = None
    code: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None

class ProjectTeamInviteCreate(BaseModel):
    emails: List[str]
    project_role: Optional[str] = "member"

class ExternalProjectCreate(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    business_unit_id: str
    code: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = "active"

class ApplicationCreate(BaseModel):
    model_config = ConfigDict(extra="allow")

    project_id: str
    application_name: str

class ApplicationUpdate(BaseModel):
    model_config = ConfigDict(extra="allow")

    project_id: Optional[str] = None
    application_name: Optional[str] = None

# ==================== HELPERS ====================

async def sync_user_from_auth0(
    user: UserModel,
    db: AsyncSession,
    *,
    allow_password_sync: bool = True,
    allow_status_activation: bool = True
) -> bool:
    """
    Synchronize user state from external identity providers into local DB.

    Rules:
    - Auth0/Zitadel are sources of truth for email_verified
    - If either provider has email_verified=True → DB is updated
    - If either provider user exists → password_set=True
    - Clears first_login_token when account becomes active
    - Safe to call multiple times (idempotent)

    Returns:
        True  -> user state was changed
        False -> no changes
    """

    # No external identity user → nothing to sync
    if not user.auth0_user_id and not user.zitadel_user_id:
        return False

    updated = False

    if user.auth0_user_id:
        try:
            auth0_result = await auth0_mgmt.get_user_by_email(user.email)
        except Exception as e:
            logger.warning(f"Auth0 sync skipped for {user.email}: {e}")
            auth0_result = {"success": False}

        if auth0_result.get("success"):
            auth0_user = auth0_result.get("user", {})
            auth0_email_verified = auth0_user.get("email_verified")

            if auth0_email_verified and not user.email_verified:
                user.email_verified = True
                updated = True

            if allow_password_sync and not user.password_set:
                user.password_set = True
                updated = True

    if user.zitadel_user_id:
        try:
            zitadel_result = await zitadel_mgmt.get_user_by_id(user.zitadel_user_id)
        except Exception as e:
            logger.warning(f"Zitadel sync skipped for {user.email}: {e}")
            zitadel_result = {"success": False}

        if zitadel_result.get("success"):
            human = zitadel_mgmt._extract_human(zitadel_result.get("user", {}))
            zitadel_email_verified = human.get("email", {}).get("isVerified")

            if zitadel_email_verified and not user.email_verified:
                user.email_verified = True
                updated = True

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

ORGANIZATION_ONBOARDING_FIELDS = [
    "organization_code", "legal_name", "industry", "business_type", "country", "region",
    "time_zone", "headquarters", "default_currency", "billing_account", "cost_center",
    "tax_id", "website", "logo_url", "primary_contact_id", "executive_sponsor_id",
    "technical_contact_id", "security_contact_id", "identity_provider", "sso_enabled",
    "scim_enabled", "mfa_required", "default_api_gateway", "default_ai_gateway",
    "default_mcp_gateway", "default_api_design_tool", "default_api_testing_tool",
    "api_agent_lifecycle_stage", "default_api_inventory", "cloud_provider",
    "kubernetes_platform", "default_environment_strategy", "compliance_standards",
    "encryption_standard", "data_residency",
]

BUSINESS_UNIT_ONBOARDING_FIELDS = [
    "display_name", "parent_business_unit_id", "division", "department", "line_of_business",
    "business_executive_id", "business_owner_id", "product_owner_id", "technical_owner_id",
    "enterprise_architect_id", "platform_owner_id", "security_owner_id", "compliance_officer_id",
    "support_team", "operations_team", "cost_center", "budget", "chargeback_model",
    "billing_account", "monthly_budget", "annual_budget", "ai_budget", "api_budget",
    "cloud_provider", "region", "kubernetes_cluster", "namespace", "api_gateway",
    "ai_gateway", "logging_platform", "monitoring_platform", "secret_manager",
    "approval_workflow", "risk_classification", "business_criticality", "data_classification",
    "regulatory_standards", "retention_policy", "backup_policy", "dr_enabled", "sla_tier",
]
BUSINESS_UNIT_QUOTA_FIELDS = {
    "api_calls_quota": "api_calls",
    "ai_tokens_quota": "ai_tokens",
    "storage_quota": "storage",
    "compute_hours_quota": "compute_hours",
    "agent_runtime_quota": "agent_runtime",
    "mcp_connections_quota": "mcp_connections",
}

PROJECT_ONBOARDING_FIELDS = [
    "project_type", "portfolio", "project_manager_id", "product_manager_id", "scrum_master_id",
    "technical_lead_id", "security_lead_id", "devops_lead_id", "methodology", "sprint_duration",
    "repository", "cicd_tool", "issue_tracker", "documentation_url", "authentication_method",
    "authorization_method", "oauth_provider", "mtls_enabled", "jwt_enabled", "api_key_enabled",
    "secrets_vault", "pci_applicable", "standard_rules", "custom_rules", "owasp_top10_enabled",
    "linting_enabled",
]
PROJECT_ENVIRONMENT_TYPES = ["Dev", "QA", "UAT", "Performance", "Stage", "Production"]

APPLICATION_FIELDS = [
    "application_name", "display_name", "description", "business_capability", "domain",
    "application_type", "criticality", "runtime", "language", "framework", "version",
    "container_image", "kubernetes_namespace", "cluster", "api_count", "api_gateway",
    "base_url", "openapi_spec_url", "asyncapi_spec_url", "graphql_enabled",
    "webhooks_enabled", "llm_provider", "default_model", "embedding_model", "ai_gateway",
    "vector_database", "prompt_registry", "mcp_enabled", "mcp_server", "mcp_resources",
    "mcp_tools", "mcp_prompts",
]

APPLICATION_AGENT_FIELDS = [
    "agent_enabled", "planner", "executor", "memory", "knowledge_base", "multi_agent_enabled", "workflow",
]
APPLICATION_MONITORING_FIELDS = ["logging", "metrics", "tracing", "alerts", "dashboards"]
APPLICATION_SECURITY_FIELDS = [
    "oauth_enabled", "jwt_enabled", "api_key_enabled", "mtls_enabled", "dlp_enabled",
    "waf_enabled", "encryption_standard",
]
APPLICATION_BILLING_FIELDS = ["cost_center", "monthly_budget", "token_budget", "api_budget"]

TEXT_LIST_FIELDS = {"compliance_standards", "regulatory_standards", "mcp_resources", "mcp_tools", "mcp_prompts"}
BOOL_FIELDS = {
    "sso_enabled", "scim_enabled", "mfa_required", "dr_enabled", "mtls_enabled", "jwt_enabled",
    "api_key_enabled", "pci_applicable", "owasp_top10_enabled", "linting_enabled",
    "graphql_enabled", "webhooks_enabled", "mcp_enabled", "agent_enabled", "multi_agent_enabled",
    "oauth_enabled", "dlp_enabled", "waf_enabled",
}
NUMBER_FIELDS = {
    "budget", "monthly_budget", "annual_budget", "ai_budget", "api_budget", "api_count", "token_budget",
    *BUSINESS_UNIT_QUOTA_FIELDS.keys(),
}
PROJECT_STATUS_VALUES = {"active", "inactive", "pending", "on_hold", "completed", "archived"}

def payload_dict(data: BaseModel, *, exclude_unset: bool = False) -> dict:
    payload = data.model_dump(exclude_unset=exclude_unset)
    payload.update(getattr(data, "model_extra", None) or {})
    return payload

def normalize_onboarding_value(key: str, value: Any) -> Any:
    if key in TEXT_LIST_FIELDS and isinstance(value, list):
        return json.dumps(value)
    if key in BOOL_FIELDS:
        return bool(value)
    if key in NUMBER_FIELDS and value in ["", None]:
        return None
    if key in NUMBER_FIELDS:
        try:
            return int(value) if key in {"api_count", "token_budget", "api_budget"} else float(value)
        except (TypeError, ValueError):
            return value
    if isinstance(value, str):
        return value.strip() or None
    return value

def apply_onboarding_fields(model: Any, payload: dict, allowed_fields: list[str]):
    for key in allowed_fields:
        if key in payload:
            setattr(model, key, normalize_onboarding_value(key, payload.get(key)))

def validate_required_organization_create_fields(payload: dict):
    required_fields = {
        "name": "Organization name",
        "email": "Email",
        "domain": "Domain",
        "contact_person": "Contact person",
        "description": "Description",
    }
    missing = [
        label
        for key, label in required_fields.items()
        if not str(payload.get(key) or "").strip()
    ]
    if not str(payload.get("phone") or payload.get("contact_phone") or "").strip():
        missing.append("Contact phone")
    if not str(payload.get("address") or payload.get("company_address") or "").strip():
        missing.append("Company address")
    if missing:
        raise HTTPException(status_code=400, detail=f"Required fields missing: {', '.join(missing)}")

def add_identity_aliases(data: dict, entity: str) -> dict:
    if entity == "organization":
        data["organization_id"] = data.get("id")
        data["organization_name"] = data.get("name")
    elif entity == "business_unit":
        data["business_unit_id"] = data.get("id")
        data["business_unit_name"] = data.get("name")
        data["business_unit_code"] = data.get("code")
    elif entity == "project":
        data["project_id"] = data.get("id")
        data["project_name"] = data.get("name")
        data["project_code"] = data.get("code")
    elif entity == "application":
        data["application_id"] = data.get("id")
    return data

async def project_to_dict(db: AsyncSession, project: ProjectModel) -> dict:
    data = add_identity_aliases(model_to_dict(project), "project")
    env_result = await db.execute(
        select(ProjectEnvironmentModel)
        .where(ProjectEnvironmentModel.project_id == project.id)
        .order_by(ProjectEnvironmentModel.environment_type.asc())
    )
    environments = {}
    for env in env_result.scalars().all():
        key = env.environment_type.lower().replace(" ", "_")
        environments[key] = {
            "environment_type": env.environment_type,
            "endpoint_url": env.endpoint_url,
            "is_enabled": env.is_enabled,
        }
        data[f"{key}_endpoint_url"] = env.endpoint_url
        data[f"{key}_enabled"] = env.is_enabled
    data["environments"] = environments
    return data

async def business_unit_to_dict(db: AsyncSession, business_unit: BusinessUnitModel) -> dict:
    data = add_identity_aliases(model_to_dict(business_unit, ["tags", "regulatory_standards"]), "business_unit")
    result = await db.execute(
        select(QuotaModel).where(
            QuotaModel.entity_type == "business_unit",
            QuotaModel.entity_id == business_unit.id,
        )
    )
    quota_key_by_type = {quota_type: field_key for field_key, quota_type in BUSINESS_UNIT_QUOTA_FIELDS.items()}
    data["quotas"] = {}
    for quota in result.scalars().all():
        field_key = quota_key_by_type.get(quota.quota_type)
        if field_key:
            data[field_key] = quota.quota_limit
        data["quotas"][quota.quota_type] = {
            "limit": quota.quota_limit,
            "used": quota.quota_used,
        }
    return data

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

def normalize_role_ids(role_ids: Optional[List[str]]) -> List[str]:
    seen = set()
    normalized = []
    for role_id in role_ids or []:
        if not role_id or role_id in seen:
            continue
        seen.add(role_id)
        normalized.append(role_id)
    return normalized

async def get_standard_roles_by_ids(db: AsyncSession, role_ids: List[str]) -> List[RoleModel]:
    normalized_ids = normalize_role_ids(role_ids)
    if not normalized_ids:
        raise HTTPException(status_code=400, detail="At least one role is required")
    result = await db.execute(
        select(RoleModel).where(
            RoleModel.id.in_(normalized_ids),
            RoleModel.organization_id.is_(None),
        )
    )
    role_by_id = {role.id: role for role in result.scalars().all()}
    missing_ids = [role_id for role_id in normalized_ids if role_id not in role_by_id]
    if missing_ids:
        raise HTTPException(status_code=404, detail="Standard role not found")
    return [role_by_id[role_id] for role_id in normalized_ids]

async def get_user_assigned_roles(db: AsyncSession, user: UserModel) -> List[RoleModel]:
    result = await db.execute(
        select(RoleModel)
        .join(UserRoleAssignmentModel, UserRoleAssignmentModel.role_id == RoleModel.id)
        .where(UserRoleAssignmentModel.user_id == user.id)
        .where(RoleModel.organization_id.is_(None))
        .order_by(RoleModel.name.asc())
    )
    assigned_roles = result.scalars().all()
    roles_by_id = {role.id: role for role in assigned_roles}
    ordered_roles = []
    seen = set()

    if user.role_id:
        primary_role = roles_by_id.get(user.role_id)
        if not primary_role:
            primary_result = await db.execute(
                select(RoleModel).where(
                    RoleModel.id == user.role_id,
                    RoleModel.organization_id.is_(None),
                )
            )
            primary_role = primary_result.scalar_one_or_none()
        if primary_role:
            ordered_roles.append(primary_role)
            seen.add(primary_role.id)

    for role in assigned_roles:
        if role.id not in seen:
            ordered_roles.append(role)
            seen.add(role.id)

    return ordered_roles

def roles_to_dict_list(roles: List[RoleModel]) -> List[dict]:
    return [model_to_dict(role, ["permissions"]) for role in roles]

async def replace_user_role_assignments(db: AsyncSession, user: UserModel, roles: List[RoleModel]) -> None:
    if not roles:
        raise HTTPException(status_code=400, detail="At least one role is required")
    user.role_id = roles[0].id
    await db.execute(
        delete(UserRoleAssignmentModel).where(UserRoleAssignmentModel.user_id == user.id)
    )
    await db.flush()
    for role in roles:
        db.add(UserRoleAssignmentModel(user_id=user.id, role_id=role.id))

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

def normalize_token_value(value: Optional[str], fallback: str = "member") -> str:
    normalized = "".join(ch.lower() if ch.isalnum() else "_" for ch in (value or "").strip())
    normalized = "_".join(part for part in normalized.split("_") if part)
    return normalized or fallback

def standard_role_slug(name: str) -> str:
    return normalize_token_value(name, "role")

def zitadel_role_key_for_role(role_name: Optional[str]) -> str:
    return standard_role_slug(role_name or "role")

DEFAULT_CONSUMER_ROLE_SLUG = os.environ.get("DEFAULT_CONSUMER_ROLE_SLUG", "api_agent_consumer")
DEFAULT_READ_ONLY_ROLE_SLUG = os.environ.get("DEFAULT_READ_ONLY_ROLE_SLUG", "read_only_auditor")

async def get_global_standard_roles(db: AsyncSession) -> List[RoleModel]:
    result = await db.execute(
        select(RoleModel)
        .where(RoleModel.organization_id.is_(None))
        .order_by(RoleModel.name.asc())
    )
    return result.scalars().all()

async def map_to_standard_role_name(db: AsyncSession, role_name: Optional[str], fallback_slug: str = DEFAULT_READ_ONLY_ROLE_SLUG) -> str:
    roles = await get_global_standard_roles(db)
    role_by_lower = {role.name.lower(): role.name for role in roles}
    role_by_slug = {standard_role_slug(role.name): role.name for role in roles}
    fallback_name = role_by_slug.get(fallback_slug) or (roles[0].name if roles else fallback_slug)
    if not role_name:
        return fallback_name
    normalized = role_name.strip().lower()
    if normalized in role_by_lower:
        return role_by_lower[normalized]
    normalized_slug = standard_role_slug(role_name)
    if normalized_slug in role_by_slug:
        return role_by_slug[normalized_slug]
    return fallback_name

def onboarding_org_identifier_candidates(org: Optional[OrganizationModel]) -> List[str]:
    if not org:
        return []
    raw_values = [
        getattr(org, "id", None),
        getattr(org, "external_org_id", None),
        getattr(org, "auth0_org_id", None),
        getattr(org, "zitadel_org_id", None),
        getattr(org, "organization_code", None),
        getattr(org, "name", None),
    ]
    candidates = []
    seen = set()
    for value in raw_values:
        normalized = str(value).strip() if value is not None else ""
        if normalized and normalized not in seen:
            seen.add(normalized)
            candidates.append(normalized)
    return candidates

def infer_onboarding_role_from_flags(developer: dict) -> Optional[str]:
    if developer.get("gatewayAdmin"):
        return "gateway admin"
    if developer.get("apiProvider"):
        return "api provider"
    if developer.get("aiEngineer"):
        return "ai engineer"
    if developer.get("apiConsumer"):
        return "api consumer"
    return None

def get_mongodb_client():
    global _mongodb_client
    if _mongodb_client is not None:
        return _mongodb_client
    if not MONGODB_ROLE_LOOKUP_ENABLED or not MONGODB_URI:
        return None
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
    except Exception as exc:
        logger.warning("MongoDB role lookup disabled because motor is unavailable: %s", exc)
        return None
    _mongodb_client = AsyncIOMotorClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    return _mongodb_client

async def find_onboarding_developer_role(db: AsyncSession, email: str, org: Optional[OrganizationModel]) -> Optional[dict]:
    client = get_mongodb_client()
    if not client or not email:
        return None

    normalized_email = email.strip().lower()
    collection = client[MONGODB_DATABASE][MONGODB_DEVELOPERS_COLLECTION]
    email_filter = {"email": {"$in": list({email.strip(), normalized_email})}}
    org_candidates = onboarding_org_identifier_candidates(org)
    queries = []
    if org_candidates:
        queries.append({"$and": [email_filter, {"organizationId": {"$in": org_candidates}}]})
    if MONGODB_ROLE_LOOKUP_EMAIL_ONLY:
        queries.append(email_filter)

    for query in queries:
        try:
            developer = await collection.find_one(query, sort=[("updatedAt", -1), ("createdAt", -1)])
        except Exception as exc:
            logger.warning("MongoDB onboarding role lookup failed for %s: %s", normalized_email, exc)
            return None
        if developer:
            raw_role = developer.get("role") or infer_onboarding_role_from_flags(developer)
            if raw_role:
                standard_role = await map_to_standard_role_name(db, raw_role, DEFAULT_CONSUMER_ROLE_SLUG)
                return {
                    "source": "mongodb",
                    "developer_id": str(developer.get("_id") or developer.get("id") or ""),
                    "organization_id": developer.get("organizationId"),
                    "raw_role": raw_role,
                    "standard_role": standard_role,
                }
    return None

async def resolve_new_user_role(
    db: AsyncSession,
    org: Optional[OrganizationModel],
    email: str,
    requested_role: Optional[RoleModel] = None,
    fallback_role_slug: str = DEFAULT_CONSUMER_ROLE_SLUG,
) -> tuple[RoleModel, Optional[dict]]:
    lookup = await find_onboarding_developer_role(db, email, org)
    if lookup:
        role = await get_standard_role(db, org.id if org else "unknown", lookup["standard_role"])
        return role, lookup
    if requested_role:
        return requested_role, None
    role = await get_standard_role(db, org.id if org else "unknown", fallback_slug=fallback_role_slug)
    return role, None

async def get_user_organization(db: AsyncSession, user: Optional[UserModel]) -> Optional[OrganizationModel]:
    individual_org_id = await get_individual_users_org_id(db)
    if not user or not user.organization_id or user.organization_id == individual_org_id:
        return None
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == user.organization_id))
    return result.scalar_one_or_none()

async def sync_user_role_from_mongodb(
    db: AsyncSession,
    user: Optional[UserModel],
    org: Optional[OrganizationModel] = None,
) -> Optional[dict]:
    """Look up the onboarding MongoDB developer role without mutating local RBAC."""
    if not user or not user.email:
        return None

    org = org or await get_user_organization(db, user)
    lookup = await find_onboarding_developer_role(db, user.email, org)
    if not lookup:
        return None

    role = await get_standard_role(db, org.id if org else (user.organization_id or "unknown"), lookup["standard_role"])
    would_change = user.role_id != role.id

    return {
        **lookup,
        "role_id": role.id,
        "role_name": role.name,
        "changed": False,
        "would_change": would_change,
    }

async def ensure_standard_roles_for_organization(db: AsyncSession, organization_id: Optional[str] = None) -> List[RoleModel]:
    return await get_global_standard_roles(db)

async def get_standard_role(
    db: AsyncSession,
    organization_id: str,
    role_name: Optional[str] = None,
    fallback_slug: str = DEFAULT_CONSUMER_ROLE_SLUG,
) -> RoleModel:
    standard_name = await map_to_standard_role_name(db, role_name, fallback_slug)
    result = await db.execute(
        select(RoleModel).where(
            RoleModel.organization_id.is_(None),
            RoleModel.name == standard_name,
        )
    )
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=500, detail=f"Standard role '{standard_name}' is not configured")
    return role

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

async def public_plan_to_dict(db: AsyncSession, plan: PlanModel) -> dict:
    product = await get_plan_product(db, plan)
    plan_cost = float(plan.cost or plan.price_monthly or 0)
    price_label = plan.price_label or (f"${plan_cost:g}" if plan_cost else "$0")
    tools_result = await db.execute(
        select(PlanToolModel)
        .where(PlanToolModel.plan_id == plan.id, PlanToolModel.is_active == True)
        .order_by(PlanToolModel.display_order, PlanToolModel.name)
    )
    plan_tools = [model_to_dict(tool) for tool in tools_result.scalars().all()]
    return {
        "id": plan.id,
        "name": plan.name,
        "product_id": product.id if product else plan.product_id,
        "product_key": product.key if product else plan.tool,
        "product_name": product.name if product else None,
        "tool": product.key if product else plan.tool,
        "description": plan.description,
        "features": parse_json_list(plan.features),
        "price": price_label,
        "price_label": price_label,
        "period": plan.billing_period,
        "billing_period": plan.billing_period,
        "api_limit": getattr(plan, "api_limit", 0),
        "api_count": getattr(plan, "api_limit", 0),
        "cost": plan_cost,
        "price_monthly": float(plan.price_monthly or plan_cost),
        "price_yearly": float(plan.price_yearly or plan_cost),
        "base_price_monthly": plan_cost,
        "base_price_yearly": plan_cost,
        "popular": bool(plan.is_popular),
        "is_popular": bool(plan.is_popular),
        "is_contact_sales": price_label.lower() == "contact sales",
        "is_active": bool(plan.is_active),
        "plan_tools": plan_tools,
    }

def normalize_plan_selections(data: PlanUpgradeCreate) -> List[PlanSelectionItem]:
    if data.requested_plans:
        return data.requested_plans
    if data.requested_plan_id:
        return [PlanSelectionItem(plan_id=data.requested_plan_id, tool_ids=data.requested_tools or [])]
    return []

def payload_to_dict(value: Any) -> dict:
    if isinstance(value, BaseModel):
        return value.model_dump(exclude_none=True)
    if isinstance(value, dict):
        return value
    return {}

def normalize_tool_values(values: Any) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []

    tools = []
    for value in values:
        if isinstance(value, str):
            tool_value = value
        else:
            item = payload_to_dict(value)
            tool_value = item.get("id") or item.get("tool_id") or item.get("name") or item.get("tool_key") or item.get("key")
        if tool_value and tool_value not in tools:
            tools.append(tool_value)
    return tools

def normalize_organization_plan_selections(data: Any) -> List[PlanSelectionItem]:
    raw_plans = getattr(data, "plans", None) or getattr(data, "requested_plans", None) or []
    selections_by_plan = {}

    for raw_plan in raw_plans:
        if isinstance(raw_plan, str):
            plan_id = raw_plan
            plan_payload = {}
        else:
            plan_payload = payload_to_dict(raw_plan)
            plan_id = (
                plan_payload.get("plan_id")
                or plan_payload.get("id")
                or plan_payload.get("requested_plan_id")
            )
        if not plan_id:
            raise HTTPException(status_code=400, detail="Each selected plan must include an id or plan_id")

        tool_values = (
            normalize_tool_values(plan_payload.get("tool_ids"))
            or normalize_tool_values(plan_payload.get("selected_tools"))
            or normalize_tool_values(plan_payload.get("tools"))
            or normalize_tool_values(plan_payload.get("plan_tools"))
        )
        selections_by_plan.setdefault(plan_id, [])
        for tool in tool_values:
            if tool not in selections_by_plan[plan_id]:
                selections_by_plan[plan_id].append(tool)

    plan_ids = getattr(data, "plan_ids", None) or []
    if not selections_by_plan and plan_ids:
        for plan_id in plan_ids:
            selections_by_plan.setdefault(plan_id, [])

    return [
        PlanSelectionItem(plan_id=plan_id, tool_ids=tool_ids)
        for plan_id, tool_ids in selections_by_plan.items()
    ]

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
    tool_names = []
    for row in rows:
        if row.plan_tool_id:
            tool_result = await db.execute(select(PlanToolModel).where(PlanToolModel.id == row.plan_tool_id))
            plan_tool = tool_result.scalar_one_or_none()
            tool_names.append(plan_tool.name if plan_tool else row.plan_tool_id)
        elif row.tool_key:
            tool_names.append(row.tool_key)
    return tool_names

def valid_subscription_query():
    return (
        select(SubscriptionModel)
        .join(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .where(PlanModel.is_active == True, PlanModel.product_id.is_not(None))
    )

async def is_real_organization(db: AsyncSession, org: Optional[OrganizationModel]) -> bool:
    return bool(org and not await is_individual_users_org(db, org))

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
    if not await is_real_organization(db, org):
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

async def cancel_active_real_org_subscriptions_for_product(
    db: AsyncSession,
    organization_id: str,
    product_id: str,
    *,
    exclude_subscription_id: Optional[str] = None,
):
    org = await get_organization_by_id(db, organization_id)
    if not await is_real_organization(db, org):
        return 0

    result = await db.execute(
        select(SubscriptionModel.id)
        .join(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .where(SubscriptionModel.organization_id == organization_id)
        .where(SubscriptionModel.status == "active")
        .where(PlanModel.product_id == product_id)
    )
    subscription_ids = [sub_id for sub_id in result.scalars().all() if sub_id]
    if exclude_subscription_id:
        subscription_ids = [sub_id for sub_id in subscription_ids if sub_id != exclude_subscription_id]
    if not subscription_ids:
        return 0

    result = await db.execute(
        update(SubscriptionModel)
        .where(SubscriptionModel.id.in_(subscription_ids))
        .values(status="cancelled")
    )
    return result.rowcount or 0

async def ensure_can_activate_subscription(db: AsyncSession, subscription: SubscriptionModel):
    org = await get_organization_by_id(db, subscription.organization_id)
    if not await is_real_organization(db, org):
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

def get_plan_tier(plan: Optional[PlanModel]) -> str:
    if not plan:
        return "unknown"
    plan_text = f"{plan.id or ''} {plan.name or ''}".lower().replace("_", " ")
    if "starter" in plan_text:
        return "starter"
    if "enterprise - plus" in plan_text or "enterprise plus" in plan_text or "enterprise plus" in plan_text.replace("-", " "):
        return "enterprise_plus"
    if "enterprise" in plan_text:
        return "enterprise"
    return "unknown"

def plan_unit_price(plan: PlanModel, billing_cycle: str = "monthly") -> float:
    if billing_cycle == "yearly":
        return float(plan.price_yearly or plan.cost or plan.price_monthly or 0)
    return float(plan.price_monthly or plan.cost or 0)

def is_per_user_plan(plan: Optional[PlanModel]) -> bool:
    if not plan:
        return False
    billing_text = f"{plan.billing_period or ''} {plan.price_label or ''}".lower()
    return "user" in billing_text or "seat" in billing_text

async def get_billable_user_count(db: AsyncSession, organization_id: str) -> int:
    result = await db.execute(
        select(func.count())
        .select_from(UserModel)
        .where(UserModel.organization_id == organization_id)
        .where(UserModel.status == "active")
    )
    return int(result.scalar() or 0)

async def calculate_subscription_invoice_amount(
    db: AsyncSession,
    subscription: SubscriptionModel,
    plan: Optional[PlanModel] = None,
) -> float:
    if plan is None:
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == subscription.plan_id))
        plan = plan_result.scalar_one_or_none()

    tier = get_plan_tier(plan)
    if tier == "starter":
        return 0.0
    if tier == "enterprise_plus":
        return float(subscription.amount or 0)
    if tier == "enterprise" and plan:
        if is_per_user_plan(plan):
            user_count = 1 if await is_individual_users_org_id(db, subscription.organization_id) else await get_billable_user_count(db, subscription.organization_id)
            return float(user_count * plan_unit_price(plan, subscription.billing_cycle))
        return float(subscription.amount or plan_unit_price(plan, subscription.billing_cycle))
    return float(subscription.amount or 0)

def _invoice_safe_token(value: Optional[str]) -> str:
    token = "".join(ch if ch.isalnum() else "-" for ch in (value or "").upper()).strip("-")
    return "-".join(part for part in token.split("-") if part) or "PRODUCT"

def _product_sku_code(product: Optional[ProductModel], plan: Optional[PlanModel]) -> str:
    raw = product.key if product and product.key else product.name if product and product.name else plan.tool if plan else "product"
    text = (raw or "product").replace("_", "-").replace(" ", "-").lower()
    for prefix in ("probestack-", "pb-"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    parts = [part for part in text.split("-") if part]
    compact = "".join(parts)
    if compact.startswith("forge") and len(compact) > 5:
        return f"F{compact[5].upper()}"
    if parts:
        return "".join(part[0].upper() for part in parts[:3])[:3]
    return "PRD"

def _plan_display_name(plan: Optional[PlanModel]) -> str:
    if not plan:
        return "Subscription"
    tier = get_plan_tier(plan)
    if tier == "starter":
        return "Starter"
    if tier == "enterprise_plus":
        return "Enterprise Plus"
    if tier == "enterprise":
        return "Enterprise"
    return plan.name or "Subscription"

def _invoice_sku(product: Optional[ProductModel], plan: Optional[PlanModel]) -> str:
    return f"PB-{_product_sku_code(product, plan)}-001"

def _annual_unit_price(subscription: SubscriptionModel, plan: Optional[PlanModel]) -> float:
    if plan:
        price = plan_unit_price(plan, "yearly")
        if price:
            return float(price)
    amount = float(subscription.amount or 0)
    if subscription.billing_cycle == "monthly":
        return amount * 12
    return amount

async def build_invoice_line_items(db: AsyncSession, organization_id: str) -> list[dict]:
    subs_result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == organization_id)
        .where(SubscriptionModel.status == "active")
        .order_by(SubscriptionModel.created_at.asc())
    )
    subscriptions = subs_result.scalars().all()
    line_items: list[dict] = []

    for subscription in subscriptions:
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == subscription.plan_id))
        plan = plan_result.scalar_one_or_none()
        product = await get_plan_product(db, plan) if plan else None
        per_user = is_per_user_plan(plan)
        qty = await get_billable_user_count(db, organization_id) if per_user else 1
        if qty < 1:
            qty = 1
        unit_price = _annual_unit_price(subscription, plan)
        description_parts = []
        if product and product.name:
            description_parts.append(product.name)
        if plan and plan.description:
            description_parts.append(plan.description)
        elif plan and plan.name:
            description_parts.append(plan.name)
        description = " - ".join(description_parts) or "Annual subscription"
        amount = float(qty * unit_price)
        line_items.append({
            "subscription_id": subscription.id,
            "sku": _invoice_sku(product, plan),
            "product_plan": _plan_display_name(plan),
            "description": description,
            "payment": "Annually",
            "qty": qty,
            "unit_price": unit_price,
            "tax_rate": 0,
            "amount": amount,
            "product_name": product.name if product else None,
            "product_key": product.key if product else (plan.tool if plan else None),
        })

    return line_items

async def calculate_organization_annual_invoice_amount(db: AsyncSession, organization_id: str) -> float:
    return float(sum(item["amount"] for item in await build_invoice_line_items(db, organization_id)))

def add_months(value: datetime, months: int) -> datetime:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)

def get_subscription_billing_period(subscription: SubscriptionModel, now: datetime) -> tuple[Optional[datetime], Optional[datetime]]:
    start = subscription.start_date
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if start > now:
        return None, None

    months_per_period = 12 if subscription.billing_cycle == "yearly" else 1
    months_elapsed = (now.year - start.year) * 12 + (now.month - start.month)
    period_index = max(0, months_elapsed // months_per_period)
    cycle_start = add_months(start, period_index * months_per_period)
    if cycle_start > now and period_index > 0:
        period_index -= 1
        cycle_start = add_months(start, period_index * months_per_period)
    cycle_end = add_months(cycle_start, months_per_period)

    end = subscription.end_date
    if end and end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    if end and cycle_start >= end:
        return None, None
    return cycle_start, cycle_end

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
    selections = [
        PlanSelectionItem(plan_id=sub.plan_id, tool_ids=await get_subscription_tools(db, sub))
        for sub in active_subs
    ]
    if selections:
        await create_organization_subscription_request_from_selections(
            db,
            organization_id,
            selections,
            status=org.status,
        )
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

async def prepare_product_upgrade_selections(
    db: AsyncSession,
    organization_id: str,
    selections: List[PlanSelectionItem],
) -> List[dict]:
    if not selections:
        raise HTTPException(status_code=400, detail="At least one plan must be selected")

    selected_plan_ids = set()
    selections_by_product = {}
    prepared = []

    for selection in selections:
        if selection.plan_id in selected_plan_ids:
            raise HTTPException(status_code=400, detail=f"Duplicate plan selected: {selection.plan_id}")
        selected_plan_ids.add(selection.plan_id)

        plan_result = await db.execute(
            select(PlanModel).where(PlanModel.id == selection.plan_id, PlanModel.is_active == True)
        )
        plan = plan_result.scalar_one_or_none()
        if not plan:
            raise HTTPException(status_code=404, detail=f"Plan {selection.plan_id} not found")

        product = await get_plan_product(db, plan)
        if not product:
            raise HTTPException(status_code=400, detail=f"Plan {plan.id} is not linked to a product")
        if product.id in selections_by_product:
            raise HTTPException(
                status_code=400,
                detail=f"Only one plan can be requested per product. Duplicate product: {product.name}",
            )
        selections_by_product[product.id] = selection

        await calculate_plan_total(db, plan, selection.tool_ids, "monthly")
        prepared.append({
            "selection": selection,
            "plan": plan,
            "product": product,
            "tools": selection.tool_ids or [],
        })

    product_ids = list(selections_by_product.keys())
    pending_result = await db.execute(
        select(PlanModel.product_id)
        .select_from(PlanUpgradeRequestModel)
        .join(PlanUpgradeRequestItemModel, PlanUpgradeRequestItemModel.request_id == PlanUpgradeRequestModel.id)
        .join(PlanModel, PlanUpgradeRequestItemModel.plan_id == PlanModel.id)
        .where(PlanUpgradeRequestModel.organization_id == organization_id)
        .where(PlanUpgradeRequestModel.status == "pending")
        .where(PlanModel.product_id.in_(product_ids))
        .distinct()
    )
    pending_product_ids = {product_id for product_id in pending_result.scalars().all() if product_id}
    if pending_product_ids:
        pending_product_names = [
            item["product"].name
            for item in prepared
            if item["product"].id in pending_product_ids
        ]
        raise HTTPException(
            status_code=409,
            detail=f"Pending upgrade request already exists for product(s): {', '.join(pending_product_names)}",
        )

    current_result = await db.execute(
        select(SubscriptionModel, PlanModel)
        .join(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .where(SubscriptionModel.organization_id == organization_id)
        .where(SubscriptionModel.status == "active")
        .where(PlanModel.product_id.in_(product_ids))
    )
    current_plan_ids_by_product = {}
    current_plan_names_by_product = {}
    for subscription, plan in current_result.all():
        current_plan_ids_by_product.setdefault(plan.product_id, []).append(subscription.plan_id)
        current_plan_names_by_product.setdefault(plan.product_id, []).append(plan.name)

    for item in prepared:
        product_id = item["product"].id
        item["current_plan_ids"] = current_plan_ids_by_product.get(product_id, [])
        item["current_plan_names"] = current_plan_names_by_product.get(product_id, [])
        if item["plan"].id in item["current_plan_ids"]:
            raise HTTPException(
                status_code=409,
                detail=f"{item['product'].name} is already subscribed to the {item['plan'].name} plan",
            )

    return prepared

async def create_product_upgrade_requests(
    db: AsyncSession,
    *,
    org: OrganizationModel,
    organization_id: str,
    selections: List[PlanSelectionItem],
    reason: Optional[str],
    requested_by: str,
) -> tuple[List[PlanUpgradeRequestModel], List[dict]]:
    prepared = await prepare_product_upgrade_selections(db, organization_id, selections)
    current_plan_ids = []
    for item in prepared:
        current_plan_ids.extend(item["current_plan_ids"])
    upgrade_request = PlanUpgradeRequestModel(
        organization_id=organization_id,
        current_plan_id=json.dumps(current_plan_ids) if current_plan_ids else "",
        reason=reason,
        requested_by=requested_by,
    )
    db.add(upgrade_request)
    await db.flush()
    await set_upgrade_request_items(db, upgrade_request.id, [item["selection"] for item in prepared])

    requested_labels = [
        f"{item['product'].name} - {item['plan'].name}"
        for item in prepared
    ]
    db.add(NotificationModel(
        title="Plan Upgrade Request",
        message=f"{org.name} requested: {', '.join(requested_labels)}",
        type="info",
        link="/plan-upgrade-requests",
    ))

    return [upgrade_request], prepared

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

async def create_organization_subscription_request_from_selections(
    db: AsyncSession,
    organization_id: str,
    selections: List[PlanSelectionItem],
    *,
    status: str = "pending"
) -> OrganizationSubscriptionRequestModel:
    request = OrganizationSubscriptionRequestModel(
        organization_id=organization_id,
        status=status
    )
    db.add(request)
    await db.flush()

    for selection in selections:
        item = OrganizationSubscriptionRequestItemModel(request_id=request.id, plan_id=selection.plan_id)
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
            db.add(OrganizationSubscriptionRequestToolModel(
                request_item_id=item.id,
                plan_tool_id=plan_tool.id,
                tool_key=None
            ))
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

    return []

async def format_selected_product_plan_lines(db: AsyncSession, plan_ids: List[str], plans: dict) -> str:
    lines = []
    for plan_id in plan_ids:
        plan = plans.get(plan_id)
        product = await get_plan_product(db, plan) if plan else None
        product_label = (
            product.name
            if product and product.name
            else product.key
            if product and product.key
            else getattr(plan, "tool", None)
            or getattr(plan, "product_id", None)
            or "Product"
        )
        plan_label = getattr(plan, "name", None) or plan_id
        lines.append(f"{product_label}:{plan_label}")
    return "\n".join(lines)

async def admin_to_dict(db: AsyncSession, admin: AdminModel) -> dict:
    data = model_to_dict(admin)
    data["organization_name"] = await get_organization_name(db, admin.organization_id)
    return data

async def user_to_dict(db: AsyncSession, user: UserModel) -> dict:
    mongodb_role_lookup = await sync_user_role_from_mongodb(db, user)
    roles = await get_user_assigned_roles(db, user)
    data = model_to_dict(user)
    data["organization_name"] = await get_organization_name(db, user.organization_id)
    data["roles"] = roles_to_dict_list(roles)
    data["role_ids"] = [role.id for role in roles]
    data["role_names"] = [role.name for role in roles]
    data["role_name"] = data["role_names"][0] if data["role_names"] else await get_role_name(db, user.role_id)
    data["role_id"] = data["role_ids"][0] if data["role_ids"] else user.role_id
    if mongodb_role_lookup:
        data["mongodb_role_lookup"] = mongodb_role_lookup
    return data

async def user_access_summary_to_dict(
    db: AsyncSession,
    user: UserModel,
    role: Optional[RoleModel] = None,
    business_units: Optional[List[dict]] = None,
) -> dict:
    """Return the compact organization/BU/team role summary for one user."""
    mongodb_role_lookup = await sync_user_role_from_mongodb(db, user)
    if mongodb_role_lookup:
        role = None
    return {
        "user_name": user.name,
        "user_email": user.email,
        "org_role": role.name if role else await get_role_name(db, user.role_id),
        "business_units": business_units or [],
        "mongodb_role_lookup": mongodb_role_lookup,
    }

async def public_user_detail_to_dict(
    db: AsyncSession,
    user: UserModel,
    role: Optional[RoleModel] = None,
    business_units: Optional[List[dict]] = None,
) -> dict:
    """Public product-integration user shape without one-time login tokens."""
    role_name = role.name if role else await get_role_name(db, user.role_id)
    role_permissions = parse_json_list(role.permissions) if role and role.permissions else []
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "organization_id": user.organization_id,
        "organization_name": await get_organization_name(db, user.organization_id),
        "role_id": user.role_id,
        "role_name": role_name,
        "org_role": role_name,
        "role": normalize_token_value(role_name, "user"),
        "role_permissions": role_permissions,
        "status": user.status,
        "email_verified": bool(user.email_verified),
        "password_set": bool(user.password_set),
        "auth0_user_id": user.auth0_user_id,
        "zitadel_user_id": user.zitadel_user_id,
        "assigned_project_ids": parse_json_list(getattr(user, "assigned_project_ids", None)),
        "assigned_apm_numbers": parse_json_list(getattr(user, "assigned_apm_numbers", None)),
        "theme_preference": getattr(user, "theme_preference", "system"),
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "business_units": business_units or [],
    }

async def get_public_organization_users(db: AsyncSession, organization_id: str) -> List[dict]:
    user_result = await db.execute(
        select(UserModel, RoleModel)
        .outerjoin(RoleModel, UserModel.role_id == RoleModel.id)
        .where(UserModel.organization_id == organization_id)
        .order_by(UserModel.created_at.desc())
    )
    user_rows = user_result.all()
    users_by_id = {}
    users_by_email = {}
    user_ids = []
    user_emails = []
    for user, role in user_rows:
        entry = {
            "user": user,
            "role": role,
            "business_units_by_id": {},
        }
        users_by_id[user.id] = entry
        users_by_email[user.email.lower()] = entry
        user_ids.append(user.id)
        user_emails.append(user.email)

    if user_rows:
        member_result = await db.execute(
            select(ProjectTeamMemberModel, ProjectModel, BusinessUnitModel)
            .join(ProjectModel, ProjectTeamMemberModel.project_id == ProjectModel.id)
            .outerjoin(BusinessUnitModel, ProjectModel.business_unit_id == BusinessUnitModel.id)
            .where(
                ProjectTeamMemberModel.organization_id == organization_id,
                ProjectModel.organization_id == organization_id,
                (
                    ProjectTeamMemberModel.user_id.in_(user_ids)
                    | ProjectTeamMemberModel.email.in_(user_emails)
                ),
            )
            .order_by(BusinessUnitModel.name.asc(), ProjectModel.name.asc())
        )
        for member, project, business_unit in member_result.all():
            entry = users_by_id.get(member.user_id) or users_by_email.get((member.email or "").lower())
            if not entry or not business_unit:
                continue
            bu_entry = entry["business_units_by_id"].setdefault(
                business_unit.id,
                {
                    "bu_name": business_unit.name,
                    "bu_role": "member",
                    "projects": [],
                },
            )
            if not any(item["project_name"] == project.name for item in bu_entry["projects"]):
                bu_entry["projects"].append({
                    "project_name": project.name,
                    "project_role": member.project_role,
                })

    return [
        await public_user_detail_to_dict(
            db,
            entry["user"],
            entry["role"],
            list(entry["business_units_by_id"].values()),
        )
        for entry in users_by_id.values()
    ]

async def subscription_to_dict(db: AsyncSession, subscription: SubscriptionModel) -> dict:
    data = model_to_dict(subscription)
    data["organization_name"] = await get_organization_name(db, subscription.organization_id)
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == subscription.plan_id))
    plan = plan_result.scalar_one_or_none()
    product = await get_plan_product(db, plan) if plan else None
    data["plan_name"] = plan.name if plan else await get_plan_name(db, subscription.plan_id)
    data["plan_tier"] = get_plan_tier(plan)
    data["billable_users"] = 1 if await is_individual_users_org_id(db, subscription.organization_id) else await get_billable_user_count(db, subscription.organization_id)
    data["is_per_user"] = is_per_user_plan(plan)
    data["billing_unit_price"] = plan_unit_price(plan, subscription.billing_cycle) if plan else float(subscription.amount or 0)
    data["billing_amount"] = await calculate_subscription_invoice_amount(db, subscription, plan)
    if product:
        data["product_id"] = product.id
        data["product_key"] = product.key
        data["product_name"] = product.name
    else:
        data["product_id"] = None
        data["product_key"] = None
        data["product_name"] = None
    quota_limit = get_subscription_quota_limit(subscription, plan)
    used_quota = get_subscription_used_quota(subscription)
    data["quota"] = quota_limit
    data["used_quota"] = used_quota
    data["remaining_quota"] = None if quota_limit is None else max(quota_limit - used_quota, 0)
    data["api_count"] = quota_limit
    data["tools"] = await get_subscription_tools(db, subscription)
    return data

def get_subscription_quota_limit(subscription: SubscriptionModel, plan: Optional[PlanModel] = None) -> Optional[int]:
    explicit_quota = getattr(subscription, "quota", None)
    if explicit_quota is not None:
        return int(explicit_quota)
    legacy_api_count = getattr(subscription, "api_count", None)
    if legacy_api_count is not None:
        return int(legacy_api_count)
    if plan:
        return int(getattr(plan, "api_limit", 0) or 0)
    return None

def get_subscription_used_quota(subscription: SubscriptionModel) -> int:
    return max(int(getattr(subscription, "used_quota", 0) or 0), 0)

def apply_subscription_quota_update(
    subscription: SubscriptionModel,
    *,
    quota: Optional[int] = None,
    used_quota: Optional[int] = None,
) -> None:
    if quota is not None and quota < 0:
        raise HTTPException(status_code=400, detail="quota cannot be negative")
    if used_quota is not None and used_quota < 0:
        raise HTTPException(status_code=400, detail="used_quota cannot be negative")
    if quota is not None:
        subscription.quota = quota
        subscription.api_count = quota
    if used_quota is not None:
        subscription.used_quota = used_quota

def apply_subscription_usage_update(subscription: SubscriptionModel, data: SubscriptionQuotaUpdate) -> None:
    quota_limit = get_subscription_quota_limit(subscription)
    provided = [data.used_quota is not None, data.usage_delta is not None, data.remaining_quota is not None]
    if sum(provided) != 1:
        raise HTTPException(status_code=400, detail="Pass exactly one of used_quota, usage_delta, or remaining_quota")
    if data.used_quota is not None:
        new_used_quota = data.used_quota
    elif data.usage_delta is not None:
        new_used_quota = get_subscription_used_quota(subscription) + data.usage_delta
    else:
        if quota_limit is None:
            raise HTTPException(status_code=400, detail="Cannot set remaining_quota when quota is not configured")
        new_used_quota = quota_limit - data.remaining_quota
    if new_used_quota < 0:
        raise HTTPException(status_code=400, detail="used_quota cannot be negative")
    if quota_limit is not None and new_used_quota > quota_limit:
        raise HTTPException(status_code=400, detail=f"used_quota cannot exceed quota ({quota_limit})")
    subscription.used_quota = new_used_quota

async def get_organization_api_capacity(db: AsyncSession, organization_id: str) -> Optional[int]:
    result = await db.execute(
        select(SubscriptionModel, PlanModel)
        .outerjoin(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .where(
            SubscriptionModel.organization_id == organization_id,
            SubscriptionModel.status == "active",
        )
    )
    quota_limits = [
        quota
        for subscription, plan in result.all()
        for quota in [get_subscription_quota_limit(subscription, plan)]
        if quota is not None
    ]
    return sum(quota_limits) if quota_limits else None

async def get_organization_api_usage(
    db: AsyncSession,
    organization_id: str,
    *,
    exclude_application_id: Optional[str] = None,
) -> int:
    query = select(func.coalesce(func.sum(ApplicationModel.api_count), 0)).where(
        ApplicationModel.organization_id == organization_id
    )
    if exclude_application_id:
        query = query.where(ApplicationModel.id != exclude_application_id)
    return int(await db.scalar(query) or 0)

async def get_organization_api_count_summary(db: AsyncSession, organization: OrganizationModel) -> dict:
    result = await db.execute(
        select(SubscriptionModel, PlanModel, ProductModel)
        .outerjoin(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .outerjoin(ProductModel, PlanModel.product_id == ProductModel.id)
        .where(
            SubscriptionModel.organization_id == organization.id,
            SubscriptionModel.status == "active",
        )
        .order_by(ProductModel.display_order, ProductModel.name, PlanModel.created_at.desc())
    )
    subscriptions = []
    total_assigned_quota = 0
    total_effective_quota = 0
    total_used_quota = 0

    for subscription, plan, product in result.all():
        assigned_quota = getattr(subscription, "quota", None)
        legacy_api_count = getattr(subscription, "api_count", None)
        plan_quota = int(getattr(plan, "api_limit", 0) or 0) if plan else 0
        effective_quota = get_subscription_quota_limit(subscription, plan)
        used_quota = get_subscription_used_quota(subscription)
        remaining_quota = None if effective_quota is None else max(effective_quota - used_quota, 0)
        if assigned_quota is not None:
            total_assigned_quota += int(assigned_quota)
        total_effective_quota += int(effective_quota or 0)
        total_used_quota += used_quota
        subscriptions.append({
            "subscription_id": subscription.id,
            "plan_id": subscription.plan_id,
            "plan_name": plan.name if plan else await get_plan_name(db, subscription.plan_id),
            "product_id": product.id if product else None,
            "product_key": product.key if product else None,
            "product_name": product.name if product else None,
            "status": subscription.status,
            "quota": effective_quota,
            "assigned_quota": assigned_quota,
            "plan_quota": plan_quota,
            "used_quota": used_quota,
            "remaining_quota": remaining_quota,
            "assigned_api_count": assigned_quota if assigned_quota is not None else legacy_api_count,
            "plan_api_limit": plan_quota,
            "effective_api_count": effective_quota,
            "start_date": subscription.start_date.isoformat() if subscription.start_date else None,
            "end_date": subscription.end_date.isoformat() if subscription.end_date else None,
        })

    enforced_capacity = await get_organization_api_capacity(db, organization.id)
    remaining_quota = None if enforced_capacity is None else max(enforced_capacity - total_used_quota, 0)

    return {
        "organization_id": organization.id,
        "organization_name": organization.name,
        "quota": total_assigned_quota,
        "total_assigned_quota": total_assigned_quota,
        "total_effective_quota": total_effective_quota,
        "used_quota": total_used_quota,
        "remaining_quota": remaining_quota,
        "api_count": total_assigned_quota,
        "total_assigned_api_count": total_assigned_quota,
        "total_effective_api_count": total_effective_quota,
        "used_api_count": total_used_quota,
        "remaining_api_count": remaining_quota,
        "capacity_enforced": enforced_capacity is not None,
        "subscriptions": subscriptions,
    }

async def get_active_subscription_for_product_identifier(
    db: AsyncSession,
    organization_id: str,
    product_identifier: str,
) -> tuple[SubscriptionModel, Optional[PlanModel], Optional[ProductModel]]:
    identifier = (product_identifier or "").strip()
    identifier_lower = identifier.lower()
    result = await db.execute(
        select(SubscriptionModel, PlanModel, ProductModel)
        .outerjoin(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .outerjoin(ProductModel, PlanModel.product_id == ProductModel.id)
        .where(
            SubscriptionModel.organization_id == organization_id,
            SubscriptionModel.status == "active",
            or_(
                ProductModel.id == identifier,
                func.lower(ProductModel.key) == identifier_lower,
                func.lower(ProductModel.name) == identifier_lower,
                SubscriptionModel.plan_id == identifier,
            ),
        )
        .order_by(SubscriptionModel.created_at.desc())
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Active product subscription quota not found")
    return row

def enforce_subscription_quota_bounds(subscription: SubscriptionModel, plan: Optional[PlanModel] = None) -> None:
    quota_limit = get_subscription_quota_limit(subscription, plan)
    used_quota = get_subscription_used_quota(subscription)
    if quota_limit is not None and used_quota > quota_limit:
        raise HTTPException(status_code=400, detail=f"used_quota cannot exceed quota ({quota_limit})")

async def update_organization_subscription_quotas(
    db: AsyncSession,
    organization_id: str,
    data: OrganizationQuotaUpdate,
) -> List[str]:
    if data.quota is not None and data.quota < 0:
        raise HTTPException(status_code=400, detail="quota cannot be negative")
    if data.used_quota is not None and data.used_quota < 0:
        raise HTTPException(status_code=400, detail="used_quota cannot be negative")

    if data.subscriptions:
        seen_subscription_ids = set()
        updated_subscription_ids = []
        for item in data.subscriptions:
            if item.subscription_id in seen_subscription_ids:
                raise HTTPException(status_code=400, detail=f"Duplicate subscription_id: {item.subscription_id}")
            seen_subscription_ids.add(item.subscription_id)
            result = await db.execute(
                select(SubscriptionModel, PlanModel)
                .outerjoin(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
                .where(
                    SubscriptionModel.id == item.subscription_id,
                    SubscriptionModel.organization_id == organization_id,
                    SubscriptionModel.status == "active",
                )
            )
            row = result.first()
            if not row:
                raise HTTPException(status_code=404, detail=f"Active subscription not found: {item.subscription_id}")
            subscription, plan = row
            apply_subscription_quota_update(subscription, quota=item.quota, used_quota=item.used_quota)
            enforce_subscription_quota_bounds(subscription, plan)
            updated_subscription_ids.append(subscription.id)
        return updated_subscription_ids

    query = (
        select(SubscriptionModel, PlanModel)
        .outerjoin(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .where(
            SubscriptionModel.organization_id == organization_id,
            SubscriptionModel.status == "active",
        )
    )
    if data.subscription_id:
        query = query.where(SubscriptionModel.id == data.subscription_id)

    result = await db.execute(query.order_by(SubscriptionModel.created_at.desc()))
    rows = list(result.all())
    if not rows:
        raise HTTPException(status_code=404, detail="Active subscription not found")
    if not data.subscription_id and len(rows) > 1:
        raise HTTPException(
            status_code=400,
            detail="Multiple active subscriptions found. Pass subscription_id or subscriptions to update specific subscriptions.",
        )

    subscription, plan = rows[0]
    apply_subscription_quota_update(subscription, quota=data.quota, used_quota=data.used_quota)
    enforce_subscription_quota_bounds(subscription, plan)
    return [subscription.id]

async def ensure_organization_api_capacity(
    db: AsyncSession,
    organization_id: str,
    requested_api_count: int,
    *,
    exclude_application_id: Optional[str] = None,
):
    capacity = await get_organization_api_capacity(db, organization_id)
    if capacity is None:
        return
    used = await get_organization_api_usage(
        db,
        organization_id,
        exclude_application_id=exclude_application_id,
    )
    requested_total = used + max(requested_api_count or 0, 0)
    if requested_total > capacity:
        raise HTTPException(
            status_code=400,
            detail=f"API count limit exceeded. Subscribed capacity is {capacity}, current usage is {used}, requested total is {requested_total}.",
        )

async def get_active_subscriptions_for_identity(
    db: AsyncSession,
    *,
    email: str,
    organization_id: Optional[str],
) -> List[SubscriptionModel]:
    if organization_id and not await is_individual_users_org_id(db, organization_id):
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
        "project_name": project.name,
        "project_role": role,
    }
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

    if not organization_id or await is_individual_users_org_id(db, organization_id) or is_super_admin:
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
            bu_data = {
                "bu_name": business_unit.name,
                "bu_role": "admin",
                "projects": [],
            }
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
        )
        .order_by(BusinessUnitModel.name.asc(), ProjectModel.name.asc())
    )

    for member, project, business_unit in member_result.all():
        project_data = context_project_payload(project, member.project_role, member)
        project_memberships.append(project_data)

        if business_unit:
            if business_unit.id not in business_units_by_id:
                bu_data = {
                    "bu_name": business_unit.name,
                    "bu_role": "member",
                    "projects": [],
                }
                business_units_by_id[business_unit.id] = bu_data
            business_units_by_id[business_unit.id]["projects"].append(project_data)
        else:
            projects_without_business_unit.append(project_data)

    return {
        "business_units": list(business_units_by_id.values()),
        "projects": project_memberships,
        "projects_without_business_unit": projects_without_business_unit,
    }

async def build_user_context(
    db: AsyncSession,
    email: Optional[str],
    auth0_user_id: Optional[str] = None,
    zitadel_user_id: Optional[str] = None,
) -> dict:
    normalized_email = email.lower().strip() if email else None
    user = None
    admin = None

    if auth0_user_id:
        result = await db.execute(select(UserModel).where(UserModel.auth0_user_id == auth0_user_id))
        user = result.scalar_one_or_none()

    if not user and zitadel_user_id:
        result = await db.execute(select(UserModel).where(UserModel.zitadel_user_id == zitadel_user_id))
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
    is_individual_identity = await is_individual_users_org_id(db, organization_id)
    if organization_id and not is_individual_identity:
        org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == organization_id))
        organization = org_result.scalar_one_or_none()

    mongodb_role_lookup = await sync_user_role_from_mongodb(db, user, organization) if user else None

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
        if zitadel_user_id and not user.zitadel_user_id:
            user.zitadel_user_id = zitadel_user_id
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
            "zitadel_user_id": user.zitadel_user_id if user else zitadel_user_id,
            "created_at": (user.created_at if user else admin.created_at).isoformat() if (user or admin) else None,
        },
        "organization": {
            "id": organization.id if organization else organization_id,
            "name": organization.name if organization else await get_organization_name(db, organization_id, None),
            "external_org_id": organization.external_org_id if organization else None,
            "auth0_org_id": organization.auth0_org_id if organization else None,
            "zitadel_org_id": organization.zitadel_org_id if organization else None,
            "status": organization.status if organization else None,
            "supported_domains": parse_json_list(organization.supported_domains) if organization and organization.supported_domains else [],
        } if organization_id else None,
        "org_role": {
            "id": role.id if role else None,
            "name": role.name if role else (admin.role if admin else None),
            "permissions": role_permissions,
        },
        "org_role_name": role.name if role else (admin.role if admin else None),
        "admin": {
            "id": admin.id,
            "role": admin.role,
            "is_active": admin.is_active,
            "permissions": admin_permissions,
        } if admin else None,
        "is_admin": bool(admin),
        "is_org_admin": is_org_admin,
        "is_super_admin": is_super_admin,
        "account_type": "individual" if is_individual_identity else "enterprise",
        "permissions": permissions,
        "mongodb_role_lookup": mongodb_role_lookup,
        "business_units": business_unit_context["business_units"],
        "projects": business_unit_context["projects"],
        "projects_without_business_unit": business_unit_context["projects_without_business_unit"],
        "subscriptions": subscription_context["subscriptions"],
        "plans": subscription_context["plans"],
        "tools": subscription_context["tools"],
    }

def normalize_scoped_role(role: Optional[str], scope: str, is_admin_scope: bool = False) -> str:
    role_key = normalize_token_value(role, "member")
    if is_admin_scope or role_key in {"admin", f"{scope}_admin"}:
        return f"{scope}_admin"
    return role_key

def build_role_assignments_claim(user_context: dict) -> dict:
    organization = user_context.get("organization") or {}
    org_role = user_context.get("org_role") or {}
    admin = user_context.get("admin") or {}
    is_org_admin = bool(user_context.get("is_org_admin"))

    organization_role = admin.get("role") or org_role.get("name")
    if is_org_admin:
        organization_role = "org_admin"

    role_assignments = {
        "organization": {
            "name": organization.get("name"),
            "key": organization.get("external_org_id") or organization.get("auth0_org_id") or organization.get("zitadel_org_id") or organization.get("id"),
            "role": normalize_scoped_role(organization_role, "org", is_org_admin),
        },
        "business_units": [],
    }

    for business_unit in user_context.get("business_units") or []:
        bu_role = business_unit.get("bu_role") or business_unit.get("business_unit_role") or business_unit.get("role")
        bu_is_admin = is_org_admin or bu_role == "admin"
        bu_claim = {
            "name": business_unit.get("bu_name") or business_unit.get("name"),
            "role": normalize_scoped_role(
                bu_role,
                "bu",
                bu_is_admin,
            ),
            "projects": [],
        }
        for project in business_unit.get("projects") or []:
            project_role = project.get("project_role") or project.get("role")
            project_is_admin = is_org_admin or project_role == "admin"
            bu_claim["projects"].append({
                "name": project.get("project_name") or project.get("name"),
                "role": normalize_scoped_role(
                    project_role,
                    "project",
                    project_is_admin,
                ),
            })
        role_assignments["business_units"].append(bu_claim)

    for project in user_context.get("projects_without_business_unit") or []:
        project_is_admin = is_org_admin or project.get("role") == "admin" or project.get("project_role") == "admin"
        role_assignments["business_units"].append({
            "name": None,
            "role": "member",
            "projects": [{
                "name": project.get("project_name") or project.get("name"),
                "role": normalize_scoped_role(
                    project.get("project_role") or project.get("role"),
                    "project",
                    project_is_admin,
                ),
            }],
        })

    return role_assignments

def build_entitlements_claim(user_context: dict) -> dict:
    products = []
    seen_products = set()

    for plan in user_context.get("plans") or []:
        product_key = plan.get("product_key") or plan.get("tool") or plan.get("product_id")
        if not product_key:
            continue
        entitlement_key = str(product_key)
        if entitlement_key in seen_products:
            continue
        seen_products.add(entitlement_key)
        products.append({
            "key": entitlement_key,
            "plan": normalize_token_value(plan.get("name"), "unknown"),
        })

    return {"products": products}

def normalize_pem_env_value(value: str) -> bytes:
    cleaned = (value or "").strip()
    if not cleaned:
        return b""
    cleaned = cleaned.replace("\\n", "\n")
    if "-----BEGIN" in cleaned:
        return cleaned.encode()
    try:
        return base64.b64decode(cleaned)
    except Exception:
        return cleaned.encode()

def get_context_token_private_key():
    global _context_token_private_key
    if _context_token_private_key:
        return _context_token_private_key

    pem = normalize_pem_env_value(PROBESTACK_CONTEXT_TOKEN_PRIVATE_KEY)
    if pem:
        password = (
            PROBESTACK_CONTEXT_TOKEN_PRIVATE_KEY_PASSPHRASE.encode()
            if PROBESTACK_CONTEXT_TOKEN_PRIVATE_KEY_PASSPHRASE
            else None
        )
        _context_token_private_key = serialization.load_pem_private_key(pem, password=password)
    else:
        logger.warning(
            "PROBESTACK_CONTEXT_TOKEN_PRIVATE_KEY is not configured; using an ephemeral RS256 key for context tokens"
        )
        _context_token_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _context_token_private_key

def get_context_token_public_key():
    return get_context_token_private_key().public_key()

def base64url_uint(value: int) -> str:
    byte_length = max(1, (value.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(value.to_bytes(byte_length, "big")).rstrip(b"=").decode()

def build_context_token_jwks() -> dict:
    public_numbers = get_context_token_public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": PROBESTACK_CONTEXT_TOKEN_ALGORITHM,
                "kid": PROBESTACK_CONTEXT_TOKEN_KID,
                "n": base64url_uint(public_numbers.n),
                "e": base64url_uint(public_numbers.e),
            }
        ]
    }

def build_user_context_token_claims(user_context: dict, issued_at: int, expires_at: int) -> dict:
    user = user_context["user"]
    organization = user_context.get("organization") or {}
    admin = user_context.get("admin") or {}
    org_role = user_context.get("org_role") or {}

    if user_context.get("is_super_admin"):
        token_role = "super_admin"
    elif user_context.get("is_org_admin"):
        token_role = "org_admin"
    else:
        token_role = normalize_token_value(org_role.get("name"), "user")

    return {
        "iss": PROBESTACK_TOKEN_ISSUER,
        "aud": PROBESTACK_TOKEN_AUDIENCE,
        "sub": user["id"],
        "email": user["email"],
        "name": user.get("name") or user["email"],
        "type": "user",
        "role": token_role,
        "organization_id": organization.get("id"),
        "organization_name": organization.get("name"),
        "userId": user["id"],
        "userEmail": user["email"],
        "userRole": org_role.get("name") or token_role,
        "userOrgId": organization.get("id"),
        "userOrgName": organization.get("name"),
        "tokenType": user_context.get("account_type", "enterprise"),
        "admin_id": admin.get("id"),
        "is_admin": bool(user_context.get("is_admin")),
        "is_org_admin": bool(user_context.get("is_org_admin")),
        "is_super_admin": bool(user_context.get("is_super_admin")),
        "role_assignments": build_role_assignments_claim(user_context),
        "entitlements": build_entitlements_claim(user_context),
        "token_type": "probestack_user_context",
        "jti": str(uuid.uuid4()),
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
    }

def create_user_context_token(user_context: dict) -> tuple[str, int]:
    expires_at = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
    issued_at = int(datetime.now(timezone.utc).timestamp())
    payload = build_user_context_token_claims(user_context, issued_at, expires_at)
    headers = {"kid": PROBESTACK_CONTEXT_TOKEN_KID, "typ": "JWT"}
    return jwt.encode(
        payload,
        get_context_token_private_key(),
        algorithm=PROBESTACK_CONTEXT_TOKEN_ALGORITHM,
        headers=headers,
    ), expires_at

async def billing_to_dict(db: AsyncSession, billing: BillingModel) -> dict:
    data = model_to_dict(billing)
    data["organization_name"] = await get_organization_name(db, billing.organization_id)
    return data

def _xlsx_col(index: int) -> str:
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name

def _xlsx_cell(ref: str, value: Any = "", style: int = 0, formula: Optional[str] = None) -> str:
    style_attr = f' s="{style}"' if style else ""
    if formula:
        cached = value if isinstance(value, (int, float)) else 0
        return f'<c r="{ref}"{style_attr}><f>{xml_escape(formula)}</f><v>{cached}</v></c>'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}"{style_attr}><v>{value}</v></c>'
    text = xml_escape("" if value is None else str(value))
    return f'<c r="{ref}"{style_attr} t="inlineStr"><is><t>{text}</t></is></c>'

def _xlsx_row(row_number: int, values: list[Any], style: int = 0, start_col: int = 1, height: Optional[int] = None) -> str:
    height_attr = f' ht="{height}" customHeight="1"' if height else ""
    cells = []
    for offset, value in enumerate(values):
        ref = f"{_xlsx_col(start_col + offset)}{row_number}"
        cell_style = value.get("style", style) if isinstance(value, dict) else style
        if isinstance(value, dict):
            cells.append(_xlsx_cell(ref, value.get("value", ""), cell_style, value.get("formula")))
        else:
            cells.append(_xlsx_cell(ref, value, cell_style))
    return f'<row r="{row_number}"{height_attr}>{"".join(cells)}</row>'

def _xlsx_styles() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <numFmts count="3">
    <numFmt numFmtId="164" formatCode="$#,##0.00"/>
    <numFmt numFmtId="165" formatCode="0%"/>
    <numFmt numFmtId="166" formatCode="yyyy-mm-dd"/>
  </numFmts>
  <fonts count="5">
    <font><sz val="11"/><color theme="1"/><name val="Calibri"/></font>
    <font><b/><sz val="20"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
    <font><b/><sz val="12"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><color rgb="FF0F172A"/><name val="Calibri"/></font>
    <font><sz val="10"/><color rgb="FF334155"/><name val="Calibri"/></font>
  </fonts>
  <fills count="5">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFFF6B2C"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFF1F5F9"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFE2E8F0"/><bgColor indexed="64"/></patternFill></fill>
  </fills>
  <borders count="2">
    <border><left/><right/><top/><bottom/><diagonal/></border>
    <border><left style="thin"><color rgb="FFCBD5E1"/></left><right style="thin"><color rgb="FFCBD5E1"/></right><top style="thin"><color rgb="FFCBD5E1"/></top><bottom style="thin"><color rgb="FFCBD5E1"/></bottom><diagonal/></border>
  </borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="10">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>
    <xf numFmtId="0" fontId="2" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
    <xf numFmtId="0" fontId="3" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf>
    <xf numFmtId="164" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"/>
    <xf numFmtId="165" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"/>
    <xf numFmtId="0" fontId="3" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
    <xf numFmtId="164" fontId="3" fillId="4" borderId="1" xfId="0" applyNumberFormat="1" applyFont="1" applyFill="1" applyBorder="1"/>
    <xf numFmtId="0" fontId="4" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf>
  </cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""

def _invoice_sheet_xml(invoice: dict, line_items: list[dict]) -> str:
    invoice_date = invoice["billing_date"].strftime("%Y-%m-%d")
    due_date = invoice["due_date"].strftime("%Y-%m-%d")
    billing_period = f"{invoice['period_start'].strftime('%Y-%m-%d')} - {invoice['period_end'].strftime('%Y-%m-%d')}"
    organization = invoice["organization"]
    customer_address = _organization_invoice_address(organization)
    rows = [
        _xlsx_row(1, ["PROBESTACK", "", "", "", "", "", "", ""], 1, height=28),
        _xlsx_row(2, ["Annual Software Subscriptions & AI Platform", "", "", "", "", "", "", ""], 3),
        _xlsx_row(4, ["INVOICE", "", "", "", "Invoice Details", "", "", ""], 7),
        _xlsx_row(5, ["", "", "", "", "Invoice #", invoice["invoice_number"], "Invoice Date", invoice_date], 4),
        _xlsx_row(6, ["From", "", "", "", "Customer PO #", "", "Due Date", due_date], 4),
        _xlsx_row(7, ["ProbeStack Inc. (USA)", "", "", "", "Payment Terms", "Net 15", "Currency", "USD"], 4),
        _xlsx_row(8, ["415 Peachtree Pkwy, Ste 250", "", "", "", "Billing Period", billing_period, "Status", invoice["status"]], 4),
        _xlsx_row(9, ["Cumming, GA 30041 | billing@probestack.com"], 4),
        _xlsx_row(11, ["Bill To"], 7),
        _xlsx_row(12, [organization.get("legal_name") or organization.get("name") or "Customer"], 4),
        _xlsx_row(13, [customer_address], 4),
        _xlsx_row(14, [organization.get("default_currency") or "USD"], 4),
        _xlsx_row(16, ["SKU", "Product Plan", "Description", "Payment", "Qty", "Unit Price", "Tax %", "Amount"], 2),
    ]
    subtotal = 0.0
    for index, item in enumerate(line_items, start=17):
        subtotal += float(item["amount"])
        rows.append(_xlsx_row(index, [
            item["sku"],
            item["product_plan"],
            item["description"],
            "Annually",
            item["qty"],
            {"value": item["unit_price"], "style": 5},
            {"value": item["tax_rate"], "style": 6},
            {"value": item["amount"], "formula": f"E{index}*F{index}", "style": 5},
        ], 4, height=34))

    total_row = max(23, 18 + len(line_items))
    tax = 0.0
    rows.extend([
        _xlsx_row(total_row, ["Payment Instructions", "", "", "", "", "Subtotal", "", {"value": subtotal, "formula": f"SUM(H17:H{16 + len(line_items)})", "style": 8}], 7),
        _xlsx_row(total_row + 1, ["Payment Method: ACH / Wire / Credit Card\nBank / Payment Portal: [Insert Details]\nPayment Frequency: Annually for all organizations\nReference: Please include the invoice number on payment.", "", "", "", "", "Tax", "", {"value": tax, "formula": f"SUMPRODUCT(H17:H{16 + len(line_items)},G17:G{16 + len(line_items)})", "style": 8}], 9, height=62),
        _xlsx_row(total_row + 2, ["", "", "", "", "", "Total Due", "", {"value": subtotal + tax, "formula": f"H{total_row}+H{total_row + 1}", "style": 8}], 7),
        _xlsx_row(total_row + 5, ["Notes & Terms"], 7),
        _xlsx_row(total_row + 6, ["SKU is the unique product-plan ID for each product such as ForgeShift or ForgeFuzz. Product Plan should be Starter, Enterprise, or Enterprise Plus. Payment is annual for all organizations. Use Qty for number of users when user-priced; use Qty = 1 for each subscription-priced or /month subscription line."], 9, height=56),
    ])
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetFormatPr defaultRowHeight="15"/>
  <cols>
    <col min="1" max="1" width="24" customWidth="1"/><col min="2" max="2" width="20" customWidth="1"/>
    <col min="3" max="3" width="54" customWidth="1"/><col min="4" max="4" width="14" customWidth="1"/>
    <col min="5" max="5" width="9" customWidth="1"/><col min="6" max="6" width="15" customWidth="1"/>
    <col min="7" max="7" width="10" customWidth="1"/><col min="8" max="8" width="16" customWidth="1"/>
  </cols>
  <sheetData>{"".join(rows)}</sheetData>
  <mergeCells count="6"><mergeCell ref="A1:H1"/><mergeCell ref="A2:H2"/><mergeCell ref="A4:D4"/><mergeCell ref="E4:H4"/><mergeCell ref="A{total_row + 1}:D{total_row + 1}"/><mergeCell ref="A{total_row + 6}:H{total_row + 6}"/></mergeCells>
</worksheet>"""

def _catalog_sheet_xml(line_items: list[dict]) -> str:
    rows = [
        _xlsx_row(1, ["SKU", "Product Plan", "Description", "Payment", "Unit Price", "Currency", "Qty Rule", "", "Invoice Usage"], 2)
    ]
    usage_notes = {
        2: "Use SKU as the unique product-plan ID.",
        3: "Plans are Starter, Enterprise, Enterprise Plus.",
        4: "Payment is annually for every organization.",
        5: "For user-priced rows, Qty = number of users.",
        6: "For subscription or /month rows, Qty = 1.",
    }
    seen = set()
    row_number = 2
    for item in line_items:
        if item["sku"] in seen:
            continue
        seen.add(item["sku"])
        qty_rule = "Qty = number of users when user-priced" if item["qty"] != 1 else "Qty = 1 for subscription or /month pricing"
        rows.append(_xlsx_row(row_number, [
            item["sku"], item["product_plan"], item["description"], "Annually",
            {"value": item["unit_price"], "style": 5}, "USD", qty_rule, "", usage_notes.get(row_number, "")
        ], 4, height=32))
        row_number += 1
    while row_number <= 6:
        rows.append(_xlsx_row(row_number, ["", "", "", "", "", "", "", "", usage_notes.get(row_number, "")], 4))
        row_number += 1
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetFormatPr defaultRowHeight="15"/>
  <cols>
    <col min="1" max="1" width="24" customWidth="1"/><col min="2" max="2" width="20" customWidth="1"/>
    <col min="3" max="3" width="58" customWidth="1"/><col min="4" max="4" width="14" customWidth="1"/>
    <col min="5" max="5" width="15" customWidth="1"/><col min="6" max="6" width="12" customWidth="1"/>
    <col min="7" max="7" width="40" customWidth="1"/><col min="9" max="9" width="44" customWidth="1"/>
  </cols>
  <sheetData>{"".join(rows)}</sheetData>
</worksheet>"""

def build_invoice_workbook(invoice: dict, line_items: list[dict]) -> bytes:
    workbook = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="Invoice" sheetId="1" r:id="rId1"/><sheet name="Product Plans" sheetId="2" r:id="rId2"/></sheets>
</workbook>"""
    workbook_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"""
    root_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        zf.writestr("xl/styles.xml", _xlsx_styles())
        zf.writestr("xl/worksheets/sheet1.xml", _invoice_sheet_xml(invoice, line_items))
        zf.writestr("xl/worksheets/sheet2.xml", _catalog_sheet_xml(line_items))
    return output.getvalue()

def _pdf_escape(value: Any) -> str:
    return str(value if value is not None else "").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

def _pdf_text_width(text: Any, size: float) -> float:
    return len(str(text or "")) * size * 0.48

def _pdf_text_line(
    x: float,
    y: float,
    text: Any,
    size: float = 10,
    bold: bool = False,
    color: tuple[float, float, float] = (0.10, 0.14, 0.22),
    align: str = "left",
    width: float = 0,
) -> str:
    if align == "right" and width:
        x = x + width - _pdf_text_width(text, size)
    font = "F2" if bold else "F1"
    return f"q {color[0]} {color[1]} {color[2]} rg BT /{font} {size:.1f} Tf {x:.1f} {y:.1f} Td ({_pdf_escape(text)}) Tj ET Q\n"

def _pdf_rect(x: float, y: float, width: float, height: float, fill: Optional[tuple[float, float, float]] = None) -> str:
    if fill:
        return f"q {fill[0]} {fill[1]} {fill[2]} rg {x:.1f} {y:.1f} {width:.1f} {height:.1f} re f Q\n"
    return f"q 0.82 0.86 0.91 RG {x:.1f} {y:.1f} {width:.1f} {height:.1f} re S Q\n"

def _pdf_line(x1: float, y1: float, x2: float, y2: float, color: tuple[float, float, float] = (0.82, 0.86, 0.91), width: float = 0.7) -> str:
    return f"q {color[0]} {color[1]} {color[2]} RG {width:.1f} w {x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S Q\n"

def _wrap_pdf_text(text: Any, max_chars: int) -> list[str]:
    words = str(text or "").split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + (1 if current else 0) <= max_chars:
            current = f"{current} {word}".strip()
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]

def _organization_invoice_address(organization: dict) -> str:
    for key in ("address", "headquarters", "billing_account"):
        value = str(organization.get(key) or "").strip()
        if value:
            return value
    return "100 Customer Avenue, Suite 200, San Francisco, CA 94105"

def build_invoice_pdf(invoice: dict, line_items: list[dict]) -> bytes:
    organization = invoice["organization"]
    org_name = organization.get("legal_name") or organization.get("name") or "Customer"
    customer_address = _organization_invoice_address(organization)
    sender_address_lines = ["415 Peachtree Pkwy", "Ste 250", "Cumming, GA 30041"]
    invoice_date = invoice["billing_date"].strftime("%Y-%m-%d")
    due_date = invoice["due_date"].strftime("%Y-%m-%d")
    billing_period = f"{invoice['period_start'].strftime('%Y-%m-%d')} - {invoice['period_end'].strftime('%Y-%m-%d')}"
    subtotal = float(sum(item["amount"] for item in line_items))
    tax = 0.0
    total = subtotal + tax

    orange = (0.95, 0.38, 0.14)
    dark = (0.09, 0.12, 0.18)
    muted = (0.39, 0.46, 0.57)
    border = (0.82, 0.86, 0.91)
    soft = (0.97, 0.98, 0.99)
    white = (1.0, 1.0, 1.0)

    stream = _pdf_rect(42, 714, 528, 48, orange)
    stream += _pdf_text_line(58, 742, "PROBESTACK", 18, True, white)
    stream += _pdf_text_line(58, 724, "Enterprise Software & AI Platform", 9.5, False, white)
    stream += _pdf_text_line(434, 732, "INVOICE", 24, True, white)
    stream += _pdf_text_line(42, 690, "Annual Software Subscriptions & AI Platform", 10, False, muted)

    stream += _pdf_text_line(42, 658, "From", 11, True, orange)
    stream += _pdf_text_line(42, 638, "ProbeStack Inc. (USA)", 10, True, dark)
    for index, line in enumerate(sender_address_lines):
        stream += _pdf_text_line(42, 624 - (index * 13), line, 8.5, False, muted)
    stream += _pdf_text_line(42, 585, "billing@probestack.com", 8.5, False, muted)

    stream += _pdf_text_line(42, 572, "Bill To", 11, True, orange)
    stream += _pdf_text_line(42, 552, org_name, 10, True, dark)
    for index, line in enumerate(_wrap_pdf_text(customer_address, 52)[:2]):
        stream += _pdf_text_line(42, 538 - (index * 13), line, 8.5, False, muted)

    stream += _pdf_rect(334, 532, 236, 130, soft)
    stream += _pdf_text_line(348, 644, "Invoice Details", 11, True, orange)
    detail_x = 348
    details = [
        ("Invoice #", invoice["invoice_number"]),
        ("Invoice Date", invoice_date),
        ("Due Date", due_date),
        ("Payment Terms", "Net 30"),
        ("Billing", "Annual"),
        ("Billing Period", billing_period),
        ("Status", str(invoice["status"]).title()),
    ]
    y = 624
    for label, value in details:
        stream += _pdf_text_line(detail_x, y, label, 8.2, True, muted)
        stream += _pdf_text_line(detail_x + 92, y, value, 8.2, False, dark)
        y -= 15

    table_left = 42
    table_top = 486
    columns = [
        ("SKU", 66),
        ("Product Plan", 76),
        ("Description", 146),
        ("Billing", 52),
        ("Qty", 28),
        ("Unit Price", 58),
        ("Tax %", 34),
        ("Amount", 68),
    ]
    x_positions = [table_left]
    for _, col_width in columns[:-1]:
        x_positions.append(x_positions[-1] + col_width)

    stream += _pdf_rect(table_left, table_top, 528, 24, dark)
    for (header, _), x in zip(columns, x_positions):
        stream += _pdf_text_line(x + 6, table_top + 8, header, 7.4, True, white)

    y = table_top - 28
    for item in line_items:
        if y < 170:
            break
        row_height = 34 if len(line_items) > 5 else 40
        desc_lines = _wrap_pdf_text(item["description"], 34)[:2]
        if (int((table_top - y) / row_height) % 2) == 0:
            stream += _pdf_rect(table_left, y - 13, 528, row_height, (0.985, 0.99, 0.995))
        stream += _pdf_text_line(x_positions[0] + 6, y, item["sku"], 7.5, True, dark)
        stream += _pdf_text_line(x_positions[1] + 6, y, item["product_plan"], 7.5, False, dark)
        stream += _pdf_text_line(x_positions[2] + 6, y, desc_lines[0], 7.5, False, dark)
        if len(desc_lines) > 1:
            stream += _pdf_text_line(x_positions[2] + 6, y - 11, desc_lines[1], 7.2, False, muted)
        stream += _pdf_text_line(x_positions[3] + 6, y, item.get("payment") or "Annually", 7.5, False, dark)
        stream += _pdf_text_line(x_positions[4] + 6, y, item["qty"], 7.5, False, dark)
        stream += _pdf_text_line(x_positions[5] + 4, y, f"${item['unit_price']:,.2f}", 7.2, False, dark, "right", columns[5][1] - 8)
        stream += _pdf_text_line(x_positions[6] + 4, y, f"{item['tax_rate']:.0f}%", 7.2, False, dark, "right", columns[6][1] - 8)
        stream += _pdf_text_line(x_positions[7] + 4, y, f"${item['amount']:,.2f}", 7.2, True, dark, "right", columns[7][1] - 8)
        stream += _pdf_line(table_left, y - 16, table_left + 528, y - 16, border)
        y -= row_height

    totals_y = max(158, y - 8)
    stream += _pdf_line(396, totals_y + 16, 570, totals_y + 16, border)
    stream += _pdf_text_line(410, totals_y, "Subtotal", 9, True, muted)
    stream += _pdf_text_line(484, totals_y, f"${subtotal:,.2f}", 9, True, dark, "right", 78)
    stream += _pdf_text_line(410, totals_y - 17, "Tax", 9, True, muted)
    stream += _pdf_text_line(484, totals_y - 17, f"${tax:,.2f}", 9, True, dark, "right", 78)
    stream += _pdf_rect(396, totals_y - 54, 174, 26, orange)
    stream += _pdf_text_line(410, totals_y - 45, "Total Due", 10.5, True, white)
    stream += _pdf_text_line(484, totals_y - 45, f"${total:,.2f}", 10.5, True, white, "right", 78)

    notes_y = 108
    stream += _pdf_rect(42, 46, 320, 78, soft)
    stream += _pdf_text_line(56, notes_y, "Payment Instructions", 9.5, True, orange)
    stream += _pdf_text_line(56, notes_y - 15, "Payment Method: ACH / Wire / Credit Card", 7.8, False, dark)
    stream += _pdf_text_line(56, notes_y - 28, "Payment Frequency: Annually for all organizations", 7.8, False, dark)
    stream += _pdf_text_line(56, notes_y - 41, "Reference: Include the invoice number on payment.", 7.8, False, dark)
    stream += _pdf_text_line(56, notes_y - 60, "Notes & Terms", 8, True, muted)
    stream += _pdf_text_line(122, notes_y - 60, "Services are governed by the applicable ProbeStack agreement.", 7.2, False, muted)
    stream += _pdf_text_line(42, 28, "Questions: billing@probestack.com", 7.2, False, muted)

    stream_bytes = stream.encode("latin-1", "replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
        f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin-1") + stream_bytes + b"endstream",
    ]
    output = io.BytesIO()
    output.write(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(output.tell())
        output.write(f"{index} 0 obj\n".encode("latin-1"))
        output.write(obj)
        output.write(b"\nendobj\n")
    xref_offset = output.tell()
    output.write(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    output.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.write(f"{offset:010d} 00000 n \n".encode("latin-1"))
    output.write(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin-1"))
    return output.getvalue()

async def user_request_to_dict(db: AsyncSession, request: UserRequestModel) -> dict:
    data = model_to_dict(request)
    data["organization_name"] = await get_organization_name(db, request.organization_id)
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
    data = add_identity_aliases(
        model_to_dict(org, ["requested_tools", "supported_domains", "gateway_environments", "compliance_standards"]),
        "organization",
    )
    requested_details = await get_organization_requested_plan_details(db, org)
    if requested_details:
        data["requested_plan"] = json.dumps([detail["plan_id"] for detail in requested_details])
        data["requested_plans"] = [detail["plan_id"] for detail in requested_details]
        data["requested_tools"] = []
        for detail in requested_details:
            data["requested_tools"].extend(detail.get("tools", []))
        data["requested_plan_details"] = requested_details

    active_subs_result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.organization_id == org.id)
        .where(SubscriptionModel.status == "active")
        .order_by(SubscriptionModel.created_at.desc())
    )
    active_subscriptions = active_subs_result.scalars().all()
    active_plan_details = []
    for subscription in active_subscriptions:
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == subscription.plan_id))
        plan = plan_result.scalar_one_or_none()
        product = await get_plan_product(db, plan) if plan else None
        active_plan_details.append({
            "subscription_id": subscription.id,
            "plan_id": subscription.plan_id,
            "plan_name": plan.name if plan else await get_plan_name(db, subscription.plan_id),
            "product_id": product.id if product else (plan.product_id if plan else None),
            "product_key": product.key if product else (plan.tool if plan else None),
            "product_name": product.name if product else None,
            "amount": subscription.amount,
            "status": subscription.status,
        })
    data["active_plan_details"] = active_plan_details
    data["active_plans"] = [detail["plan_id"] for detail in active_plan_details if detail.get("plan_id")]
    if active_plan_details:
        data["plan_display"] = ", ".join(
            [
                f"{detail.get('product_name') or detail.get('product_key') or 'Product'} - {detail.get('plan_name') or detail.get('plan_id')}"
                for detail in active_plan_details
            ]
        )
    elif requested_details:
        data["plan_display"] = ", ".join(
            [
                f"{detail.get('product_name') or 'Product'} - {detail.get('plan_name') or detail.get('plan_id')}"
                for detail in requested_details
            ]
        )
    else:
        data["plan_display"] = "No active plan"
    return data

async def public_organization_to_dict(db: AsyncSession, org: OrganizationModel) -> dict:
    data = await organization_to_dict(db, org)
    return {
        "id": data.get("id"),
        "name": data.get("name"),
        "external_org_id": data.get("external_org_id"),
        "domain": data.get("domain"),
        "status": data.get("status"),
        "organization_code": data.get("organization_code"),
        "industry": data.get("industry"),
        "country": data.get("country"),
        "region": data.get("region"),
        "website": data.get("website"),
        "logo_url": data.get("logo_url"),
        "plan_display": data.get("plan_display"),
        "active_plan_details": [
            {
                "subscription_id": detail.get("subscription_id"),
                "plan_id": detail.get("plan_id"),
                "plan_name": detail.get("plan_name"),
                "product_id": detail.get("product_id"),
                "product_key": detail.get("product_key"),
                "product_name": detail.get("product_name"),
                "status": detail.get("status"),
            }
            for detail in data.get("active_plan_details") or []
        ],
        "requested_plan_details": [
            {
                "plan_id": detail.get("plan_id"),
                "plan_name": detail.get("plan_name"),
                "product_id": detail.get("product_id"),
                "product_name": detail.get("product_name"),
            }
            for detail in data.get("requested_plan_details") or []
        ],
    }

async def upgrade_request_to_dict(db: AsyncSession, request: PlanUpgradeRequestModel) -> dict:
    data = model_to_dict(request)
    request_items = await get_upgrade_request_items(db, request)
    data["organization_name"] = await get_organization_name(db, request.organization_id)
    current_plan_ids = parse_json_list(request.current_plan_id)
    data["current_plan_ids"] = current_plan_ids
    current_plan_details = []
    for plan_id in current_plan_ids:
        plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
        plan = plan_result.scalar_one_or_none()
        product = await get_plan_product(db, plan) if plan else None
        current_plan_details.append({
            "plan_id": plan_id,
            "plan_name": plan.name if plan else plan_id,
            "product_id": product.id if product else None,
            "product_name": product.name if product else None,
            "display_name": f"{product.name} - {plan.name}" if product and plan else plan.name if plan else plan_id,
        })
    data["current_plan_details"] = current_plan_details
    data["current_plan_name"] = ", ".join([item["display_name"] for item in current_plan_details]) if current_plan_details else "No current plan for selected product"
    data["current_plan_names"] = [item["plan_name"] for item in current_plan_details]
    data["requested_plan_name"] = None
    data["requested_plans_details"] = []
    data["requested_plan_ids"] = []
    data["requested_tools"] = []
    if request_items:
        data["requested_plans_details"] = request_items
        data["requested_plan_ids"] = [item["plan_id"] for item in request_items]
        for item in request_items:
            data["requested_tools"].extend(item.get("tools", []))
            item["display_name"] = (
                f"{item['product_name']} - {item['plan_name']}"
                if item.get("product_name") and item.get("plan_name")
                else item.get("plan_name")
            )
        data["requested_plan_name"] = ", ".join([item["display_name"] for item in request_items if item.get("display_name")])
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
    token = credentials.credentials
    try:
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")
        if algorithm == PROBESTACK_CONTEXT_TOKEN_ALGORITHM:
            payload = jwt.decode(
                token,
                get_context_token_public_key(),
                algorithms=[PROBESTACK_CONTEXT_TOKEN_ALGORITHM],
                issuer=PROBESTACK_TOKEN_ISSUER,
                options={"verify_aud": False},
            )
        else:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                options={"verify_aud": False},
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def optional_verify_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_security)):
    if not credentials:
        return None
    return verify_token(credentials)

def normalized_issuer_url(value: str) -> str:
    issuer = (value or "").strip().rstrip("/")
    if issuer and not issuer.startswith(("http://", "https://")):
        issuer = f"https://{issuer}"
    return issuer

def expected_provider_issuer(provider: str) -> str:
    if provider == "auth0":
        return normalized_issuer_url(AUTH0_DOMAIN)
    if provider == "zitadel":
        return normalized_issuer_url(ZITADEL_DOMAIN)
    return ""

def expected_provider_audience(provider: str) -> str:
    if provider == "auth0":
        return AUTH0_CLIENT_ID
    if provider == "zitadel":
        return ZITADEL_CLIENT_ID
    return ""

def infer_identity_provider_from_issuer(issuer: str, requested_provider: Optional[str] = None) -> str:
    provider = normalize_identity_provider(requested_provider) if requested_provider else ""
    normalized_issuer = normalized_issuer_url(issuer).lower()
    if provider in SUPPORTED_IDENTITY_PROVIDERS:
        return provider
    if "zitadel" in normalized_issuer:
        return "zitadel"
    return "auth0"

def get_jwks_client(issuer: str):
    normalized_issuer = normalized_issuer_url(issuer)
    if not normalized_issuer:
        raise HTTPException(status_code=401, detail="id_token issuer is missing")
    if "zitadel" in normalized_issuer.lower():
        jwks_url = f"{normalized_issuer}/oauth/v2/keys"
    else:
        jwks_url = f"{normalized_issuer}/.well-known/jwks.json"
    if jwks_url not in _jwks_clients:
        _jwks_clients[jwks_url] = jwt.PyJWKClient(jwks_url)
    return _jwks_clients[jwks_url]

def verify_provider_id_token(id_token: str, requested_provider: Optional[str] = None) -> tuple[dict, str]:
    try:
        unverified = jwt.decode(id_token, options={"verify_signature": False})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id_token")

    issuer_claim = (unverified.get("iss") or "").strip()
    issuer = normalized_issuer_url(issuer_claim)
    provider = infer_identity_provider_from_issuer(issuer, requested_provider)
    expected_issuer = expected_provider_issuer(provider)
    audience = expected_provider_audience(provider)

    if expected_issuer and issuer != expected_issuer:
        raise HTTPException(status_code=401, detail=f"id_token issuer does not match configured {provider} issuer")
    if not audience:
        raise HTTPException(status_code=500, detail=f"{provider} client ID is not configured")

    try:
        signing_key = get_jwks_client(issuer).get_signing_key_from_jwt(id_token).key
        decoded = jwt.decode(
            id_token,
            signing_key,
            algorithms=["RS256", "EdDSA", "ES256"],
            audience=audience,
            issuer=issuer_claim or issuer,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="id_token expired")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid id_token: {str(exc)}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Unable to verify id_token: {str(exc)}")

    return decoded, provider

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

async def get_subscription_access_scope(db: AsyncSession, payload: dict) -> dict:
    """Resolve what subscriptions this token is allowed to read."""
    if payload.get("role") == "super_admin" and payload.get("token_type") != "probestack_user_context":
        return {"scope": "all"}

    if payload.get("role") == "org_admin" and payload.get("organization_id"):
        return {"scope": "organization", "organization_id": payload.get("organization_id")}

    subject = payload.get("sub")
    email = (payload.get("email") or "").strip().lower()

    user = None
    if subject:
        result = await db.execute(select(UserModel).where(UserModel.id == subject))
        user = result.scalar_one_or_none()
    if not user and email:
        result = await db.execute(select(UserModel).where(UserModel.email == email))
        user = result.scalar_one_or_none()

    if user:
        await sync_user_role_from_mongodb(db, user)
        individual_org_id = await get_individual_users_org_id(db)
        if user.organization_id == individual_org_id:
            return {"scope": "individual", "email": user.email}
        return {"scope": "organization", "organization_id": user.organization_id}

    admin = None
    if subject:
        result = await db.execute(select(AdminModel).where(AdminModel.id == subject))
        admin = result.scalar_one_or_none()
    if not admin and email:
        result = await db.execute(select(AdminModel).where(AdminModel.email == email))
        admin = result.scalar_one_or_none()

    if admin and admin.role == "super_admin":
        return {"scope": "all"}
    if admin and admin.organization_id:
        return {"scope": "organization", "organization_id": admin.organization_id}

    raise HTTPException(status_code=403, detail="No subscription access for this token")

async def get_authenticated_data_scope(db: AsyncSession, payload: dict) -> dict:
    """Resolve the organization/email scope for a verified admin or product user token."""
    if payload.get("role") == "super_admin" and payload.get("token_type") != "probestack_user_context":
        return {"scope": "all"}

    if payload.get("role") == "org_admin" and payload.get("organization_id"):
        return {"scope": "organization", "organization_id": payload.get("organization_id")}

    subject = payload.get("sub")
    email = (payload.get("email") or "").strip().lower()

    user = None
    if subject:
        result = await db.execute(select(UserModel).where(UserModel.id == subject))
        user = result.scalar_one_or_none()
    if not user and email:
        result = await db.execute(select(UserModel).where(UserModel.email == email))
        user = result.scalar_one_or_none()
    if user:
        await sync_user_role_from_mongodb(db, user)
        if await is_individual_users_org_id(db, user.organization_id):
            return {"scope": "individual", "email": user.email}
        return {"scope": "organization", "organization_id": user.organization_id}

    admin = None
    if subject:
        result = await db.execute(select(AdminModel).where(AdminModel.id == subject))
        admin = result.scalar_one_or_none()
    if not admin and email:
        result = await db.execute(select(AdminModel).where(AdminModel.email == email))
        admin = result.scalar_one_or_none()
    if admin and admin.role == "super_admin":
        return {"scope": "all"}
    if admin and admin.organization_id:
        return {"scope": "organization", "organization_id": admin.organization_id}

    raise HTTPException(status_code=403, detail="No data access for this token")

def has_data_scope_access(access_scope: dict, *, email: Optional[str], organization_id: Optional[str]) -> bool:
    if access_scope["scope"] == "all":
        return True
    if access_scope["scope"] == "organization":
        return bool(organization_id and organization_id == access_scope.get("organization_id"))
    if access_scope["scope"] == "individual":
        return bool(email and email.strip().lower() == access_scope.get("email"))
    return False

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

def normalize_identity_provider(provider: Optional[str]) -> str:
    normalized = (provider or DEFAULT_IDENTITY_PROVIDER).strip().lower()
    if normalized in {"auth0", "auth-0"}:
        return "auth0"
    if normalized in {"zitadel", "zitadel_only", "zitadel-only"}:
        return "zitadel"
    raise HTTPException(status_code=400, detail="Identity provider must be auth0 or zitadel")

async def get_active_identity_provider(db: AsyncSession) -> str:
    result = await db.execute(
        select(SystemSettingModel).where(SystemSettingModel.key == IDENTITY_PROVIDER_SETTING_KEY)
    )
    setting = result.scalar_one_or_none()
    if not setting:
        return DEFAULT_IDENTITY_PROVIDER
    return normalize_identity_provider(setting.value)

def identity_provider_config(provider: str) -> dict:
    provider = normalize_identity_provider(provider)
    if provider == "auth0":
        return {
            "provider": "auth0",
            "configured": auth0_mgmt.enabled,
            "domain": AUTH0_DOMAIN,
            "management_domain": AUTH0_MGMT_DOMAIN,
            "organization_mode": "organizations",
        }
    return {
        "provider": "zitadel",
        "configured": zitadel_mgmt.enabled,
        "domain": zitadel_mgmt.base_url,
        "organization_mode": "organizations",
    }

def require_identity_provider_configured(provider: str):
    config = identity_provider_config(provider)
    if not config["configured"]:
        raise HTTPException(
            status_code=503,
            detail=f"{provider.upper()} is selected but not configured",
        )

async def set_active_identity_provider(db: AsyncSession, provider: str, updated_by: Optional[str] = None) -> SystemSettingModel:
    provider = normalize_identity_provider(provider)
    require_identity_provider_configured(provider)
    result = await db.execute(
        select(SystemSettingModel).where(SystemSettingModel.key == IDENTITY_PROVIDER_SETTING_KEY)
    )
    setting = result.scalar_one_or_none()
    if not setting:
        setting = SystemSettingModel(
            key=IDENTITY_PROVIDER_SETTING_KEY,
            value=provider,
            updated_by=updated_by,
        )
        db.add(setting)
    else:
        setting.value = provider
        setting.updated_by = updated_by
        setting.updated_at = datetime.now(timezone.utc)
    await db.flush()
    return setting

async def get_system_setting_value(db: AsyncSession, key: str, default: Optional[str] = None) -> Optional[str]:
    result = await db.execute(select(SystemSettingModel).where(SystemSettingModel.key == key))
    setting = result.scalar_one_or_none()
    return setting.value if setting else default

async def get_required_system_setting_value(db: AsyncSession, key: str, fallback: Optional[str] = None) -> str:
    value = await get_system_setting_value(db, key)
    if value:
        return value.strip()
    if fallback:
        return fallback.strip()
    raise HTTPException(status_code=500, detail=f"Missing required system setting: {key}")

async def get_individual_users_org_id(db: AsyncSession) -> str:
    return await get_required_system_setting_value(db, INDIVIDUAL_USERS_ORG_ID_SETTING_KEY, INDIVIDUAL_USERS_ORG_ID_FALLBACK)

async def is_individual_users_org_id(db: AsyncSession, organization_id: Optional[str]) -> bool:
    if not organization_id:
        return False
    individual_org_id = await get_individual_users_org_id(db)
    return organization_id == individual_org_id

async def get_individual_users_org_name(db: AsyncSession) -> str:
    return await get_required_system_setting_value(db, INDIVIDUAL_USERS_ORG_NAME_SETTING_KEY, INDIVIDUAL_USERS_ORG_NAME_FALLBACK)

async def get_individual_users_org_email(db: AsyncSession) -> str:
    return await get_required_system_setting_value(db, INDIVIDUAL_USERS_ORG_EMAIL_SETTING_KEY, INDIVIDUAL_USERS_ORG_EMAIL_FALLBACK)

async def get_individual_users_contact_person(db: AsyncSession) -> str:
    return await get_required_system_setting_value(db, INDIVIDUAL_USERS_CONTACT_PERSON_SETTING_KEY, INDIVIDUAL_USERS_CONTACT_PERSON_FALLBACK)

async def get_individual_default_plan_ids(db: AsyncSession) -> List[str]:
    configured = await get_system_setting_value(db, INDIVIDUAL_DEFAULT_PLAN_IDS_SETTING_KEY)
    if configured:
        parsed = parse_json_list(configured)
        if parsed:
            return parsed
    env_plan_ids = parse_json_list(os.environ.get("DEFAULT_INDIVIDUAL_PLAN_IDS"))
    env_plan_id = os.environ.get("DEFAULT_INDIVIDUAL_PLAN_ID")
    return env_plan_ids or ([env_plan_id] if env_plan_id else [])

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

async def is_individual_users_org(db: AsyncSession, org: Optional[OrganizationModel]) -> bool:
    if not org:
        return False
    individual_org_id = await get_individual_users_org_id(db)
    individual_org_name = await get_individual_users_org_name(db)
    return org.id == individual_org_id or org.name == individual_org_name

async def assert_email_allowed_for_org(db: AsyncSession, email: str, org: OrganizationModel):
    if await is_individual_users_org(db, org):
        return
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

async def find_real_org_by_email_domain(db: AsyncSession, email: str) -> Optional[OrganizationModel]:
    if not email or "@" not in email:
        return None
    email_domain = "@" + email.split("@", 1)[1].lower()
    individual_org_id = await get_individual_users_org_id(db)
    individual_org_name = await get_individual_users_org_name(db)
    result = await db.execute(
        select(OrganizationModel).where(
            OrganizationModel.status == "approved",
            OrganizationModel.id != individual_org_id,
            OrganizationModel.name != individual_org_name,
        )
    )
    for org in result.scalars().all():
        if email_domain in get_org_allowed_domains(org):
            return org
    return None

async def get_or_create_individual_users_org(db: AsyncSession) -> OrganizationModel:
    individual_org_id = await get_individual_users_org_id(db)
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == individual_org_id))
    org = result.scalar_one_or_none()
    if org:
        return org
    org = OrganizationModel(
        id=individual_org_id,
        name=await get_individual_users_org_name(db),
        email=await get_individual_users_org_email(db),
        domain=None,
        status="approved",
        contact_person=await get_individual_users_contact_person(db),
        approved_at=datetime.now(timezone.utc),
    )
    db.add(org)
    await db.flush()
    return org

async def get_default_individual_plan(db: AsyncSession) -> PlanModel:
    preferred_ids = await get_individual_default_plan_ids(db)
    for plan_id in [pid for pid in preferred_ids if pid]:
        result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id, PlanModel.is_active == True))
        plan = result.scalar_one_or_none()
        if plan:
            return plan
    result = await db.execute(
        select(PlanModel)
        .where(PlanModel.is_active == True)
        .where(PlanModel.name.ilike("%starter%"))
        .order_by(PlanModel.cost.asc(), PlanModel.created_at.asc())
    )
    plan = result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=400, detail="No active starter plan is configured for individual users")
    return plan

async def create_individual_request_for_unknown_domain(
    db: AsyncSession,
    *,
    email: str,
    name: str,
    job_title: Optional[str] = None,
    phone: Optional[str] = None,
    notes: Optional[str] = None,
) -> IndividualUserRequestModel:
    await get_or_create_individual_users_org(db)
    plan = await get_default_individual_plan(db)
    existing = await db.execute(
        select(IndividualUserRequestModel).where(
            IndividualUserRequestModel.email == email,
            IndividualUserRequestModel.status == "pending",
        )
    )
    existing_request = existing.scalar_one_or_none()
    if existing_request:
        return existing_request

    request = IndividualUserRequestModel(
        email=email,
        name=name or derive_name_from_email(email),
        requested_tools=json.dumps([]),
        requested_plan=json.dumps([plan.id]),
        purpose=notes or "Unknown organization domain; routed to Individual Users.",
        company_name=email.split("@", 1)[1] if "@" in email else None,
        job_title=job_title,
        phone=phone,
    )
    db.add(request)
    db.add(NotificationModel(
        title="New Individual User Request",
        message=f"{request.name} ({email}) was routed to Individual Users for {plan.name}.",
        type="info",
        link=f"/individual-requests/{request.id}",
    ))
    await db.flush()
    return request

async def create_individual_user_subscription(
    db: AsyncSession,
    *,
    user: UserModel,
    plan: PlanModel,
    requested_tools: Optional[List[str]] = None,
    source_request: Optional[IndividualUserRequestModel] = None,
) -> SubscriptionModel:
    tools = requested_tools or []
    individual_org_id = await get_individual_users_org_id(db)
    subscription = SubscriptionModel(
        organization_id=individual_org_id,
        plan_id=plan.id,
        status="active",
        start_date=datetime.now(timezone.utc),
        end_date=datetime.now(timezone.utc) + timedelta(days=30),
        billing_cycle="monthly",
        amount=plan.price_monthly,
        quota=int(getattr(plan, "api_limit", 0) or 0),
        used_quota=0,
    )
    db.add(subscription)
    await db.flush()
    await set_subscription_tools(db, subscription.id, plan.id, tools)

    if source_request:
        source_request.assigned_subscription_id = subscription.id
    return subscription

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
    if status not in PROJECT_STATUS_VALUES:
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
    apply_onboarding_fields(business_unit, payload_dict(data), BUSINESS_UNIT_ONBOARDING_FIELDS)
    db.add(business_unit)
    await db.flush()
    await upsert_business_unit_quotas(db, business_unit.id, payload_dict(data))
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
    if status not in PROJECT_STATUS_VALUES:
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
    apply_onboarding_fields(project, payload_dict(data), PROJECT_ONBOARDING_FIELDS)
    db.add(project)
    await db.flush()
    await upsert_project_environments(db, project.id, payload_dict(data))
    return project

async def upsert_project_environments(db: AsyncSession, project_id: str, payload: dict):
    for env_type in PROJECT_ENVIRONMENT_TYPES:
        key = env_type.lower().replace(" ", "_")
        endpoint_key = f"{key}_endpoint_url"
        enabled_key = f"{key}_enabled"
        if endpoint_key not in payload and enabled_key not in payload:
            continue
        result = await db.execute(
            select(ProjectEnvironmentModel).where(
                ProjectEnvironmentModel.project_id == project_id,
                ProjectEnvironmentModel.environment_type == env_type,
            )
        )
        env = result.scalar_one_or_none()
        if not env:
            env = ProjectEnvironmentModel(project_id=project_id, environment_type=env_type)
            db.add(env)
        if endpoint_key in payload:
            env.endpoint_url = normalize_onboarding_value(endpoint_key, payload.get(endpoint_key))
        if enabled_key in payload:
            env.is_enabled = bool(payload.get(enabled_key))
        env.updated_at = datetime.now(timezone.utc)

async def upsert_business_unit_quotas(db: AsyncSession, business_unit_id: str, payload: dict):
    for field_key, quota_type in BUSINESS_UNIT_QUOTA_FIELDS.items():
        if field_key not in payload:
            continue
        quota_limit = normalize_onboarding_value(field_key, payload.get(field_key))
        result = await db.execute(
            select(QuotaModel).where(
                QuotaModel.entity_type == "business_unit",
                QuotaModel.entity_id == business_unit_id,
                QuotaModel.quota_type == quota_type,
            )
        )
        quota = result.scalar_one_or_none()
        if not quota:
            quota = QuotaModel(
                entity_type="business_unit",
                entity_id=business_unit_id,
                quota_type=quota_type,
                quota_used=0,
            )
            db.add(quota)
        quota.quota_limit = quota_limit
        quota.updated_at = datetime.now(timezone.utc)

async def get_application_for_org(db: AsyncSession, application_id: str, organization_id: str) -> ApplicationModel:
    result = await db.execute(
        select(ApplicationModel).where(
            ApplicationModel.id == application_id,
            ApplicationModel.organization_id == organization_id,
        )
    )
    application = result.scalar_one_or_none()
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    return application

async def application_to_dict(db: AsyncSession, application: ApplicationModel) -> dict:
    data = add_identity_aliases(
        model_to_dict(application, ["mcp_resources", "mcp_tools", "mcp_prompts"]),
        "application",
    )
    for key, model_cls, json_fields in [
        ("agent", ApplicationAgentModel, []),
        ("monitoring", ApplicationMonitoringModel, []),
        ("security", ApplicationSecurityModel, []),
        ("billing", ApplicationBillingModel, []),
    ]:
        related = await db.get(model_cls, application.id)
        data[key] = model_to_dict(related, json_fields) if related else {}
    return data

async def assert_application_unique(
    db: AsyncSession,
    project_id: str,
    application_name: Optional[str],
    exclude_id: Optional[str] = None,
):
    if not application_name:
        return
    query = select(ApplicationModel).where(
        ApplicationModel.project_id == project_id,
        ApplicationModel.application_name == application_name,
    )
    if exclude_id:
        query = query.where(ApplicationModel.id != exclude_id)
    if (await db.execute(query)).scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Application name already exists in this project")

async def upsert_application_sections(db: AsyncSession, application_id: str, payload: dict):
    section_specs = [
        (ApplicationAgentModel, APPLICATION_AGENT_FIELDS),
        (ApplicationMonitoringModel, APPLICATION_MONITORING_FIELDS),
        (ApplicationSecurityModel, APPLICATION_SECURITY_FIELDS),
        (ApplicationBillingModel, APPLICATION_BILLING_FIELDS),
    ]
    for model_cls, fields in section_specs:
        if not any(field in payload for field in fields):
            continue
        row = await db.get(model_cls, application_id)
        if not row:
            row = model_cls(application_id=application_id)
            db.add(row)
        apply_onboarding_fields(row, payload, fields)

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
    return await get_standard_role(db, org.id)

def supported_domains_from_domain(domain: Optional[str]) -> Optional[str]:
    cleaned_domain = (domain or "").strip().lower().lstrip("@")
    if not cleaned_domain:
        return None
    return json.dumps([f"@{cleaned_domain}"])

def build_probestack_org_metadata(org: OrganizationModel) -> dict:
    return {
        "probestack_org_id": org.id,
        "probestack_org_name": org.name,
    }

async def probestack_token_type_for_org(db: AsyncSession, org: Optional[OrganizationModel]) -> str:
    return "individual" if await is_individual_users_org(db, org) else "enterprise"

async def build_probestack_user_metadata(
    db: AsyncSession,
    user: UserModel,
    email: str,
    org: Optional[OrganizationModel],
    role_name: Optional[str],
    base_metadata: Optional[dict] = None,
) -> dict:
    metadata = dict(base_metadata or {})
    token_type = await probestack_token_type_for_org(db, org)
    metadata.update(
        {
            "probestack_user_id": user.id,
            "probestack_user_email": email,
            "probestack_user_role": role_name or await get_role_name(db, user.role_id, "API/Agent Consumer"),
            "probestack_token_type": token_type,
        }
    )
    if org:
        metadata.update(
            {
                "organization_id": org.id,
                "organization_name": org.name,
                "probestack_org_id": org.id,
                "probestack_org_name": org.name,
            }
        )
    return metadata

async def provision_organization_in_zitadel(org: OrganizationModel) -> dict:
    """Create the matching Zitadel organization and persist its ID on the local organization row."""
    if not zitadel_mgmt.enabled:
        logger.info(f"Zitadel organization provisioning skipped for {org.name}: not configured")
        return {"success": False, "skipped": True}
    if org.zitadel_org_id:
        metadata_result = await zitadel_mgmt.set_organization_metadata(
            org.zitadel_org_id,
            build_probestack_org_metadata(org),
        )
        return {
            "success": True,
            "exists": True,
            "zitadel_org_id": org.zitadel_org_id,
            "metadata": metadata_result,
        }

    zitadel_result = await zitadel_mgmt.create_organization(org.name)
    if not zitadel_result.get("success"):
        return zitadel_result

    org.zitadel_org_id = zitadel_result.get("zitadel_org_id")
    if not org.zitadel_org_id:
        return {"success": False, "error": "Zitadel organization response did not include an organization ID"}

    if org.domain:
        domain_result = await zitadel_mgmt.add_organization_domain(org.zitadel_org_id, org.domain)
        zitadel_result["domain"] = domain_result
        if not org.supported_domains:
            org.supported_domains = supported_domains_from_domain(org.domain)

    metadata_result = await zitadel_mgmt.set_organization_metadata(
        org.zitadel_org_id,
        build_probestack_org_metadata(org),
    )
    zitadel_result["metadata"] = metadata_result

    logger.info(f"Zitadel organization created for {org.name}: {org.zitadel_org_id}")
    return zitadel_result

async def provision_organization_in_auth0(org: OrganizationModel) -> dict:
    """Create the matching Auth0 organization and persist its ID on the local organization row."""
    if not auth0_mgmt.enabled:
        logger.info(f"Auth0 organization provisioning skipped for {org.name}: not configured")
        return {"success": False, "skipped": True, "error": "Auth0 is disabled"}
    if org.auth0_org_id:
        return {"success": True, "exists": True, "auth0_org_id": org.auth0_org_id}

    auth0_result = await auth0_mgmt.create_organization(
        org.name,
        {
            "probestack_org_id": org.id,
            "domain": org.domain or "",
            "external_org_id": org.external_org_id or "",
        },
    )
    if not auth0_result.get("success"):
        return auth0_result

    org.auth0_org_id = auth0_result.get("auth0_org_id")
    if not org.auth0_org_id:
        return {"success": False, "error": "Auth0 organization response did not include an organization ID"}

    connection_result = await auth0_mgmt.add_connection_to_organization(org.auth0_org_id)
    auth0_result["connection"] = connection_result
    if not connection_result.get("success") and not connection_result.get("skipped"):
        return {
            **auth0_result,
            "success": False,
            "error": connection_result.get("error") or "Failed to enable Auth0 organization connection",
        }

    if org.domain and not org.supported_domains:
        org.supported_domains = supported_domains_from_domain(org.domain)

    logger.info(f"Auth0 organization created for {org.name}: {org.auth0_org_id}")
    return auth0_result

async def provision_organization_for_active_provider(
    db: AsyncSession,
    org: OrganizationModel,
    provider: Optional[str] = None,
) -> dict:
    active_provider = normalize_identity_provider(provider or await get_active_identity_provider(db))
    require_identity_provider_configured(active_provider)
    if active_provider == "auth0":
        result = await provision_organization_in_auth0(org)
    else:
        result = await provision_organization_in_zitadel(org)
    result["identity_provider"] = active_provider
    return result

def should_skip_auth0(active_provider: Optional[str] = None, skip_auth0: bool = False) -> bool:
    provider = normalize_identity_provider(active_provider)
    return (not auth0_mgmt.enabled) or skip_auth0 or provider != "auth0"

async def provision_user_in_zitadel(
    user: UserModel,
    email: str,
    name: str,
    user_metadata: Optional[dict] = None,
    zitadel_org_id: Optional[str] = None,
    role_name: Optional[str] = None,
) -> dict:
    """Create or link the matching Zitadel user without blocking local DB creation."""
    if not zitadel_mgmt.enabled:
        logger.info(f"Zitadel provisioning skipped for {email}: not configured")
        return {"success": False, "skipped": True}

    zitadel_result = await zitadel_mgmt.create_user(
        email=email,
        name=name,
        user_metadata=user_metadata or {},
        organization_id=zitadel_org_id,
    )
    if zitadel_result.get("success"):
        user.zitadel_user_id = zitadel_result.get("zitadel_user_id")
        logger.info(f"Zitadel user created for {email}: {user.zitadel_user_id}")
        if user.zitadel_user_id and not zitadel_result.get("verification_email_sent"):
            await zitadel_mgmt.send_verification_email(user.zitadel_user_id)
    elif zitadel_result.get("exists"):
        existing_user = await zitadel_mgmt.get_user_by_email(email, zitadel_org_id)
        if existing_user.get("success"):
            user.zitadel_user_id = zitadel_mgmt._extract_user_id(existing_user.get("user", {}))
            logger.info(f"Zitadel user already exists for {email}: {user.zitadel_user_id}")
            if user.zitadel_user_id:
                await zitadel_mgmt.send_password_reset_email_by_user_id(user.zitadel_user_id)
                zitadel_result = {
                    **zitadel_result,
                    "success": True,
                    "zitadel_user_id": user.zitadel_user_id,
                    "user": existing_user.get("user"),
                }
    else:
        logger.warning(f"Failed to create Zitadel user for {email}: {zitadel_result.get('error')}")

    if user.zitadel_user_id and zitadel_org_id and role_name:
        role_assignment = await zitadel_mgmt.assign_user_roles(
            user.zitadel_user_id,
            zitadel_org_id,
            [zitadel_role_key_for_role(role_name)],
        )
        zitadel_result["role_assignment"] = role_assignment
        if not role_assignment.get("success") and not role_assignment.get("skipped"):
            logger.warning(
                f"Failed to assign Zitadel role for {email}: {role_assignment.get('error')}"
            )
    if user.zitadel_user_id:
        metadata_result = await zitadel_mgmt.set_user_metadata(user.zitadel_user_id, user_metadata or {})
        zitadel_result["metadata"] = metadata_result
        if not metadata_result.get("success") and not metadata_result.get("skipped"):
            logger.warning(
                f"Failed to set Zitadel user metadata for {email}: {metadata_result.get('error')}"
            )
    return zitadel_result

async def provision_user_in_auth0(
    user: UserModel,
    email: str,
    name: str,
    user_metadata: Optional[dict] = None,
    auth0_org_id: Optional[str] = None,
    role_name: Optional[str] = None,
) -> dict:
    """Create or link the matching Auth0 user and add it to the Auth0 organization."""
    if not auth0_mgmt.enabled:
        logger.info(f"Auth0 provisioning skipped for {email}: not configured")
        return {"success": False, "skipped": True, "error": "Auth0 is disabled"}

    auth0_result = await auth0_mgmt.create_user(
        email=email,
        name=name,
        user_metadata=user_metadata or {},
    )
    if auth0_result.get("success"):
        user.auth0_user_id = auth0_result.get("auth0_user_id")
        logger.info(f"Auth0 user created for {email}: {user.auth0_user_id}")
        if user.auth0_user_id:
            await auth0_mgmt.send_verification_email(user.auth0_user_id)
    elif auth0_result.get("exists"):
        existing_user = await auth0_mgmt.get_user_by_email(email)
        if existing_user.get("success"):
            user.auth0_user_id = existing_user["user"].get("user_id")
            logger.info(f"Auth0 user already exists for {email}: {user.auth0_user_id}")
            if user.auth0_user_id:
                await auth0_mgmt.send_verification_email(user.auth0_user_id)
                auth0_result = {
                    **auth0_result,
                    "success": True,
                    "auth0_user_id": user.auth0_user_id,
                    "user": existing_user.get("user"),
                }
    else:
        logger.warning(f"Failed to create Auth0 user for {email}: {auth0_result.get('error')}")

    if user.auth0_user_id and auth0_org_id:
        membership_result = await auth0_mgmt.add_user_to_organization(auth0_org_id, user.auth0_user_id)
        auth0_result["organization_membership"] = membership_result
        if not membership_result.get("success"):
            logger.warning(
                f"Failed to add Auth0 organization member for {email}: {membership_result.get('error')}"
            )
            return {
                **auth0_result,
                "success": False,
                "error": membership_result.get("error") or "Failed to add user to Auth0 organization",
            }

    return auth0_result

async def provision_user_for_active_provider(
    db: AsyncSession,
    user: UserModel,
    email: str,
    name: str,
    user_metadata: Optional[dict] = None,
    org: Optional[OrganizationModel] = None,
    role_name: Optional[str] = None,
    provider: Optional[str] = None,
) -> dict:
    active_provider = normalize_identity_provider(provider or await get_active_identity_provider(db))
    require_identity_provider_configured(active_provider)
    metadata = await build_probestack_user_metadata(
        db,
        user,
        email,
        org,
        role_name,
        user_metadata,
    )
    if active_provider == "auth0":
        result = await provision_user_in_auth0(
            user,
            email,
            name,
            metadata,
            org.auth0_org_id if org else None,
            role_name,
        )
        if not user.auth0_user_id:
            result = {
                **result,
                "success": False,
                "error": result.get("error") or "Auth0 user ID was not stored",
            }
    else:
        result = await provision_user_in_zitadel(
            user,
            email,
            name,
            metadata,
            org.zitadel_org_id if org else None,
            role_name,
        )
        if not user.zitadel_user_id:
            result = {
                **result,
                "success": False,
                "error": result.get("error") or "Zitadel user ID was not stored",
            }
    result["identity_provider"] = active_provider
    return result

async def create_invited_org_user(db: AsyncSession, org: OrganizationModel, email: str) -> UserModel:
    role = await get_or_create_default_org_role(db, org)
    role, onboarding_role_lookup = await resolve_new_user_role(db, org, email, role)
    user = UserModel(
        email=email,
        name=derive_name_from_email(email),
        organization_id=org.id,
        role_id=role.id,
        status="pending_verification",
        email_verified=False,
        password_set=False,
        first_login_token=secrets.token_urlsafe(32)
    )
    db.add(user)
    await db.flush()
    await replace_user_role_assignments(db, user, [role])

    active_provider = await get_active_identity_provider(db)
    if active_provider == "auth0" and not org.auth0_org_id and org.status == "approved":
        org_result = await provision_organization_in_auth0(org)
        if not org_result.get("success"):
            logger.warning(f"Failed to provision Auth0 organization for {org.name}: {org_result.get('error')}")
    elif active_provider == "zitadel" and not org.zitadel_org_id and org.status == "approved":
        org_result = await provision_organization_in_zitadel(org)
        if not org_result.get("success"):
            logger.warning(f"Failed to provision Zitadel organization for {org.name}: {org_result.get('error')}")

    await provision_user_for_active_provider(
        db,
        user,
        email,
        user.name,
        {
            "probestack_user_id": user.id,
            "organization_id": org.id,
            "organization_name": org.name,
        },
        org,
        role.name,
        active_provider,
    )

    return user

def build_setup_account_url(email: str, token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    return f"{APP_URL.rstrip('/')}/setup-account?{urlencode({'email': email, 'token': token})}"

def build_login_url() -> str:
    return f"{APP_URL.rstrip('/')}/admin/login"

def normalize_email_recipients(recipients: Any) -> List[str]:
    if not recipients:
        return []
    if isinstance(recipients, str):
        raw_recipients = recipients.replace(";", ",").split(",")
    else:
        raw_recipients = []
        for recipient in recipients:
            if isinstance(recipient, str):
                raw_recipients.extend(recipient.replace(";", ",").split(","))
    normalized = []
    seen = set()
    for recipient in raw_recipients:
        email = recipient.strip()
        email_key = email.lower()
        if email and email_key not in seen:
            normalized.append(email)
            seen.add(email_key)
    return normalized

async def ensure_notification_group_seeded(db: AsyncSession) -> None:
    setting_key = "notification_group_initialized"
    setting_result = await db.execute(select(SystemSettingModel).where(SystemSettingModel.key == setting_key))
    if setting_result.scalar_one_or_none():
        return
    for email in normalize_email_recipients(ORG_REQUEST_NOTIFICATION_EMAILS):
        existing_result = await db.execute(
            select(NotificationGroupEmailModel).where(func.lower(NotificationGroupEmailModel.email) == email.lower())
        )
        if not existing_result.scalar_one_or_none():
            db.add(NotificationGroupEmailModel(email=email, is_active=True))
    db.add(SystemSettingModel(key=setting_key, value="true"))
    await db.flush()

async def get_notification_group_emails(db: AsyncSession, *, active_only: bool = True) -> List[str]:
    await ensure_notification_group_seeded(db)
    query = select(NotificationGroupEmailModel)
    if active_only:
        query = query.where(NotificationGroupEmailModel.is_active == True)
    result = await db.execute(query.order_by(NotificationGroupEmailModel.created_at.asc()))
    return normalize_email_recipients([entry.email for entry in result.scalars().all()])

async def get_org_admin_emails(db: AsyncSession, organization_id: str) -> List[str]:
    result = await db.execute(
        select(AdminModel.email)
        .where(AdminModel.organization_id == organization_id)
        .where(AdminModel.role == "org_admin")
        .where(AdminModel.is_active == True)
        .order_by(AdminModel.created_at.asc())
    )
    return normalize_email_recipients(result.scalars().all())

async def get_billing_invoice_recipient_options(db: AsyncSession, organization_id: str) -> List[dict]:
    recipients = {}
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == organization_id))
    organization = org_result.scalar_one_or_none()
    if organization and organization.email:
        recipients[organization.email.lower()] = {
            "email": organization.email,
            "name": organization.name,
            "type": "organization",
            "label": f"{organization.name} ({organization.email}) - Organization",
        }
    admin_result = await db.execute(
        select(AdminModel)
        .where(AdminModel.organization_id == organization_id)
        .where(AdminModel.is_active == True)
        .order_by(AdminModel.name.asc(), AdminModel.email.asc())
    )
    for admin in admin_result.scalars().all():
        recipients[admin.email.lower()] = {
            "email": admin.email,
            "name": admin.name,
            "type": "org_admin",
            "label": f"{admin.name} ({admin.email}) - Org Admin",
        }
    user_result = await db.execute(
        select(UserModel)
        .where(UserModel.organization_id == organization_id)
        .order_by(UserModel.name.asc(), UserModel.email.asc())
    )
    for user in user_result.scalars().all():
        recipients.setdefault(user.email.lower(), {
            "email": user.email,
            "name": user.name,
            "type": "user",
            "label": f"{user.name} ({user.email}) - User",
        })
    return list(recipients.values())

def send_email(
    to_email: Any,
    subject: str,
    text_body: str,
    html_body: Optional[str] = None,
    cc_email: Optional[Any] = None,
    bcc_email: Optional[Any] = None,
    attachments: Optional[List[dict]] = None
) -> dict:
    to_emails = normalize_email_recipients(to_email)
    cc_emails = normalize_email_recipients(cc_email)
    bcc_emails = normalize_email_recipients(bcc_email)
    to_keys = {email.lower() for email in to_emails}
    cc_emails = [email for email in cc_emails if email.lower() not in to_keys]
    cc_keys = {email.lower() for email in cc_emails}
    bcc_emails = [email for email in bcc_emails if email.lower() not in to_keys and email.lower() not in cc_keys]
    if not to_emails:
        logger.warning("Skipped email with no recipients. Subject: %s", subject)
        return {
            "sent": False,
            "reason": "No recipients",
            "to": [],
            "cc": [],
            "bcc": []
        }

    to_header = ", ".join(to_emails)
    cc_header = ", ".join(cc_emails)
    bcc_header = ", ".join(bcc_emails)

    if SENDGRID_API_KEY and SENDGRID_FROM_EMAIL:
        payload = {
            "personalizations": [{
                "to": [{"email": email} for email in to_emails],
            }],
            "from": {
                "email": SENDGRID_FROM_EMAIL,
                "name": SENDGRID_FROM_NAME,
            },
            "subject": subject,
            "content": [{
                "type": "text/plain",
                "value": text_body,
            }],
        }
        if cc_emails:
            payload["personalizations"][0]["cc"] = [{"email": email} for email in cc_emails]
        if bcc_emails:
            payload["personalizations"][0]["bcc"] = [{"email": email} for email in bcc_emails]
        if html_body:
            payload["content"].append({
                "type": "text/html",
                "value": html_body,
            })
        if attachments:
            payload["attachments"] = [
                {
                    "content": base64.b64encode(attachment["content"]).decode("ascii"),
                    "filename": attachment["filename"],
                    "type": attachment.get("type", "application/octet-stream"),
                    "disposition": attachment.get("disposition", "attachment"),
                }
                for attachment in attachments
                if attachment.get("content") and attachment.get("filename")
            ]

        try:
            response = httpx.post(
                SENDGRID_API_URL,
                headers={
                    "Authorization": f"Bearer {SENDGRID_API_KEY}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=15,
            )
            if 200 <= response.status_code < 300:
                logger.info("SendGrid email sent to %s. Cc: %s. Bcc: %s. Subject: %s", to_header, cc_header or "-", bcc_header or "-", subject)
                return {"sent": True, "provider": "sendgrid", "to": to_emails, "cc": cc_emails, "bcc": bcc_emails}
            logger.error(
                "SendGrid email failed to %s. Cc: %s. Bcc: %s. Subject: %s. Status: %s. Response: %s",
                to_header,
                cc_header or "-",
                bcc_header or "-",
                subject,
                response.status_code,
                response.text[:500],
            )
            return {
                "sent": False,
                "provider": "sendgrid",
                "reason": f"SendGrid returned {response.status_code}: {response.text[:500]}",
                "to": to_emails,
                "cc": cc_emails,
                "bcc": bcc_emails,
            }
        except Exception as exc:
            logger.error("SendGrid email error to %s. Cc: %s. Bcc: %s. Subject: %s. Error: %s", to_header, cc_header or "-", bcc_header or "-", subject, exc)
            return {
                "sent": False,
                "provider": "sendgrid",
                "reason": str(exc),
                "to": to_emails,
                "cc": cc_emails,
                "bcc": bcc_emails,
            }

    if not SMTP_HOST or not SMTP_FROM_EMAIL:
        logger.warning(
            "SMTP not configured; skipped email to %s. Subject: %s",
            to_header,
            subject
        )
        return {
            "sent": False,
            "reason": "SMTP not configured",
            "to": to_emails,
            "cc": cc_emails,
            "bcc": bcc_emails
        }

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    message["To"] = to_header
    if cc_header:
        message["Cc"] = cc_header
    if bcc_header:
        message["Bcc"] = bcc_header
    message.set_content(text_body)
    if html_body:
        message.add_alternative(html_body, subtype="html")
    for attachment in attachments or []:
        content = attachment.get("content")
        filename = attachment.get("filename")
        if not content or not filename:
            continue
        content_type = attachment.get("type", "application/octet-stream")
        maintype, _, subtype = content_type.partition("/")
        message.add_attachment(
            content,
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=filename,
        )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            if SMTP_USE_TLS:
                smtp.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)
        logger.info("Email sent to %s. Cc: %s. Bcc: %s. Subject: %s", to_header, cc_header or "-", bcc_header or "-", subject)
        return {"sent": True, "to": to_emails, "cc": cc_emails, "bcc": bcc_emails}
    except Exception as exc:
        logger.error("Failed to send email to %s. Cc: %s. Bcc: %s. Subject: %s. Error: %s", to_header, cc_header or "-", bcc_header or "-", subject, exc)
        return {
            "sent": False,
            "reason": str(exc),
            "to": to_emails,
            "cc": cc_emails,
            "bcc": bcc_emails
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

def send_new_organization_request_email(
    *,
    request_id: str,
    organization_name: str,
    organization_email: str,
    domain: str,
    contact_person: str,
    contact_phone: str,
    company_address: str,
    description: str,
    additional_notes: Optional[str],
    plans: str,
    selected_tools: str,
    notification_emails: Optional[List[str]] = None
) -> dict:
    review_url = f"{APP_URL.rstrip('/')}/admin/pending-organizations"
    subject = f"New ProbeStack organization request: {organization_name}"
    plan_text = plans or "No plan selected"
    tools_text = selected_tools or ""
    notes_text = additional_notes or "None"
    safe_review_url = escape(review_url, quote=True)
    safe_organization_name = escape(organization_name)
    safe_request_id = escape(request_id)
    safe_organization_email = escape(organization_email)
    safe_domain = escape(domain)
    safe_contact_person = escape(contact_person)
    safe_contact_phone = escape(contact_phone)
    safe_company_address = escape(company_address)
    safe_plan_html = "<br>".join(escape(line) for line in plan_text.splitlines() if line.strip()) or "No plan selected"
    safe_tools_text = escape(tools_text)
    tools_text_line = f"Tools: {tools_text}" if tools_text else "Tools: None selected"
    tools_row_html = f"""
            <tr>
              <td style="padding:10px 0;color:#64748b;">Tools</td>
              <td style="padding:10px 0;color:#172033;">{safe_tools_text}</td>
            </tr>
    """ if tools_text else ""
    safe_description = escape(description)
    safe_notes_text = escape(notes_text)
    text_body = "\n".join([
        "A new organization request is waiting in the ProbeStack admin panel.",
        "",
        f"Organization: {organization_name}",
        f"Request ID: {request_id}",
        f"Email: {organization_email}",
        f"Domain: {domain}",
        f"Contact: {contact_person}",
        f"Phone: {contact_phone}",
        f"Address: {company_address}",
        f"Plans: {plan_text}",
        tools_text_line,
        "",
        "Description:",
        description,
        "",
        "Additional notes:",
        notes_text,
        "",
        f"Review request: {review_url}",
        "",
        "ProbeStack"
    ])
    html_body = f"""
    <div style="margin:0;background:#f6f8fb;padding:28px 0;font-family:Arial,Helvetica,sans-serif;color:#172033;">
      <div style="max-width:680px;margin:0 auto;background:#ffffff;border:1px solid #e6ebf2;border-radius:14px;overflow:hidden;">
        <div style="background:#0f172a;padding:26px 30px;color:#ffffff;">
          <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#93c5fd;font-weight:700;">ProbeStack Admin</div>
          <h1 style="margin:10px 0 0;font-size:24px;line-height:1.3;font-weight:700;">New organization request received</h1>
          <p style="margin:10px 0 0;color:#cbd5e1;font-size:15px;">{safe_organization_name} is waiting for review in the admin panel.</p>
        </div>

        <div style="padding:28px 30px;">
          <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:14px;">
            <tr>
              <td style="padding:10px 0;color:#64748b;width:155px;">Organization</td>
              <td style="padding:10px 0;font-weight:700;color:#172033;">{safe_organization_name}</td>
            </tr>
            <tr>
              <td style="padding:10px 0;color:#64748b;">Request ID</td>
              <td style="padding:10px 0;font-family:Consolas,Monaco,monospace;color:#172033;">{safe_request_id}</td>
            </tr>
            <tr>
              <td style="padding:10px 0;color:#64748b;">Contact</td>
              <td style="padding:10px 0;color:#172033;">{safe_contact_person} &lt;{safe_organization_email}&gt;</td>
            </tr>
            <tr>
              <td style="padding:10px 0;color:#64748b;">Phone</td>
              <td style="padding:10px 0;color:#172033;">{safe_contact_phone}</td>
            </tr>
            <tr>
              <td style="padding:10px 0;color:#64748b;">Domain</td>
              <td style="padding:10px 0;color:#172033;">{safe_domain}</td>
            </tr>
            <tr>
              <td style="padding:10px 0;color:#64748b;">Plans</td>
              <td style="padding:10px 0;color:#172033;font-weight:700;line-height:1.6;">{safe_plan_html}</td>
            </tr>
            {tools_row_html}
          </table>

          <div style="margin-top:18px;padding:16px;border-radius:10px;background:#f8fafc;border:1px solid #e2e8f0;">
            <div style="font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;font-weight:700;">Company address</div>
            <p style="margin:8px 0 0;font-size:14px;line-height:1.6;color:#172033;">{safe_company_address}</p>
          </div>

          <div style="margin-top:14px;padding:16px;border-radius:10px;background:#f8fafc;border:1px solid #e2e8f0;">
            <div style="font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;font-weight:700;">Description</div>
            <p style="margin:8px 0 0;font-size:14px;line-height:1.6;color:#172033;">{safe_description}</p>
          </div>

          <div style="margin-top:14px;padding:16px;border-radius:10px;background:#f8fafc;border:1px solid #e2e8f0;">
            <div style="font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;font-weight:700;">Additional notes</div>
            <p style="margin:8px 0 0;font-size:14px;line-height:1.6;color:#172033;">{safe_notes_text}</p>
          </div>

          <div style="margin-top:26px;">
            <a href="{safe_review_url}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;font-weight:700;padding:12px 18px;border-radius:8px;font-size:14px;">Review in admin panel</a>
          </div>
        </div>

        <div style="border-top:1px solid #e6ebf2;padding:18px 30px;color:#64748b;font-size:12px;background:#fbfdff;">
          This notification was sent to the ProbeStack admin email group.
        </div>
      </div>
    </div>
    """
    recipients = normalize_email_recipients(notification_emails) or normalize_email_recipients(ORG_REQUEST_NOTIFICATION_EMAILS)
    return send_email(recipients, subject, text_body, html_body)

def send_organization_approval_email(
    *,
    organization_name: str,
    organization_email: str,
    contact_person: str,
    notification_emails: Optional[List[str]] = None
) -> dict:
    subject = f"Your ProbeStack organization request has been approved"
    greeting_name = contact_person or organization_name
    safe_greeting_name = escape(greeting_name)
    safe_organization_name = escape(organization_name)
    text_body = "\n".join([
        f"Hi {greeting_name},",
        "",
        f"Good news - your organization request for {organization_name} has been approved.",
        "",
        "We would like to schedule a meeting to discuss your requirements, onboarding details, and next steps.",
        "",
        "Please reply to this email with a few suitable time slots, and our team will coordinate the meeting.",
        "",
        "ProbeStack"
    ])
    html_body = f"""
    <div style="margin:0;background:#f6f8fb;padding:28px 0;font-family:Arial,Helvetica,sans-serif;color:#172033;">
      <div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #e6ebf2;border-radius:14px;overflow:hidden;">
        <div style="background:#064e3b;padding:28px 30px;color:#ffffff;">
          <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#a7f3d0;font-weight:700;">ProbeStack</div>
          <h1 style="margin:10px 0 0;font-size:24px;line-height:1.3;font-weight:700;">Your organization request is approved</h1>
          <p style="margin:10px 0 0;color:#d1fae5;font-size:15px;">We are ready to move forward with {safe_organization_name}.</p>
        </div>

        <div style="padding:30px;">
          <p style="margin:0 0 16px;font-size:16px;line-height:1.6;">Hi {safe_greeting_name},</p>
          <p style="margin:0 0 16px;font-size:16px;line-height:1.6;">Good news - your organization request for <strong>{safe_organization_name}</strong> has been approved.</p>
          <p style="margin:0 0 18px;font-size:16px;line-height:1.6;">We would like to schedule a meeting to discuss your requirements, onboarding details, and next steps.</p>

          <div style="padding:16px 18px;border-radius:10px;background:#ecfdf5;border:1px solid #bbf7d0;margin:22px 0;">
            <div style="font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#047857;font-weight:700;">Next step</div>
            <p style="margin:8px 0 0;font-size:15px;line-height:1.6;color:#172033;">Please reply to this email with a few suitable time slots, and our team will coordinate the meeting.</p>
          </div>

          <p style="margin:22px 0 0;font-size:15px;line-height:1.6;color:#475569;">Thank you,<br><strong>ProbeStack Team</strong></p>
        </div>

        <div style="border-top:1px solid #e6ebf2;padding:18px 30px;color:#64748b;font-size:12px;background:#fbfdff;">
          ProbeStack will coordinate the follow-up meeting with your team.
        </div>
      </div>
    </div>
    """
    return send_email(
        organization_email,
        subject,
        text_body,
        html_body,
        bcc_email=normalize_email_recipients(notification_emails) or normalize_email_recipients(ORG_APPROVAL_CC_EMAILS)
    )

def send_request_decision_email(
    *,
    to_email: str,
    recipient_name: str,
    request_name: str,
    status: str,
    organization_name: Optional[str] = None,
    reason: Optional[str] = None,
    next_steps: Optional[str] = None,
    action_url: Optional[str] = None,
    notification_emails: Optional[List[str]] = None
) -> dict:
    normalized_status = (status or "").strip().lower()
    is_approved = normalized_status == "approved"
    status_label = "approved" if is_approved else "rejected"
    subject = f"Your ProbeStack {request_name} has been {status_label}"
    safe_recipient_name = escape(recipient_name or "there")
    safe_request_name = escape(request_name)
    safe_status_label = escape(status_label)
    safe_organization_name = escape(organization_name or "ProbeStack")
    safe_reason = escape(reason or "No reason was provided.")
    safe_next_steps = escape(next_steps or ("We will follow up with next steps shortly." if is_approved else "You can reply to this email if you have questions or would like to discuss this decision."))
    safe_action_url = escape(action_url or "", quote=True)
    header_color = "#064e3b" if is_approved else "#7f1d1d"
    accent_color = "#a7f3d0" if is_approved else "#fecaca"
    panel_bg = "#ecfdf5" if is_approved else "#fef2f2"
    panel_border = "#bbf7d0" if is_approved else "#fecaca"
    panel_label = "Next step" if is_approved else "Reason"
    panel_text = safe_next_steps if is_approved else safe_reason
    status_sentence = (
        f"Your {request_name} for {organization_name or 'ProbeStack'} has been approved."
        if is_approved
        else f"Your {request_name} for {organization_name or 'ProbeStack'} has been rejected."
    )
    action_line = f"Open ProbeStack: {action_url}" if action_url else ""
    text_lines = [
        f"Hi {recipient_name or 'there'},",
        "",
        status_sentence,
        "",
    ]
    if is_approved:
        text_lines.extend(["Next step:", next_steps or "We will follow up with next steps shortly."])
    else:
        text_lines.extend(["Reason:", reason or "No reason was provided."])
        text_lines.extend(["", "You can reply to this email if you have questions or would like to discuss this decision."])
    if action_line:
        text_lines.extend(["", action_line])
    text_lines.extend(["", "ProbeStack"])
    action_html = f"""
          <div style="margin-top:22px;">
            <a href="{safe_action_url}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;font-weight:700;padding:12px 18px;border-radius:8px;font-size:14px;">Open ProbeStack</a>
          </div>
    """ if action_url else ""
    html_body = f"""
    <div style="margin:0;background:#f6f8fb;padding:28px 0;font-family:Arial,Helvetica,sans-serif;color:#172033;">
      <div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #e6ebf2;border-radius:14px;overflow:hidden;">
        <div style="background:{header_color};padding:28px 30px;color:#ffffff;">
          <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:{accent_color};font-weight:700;">ProbeStack</div>
          <h1 style="margin:10px 0 0;font-size:24px;line-height:1.3;font-weight:700;">Request {safe_status_label}</h1>
          <p style="margin:10px 0 0;color:{accent_color};font-size:15px;">Your {safe_request_name} for {safe_organization_name} has been {safe_status_label}.</p>
        </div>

        <div style="padding:30px;">
          <p style="margin:0 0 16px;font-size:16px;line-height:1.6;">Hi {safe_recipient_name},</p>
          <p style="margin:0 0 18px;font-size:16px;line-height:1.6;">Your <strong>{safe_request_name}</strong> for <strong>{safe_organization_name}</strong> has been <strong>{safe_status_label}</strong>.</p>

          <div style="padding:16px 18px;border-radius:10px;background:{panel_bg};border:1px solid {panel_border};margin:22px 0;">
            <div style="font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#475569;font-weight:700;">{panel_label}</div>
            <p style="margin:8px 0 0;font-size:15px;line-height:1.6;color:#172033;">{panel_text}</p>
          </div>

          {action_html}

          <p style="margin:22px 0 0;font-size:15px;line-height:1.6;color:#475569;">Thank you,<br><strong>ProbeStack Team</strong></p>
        </div>
      </div>
    </div>
    """
    return send_email(
        to_email,
        subject,
        "\n".join(text_lines),
        html_body,
        bcc_email=notification_emails,
    )

def send_plan_upgrade_request_email(
    *,
    organization_name: str,
    request_id: str,
    requested_by_email: Optional[str],
    requested_details: List[dict],
    reason: Optional[str],
    notification_emails: List[str]
) -> dict:
    review_url = f"{APP_URL.rstrip('/')}/admin/upgrade-requests"
    subject = f"Plan upgrade request: {organization_name}"
    plan_lines = [
        f"{detail.get('product').name if detail.get('product') else 'Product'}:{detail.get('plan').name if detail.get('plan') else detail.get('selection').plan_id}"
        for detail in requested_details
    ]
    requested_text = "\n".join(plan_lines) or "No plan details available"
    tools_lines = []
    for detail in requested_details:
        tools = detail.get("tools") or []
        tools_lines.append(f"{detail.get('product').name if detail.get('product') else 'Product'} tools: {', '.join(tools) if tools else 'No tools selected'}")
    tools_text = "\n".join(tools_lines)
    safe_organization_name = escape(organization_name)
    safe_request_id = escape(request_id)
    safe_requested_by = escape(requested_by_email or "Org admin")
    safe_requested_html = "<br>".join(escape(line) for line in requested_text.splitlines())
    safe_tools_html = "<br>".join(escape(line) for line in tools_text.splitlines())
    safe_reason = escape(reason or "No reason provided")
    safe_review_url = escape(review_url, quote=True)
    text_body = "\n".join([
        "A plan upgrade request is waiting for review.",
        "",
        f"Organization: {organization_name}",
        f"Request ID: {request_id}",
        f"Requested by: {requested_by_email or 'Org admin'}",
        "",
        "Requested plans:",
        requested_text,
        "",
        "Selected tools:",
        tools_text or "No tools selected",
        "",
        "Reason:",
        reason or "No reason provided",
        "",
        f"Review request: {review_url}",
        "",
        "ProbeStack"
    ])
    html_body = f"""
    <div style="margin:0;background:#f6f8fb;padding:28px 0;font-family:Arial,Helvetica,sans-serif;color:#172033;">
      <div style="max-width:680px;margin:0 auto;background:#ffffff;border:1px solid #e6ebf2;border-radius:14px;overflow:hidden;">
        <div style="background:#1e293b;padding:26px 30px;color:#ffffff;">
          <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#bae6fd;font-weight:700;">ProbeStack Admin</div>
          <h1 style="margin:10px 0 0;font-size:24px;line-height:1.3;font-weight:700;">Plan upgrade request received</h1>
          <p style="margin:10px 0 0;color:#dbeafe;font-size:15px;">{safe_organization_name} requested a subscription change.</p>
        </div>
        <div style="padding:28px 30px;">
          <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:14px;">
            <tr><td style="padding:10px 0;color:#64748b;width:150px;">Organization</td><td style="padding:10px 0;font-weight:700;color:#172033;">{safe_organization_name}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;">Request ID</td><td style="padding:10px 0;font-family:Consolas,Monaco,monospace;color:#172033;">{safe_request_id}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;">Requested by</td><td style="padding:10px 0;color:#172033;">{safe_requested_by}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;">Plans</td><td style="padding:10px 0;color:#172033;font-weight:700;line-height:1.6;">{safe_requested_html}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;">Tools</td><td style="padding:10px 0;color:#172033;line-height:1.6;">{safe_tools_html or 'No tools selected'}</td></tr>
          </table>
          <div style="margin-top:16px;padding:16px;border-radius:10px;background:#f8fafc;border:1px solid #e2e8f0;">
            <div style="font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;font-weight:700;">Reason</div>
            <p style="margin:8px 0 0;font-size:14px;line-height:1.6;color:#172033;">{safe_reason}</p>
          </div>
          <div style="margin-top:24px;">
            <a href="{safe_review_url}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;font-weight:700;padding:12px 18px;border-radius:8px;font-size:14px;">Review upgrade request</a>
          </div>
        </div>
      </div>
    </div>
    """
    return send_email(notification_emails, subject, text_body, html_body)

def send_user_request_admin_email(
    *,
    organization_name: str,
    request_id: str,
    requester_name: str,
    requester_email: str,
    requested_role: str,
    job_title: Optional[str],
    department: Optional[str],
    phone: Optional[str],
    notes: Optional[str],
    to_emails: List[str],
    notification_emails: List[str]
) -> dict:
    review_url = f"{APP_URL.rstrip('/')}/admin/my-user-requests"
    subject = f"New user request for {organization_name}: {requester_name}"
    safe_organization_name = escape(organization_name)
    safe_requester_name = escape(requester_name)
    safe_requester_email = escape(requester_email)
    safe_requested_role = escape(requested_role)
    safe_request_id = escape(request_id)
    safe_job_title = escape(job_title or "Not provided")
    safe_department = escape(department or "Not provided")
    safe_phone = escape(phone or "Not provided")
    safe_notes = escape(notes or "None")
    safe_review_url = escape(review_url, quote=True)
    text_body = "\n".join([
        f"A user request is waiting for approval in {organization_name}.",
        "",
        f"Name: {requester_name}",
        f"Email: {requester_email}",
        f"Requested role: {requested_role}",
        f"Job title: {job_title or 'Not provided'}",
        f"Department: {department or 'Not provided'}",
        f"Phone: {phone or 'Not provided'}",
        "",
        "Notes:",
        notes or "None",
        "",
        f"Review request: {review_url}",
        "",
        "ProbeStack"
    ])
    html_body = f"""
    <div style="margin:0;background:#f6f8fb;padding:28px 0;font-family:Arial,Helvetica,sans-serif;color:#172033;">
      <div style="max-width:660px;margin:0 auto;background:#ffffff;border:1px solid #e6ebf2;border-radius:14px;overflow:hidden;">
        <div style="background:#0f766e;padding:26px 30px;color:#ffffff;">
          <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#ccfbf1;font-weight:700;">ProbeStack Approval</div>
          <h1 style="margin:10px 0 0;font-size:24px;line-height:1.3;font-weight:700;">New user request</h1>
          <p style="margin:10px 0 0;color:#ccfbf1;font-size:15px;">{safe_requester_name} requested access to {safe_organization_name}.</p>
        </div>
        <div style="padding:28px 30px;">
          <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:14px;">
            <tr><td style="padding:10px 0;color:#64748b;width:150px;">Request ID</td><td style="padding:10px 0;font-family:Consolas,Monaco,monospace;color:#172033;">{safe_request_id}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;">Name</td><td style="padding:10px 0;font-weight:700;color:#172033;">{safe_requester_name}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;">Email</td><td style="padding:10px 0;color:#172033;">{safe_requester_email}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;">Requested role</td><td style="padding:10px 0;color:#172033;font-weight:700;">{safe_requested_role}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;">Job title</td><td style="padding:10px 0;color:#172033;">{safe_job_title}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;">Department</td><td style="padding:10px 0;color:#172033;">{safe_department}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;">Phone</td><td style="padding:10px 0;color:#172033;">{safe_phone}</td></tr>
          </table>
          <div style="margin-top:16px;padding:16px;border-radius:10px;background:#f8fafc;border:1px solid #e2e8f0;">
            <div style="font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;font-weight:700;">Notes</div>
            <p style="margin:8px 0 0;font-size:14px;line-height:1.6;color:#172033;">{safe_notes}</p>
          </div>
          <div style="margin-top:24px;">
            <a href="{safe_review_url}" style="display:inline-block;background:#0f766e;color:#ffffff;text-decoration:none;font-weight:700;padding:12px 18px;border-radius:8px;font-size:14px;">Review user request</a>
          </div>
        </div>
      </div>
    </div>
    """
    to_recipients = normalize_email_recipients(to_emails) or normalize_email_recipients(notification_emails)
    return send_email(to_recipients, subject, text_body, html_body, bcc_email=notification_emails)

def send_billing_invoice_email(
    *,
    organization_name: str,
    invoice_number: str,
    amount: float,
    due_date: datetime,
    to_emails: List[str],
    notification_emails: List[str],
    pdf_contents: bytes
) -> dict:
    subject = f"ProbeStack invoice {invoice_number}"
    safe_organization_name = escape(organization_name)
    safe_invoice_number = escape(invoice_number)
    due_date_text = due_date.strftime("%Y-%m-%d")
    amount_text = f"${amount:,.2f}"
    text_body = "\n".join([
        f"Hi {organization_name},",
        "",
        f"Please find attached ProbeStack invoice {invoice_number}.",
        f"Amount due: {amount_text}",
        f"Due date: {due_date_text}",
        "",
        "If you have questions about this invoice, please reply to this email.",
        "",
        "ProbeStack"
    ])
    html_body = f"""
    <div style="margin:0;background:#f6f8fb;padding:28px 0;font-family:Arial,Helvetica,sans-serif;color:#172033;">
      <div style="max-width:620px;margin:0 auto;background:#ffffff;border:1px solid #e6ebf2;border-radius:14px;overflow:hidden;">
        <div style="background:#0f172a;padding:26px 30px;color:#ffffff;">
          <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#fde68a;font-weight:700;">ProbeStack Billing</div>
          <h1 style="margin:10px 0 0;font-size:24px;line-height:1.3;font-weight:700;">Invoice {safe_invoice_number}</h1>
          <p style="margin:10px 0 0;color:#e2e8f0;font-size:15px;">Billing document for {safe_organization_name}</p>
        </div>
        <div style="padding:28px 30px;">
          <p style="margin:0 0 16px;font-size:16px;line-height:1.6;">Please find the invoice attached as a PDF.</p>
          <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:14px;">
            <tr><td style="padding:10px 0;color:#64748b;width:130px;">Amount due</td><td style="padding:10px 0;font-weight:700;color:#172033;">{amount_text}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;">Due date</td><td style="padding:10px 0;color:#172033;">{due_date_text}</td></tr>
          </table>
          <p style="margin:18px 0 0;font-size:15px;line-height:1.6;color:#475569;">If you have questions about this invoice, please reply to this email.</p>
        </div>
      </div>
    </div>
    """
    return send_email(
        to_emails,
        subject,
        text_body,
        html_body,
        bcc_email=notification_emails,
        attachments=[{
            "filename": f"{invoice_number}.pdf",
            "type": "application/pdf",
            "content": pdf_contents,
        }],
    )

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
    organization_name = await get_organization_name(db, admin.organization_id)
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
        "organization_name": await get_organization_name(db, admin.organization_id),
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
            "organization_name": await get_organization_name(db, user.organization_id),
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
    if user.zitadel_user_id:
        await zitadel_mgmt.verify_user_email(user.zitadel_user_id)
    
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
    
    # Update password in Auth0 only when Auth0 is enabled.
    if auth0_mgmt.enabled and user.auth0_user_id:
        auth0_result = await auth0_mgmt.update_user_password(user.auth0_user_id, password)
        if not auth0_result.get("success"):
            raise HTTPException(
                status_code=500, 
                detail=f"Failed to set password in Auth0: {auth0_result.get('error')}"
            )
    if user.zitadel_user_id:
        zitadel_result = await zitadel_mgmt.update_user_password(user.zitadel_user_id, password)
        if not zitadel_result.get("success"):
            raise HTTPException(
                status_code=500,
                detail=f"Failed to set password in Zitadel: {zitadel_result.get('error')}"
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

    # Ensure Auth0 user exists only when Auth0 is enabled.
    if auth0_mgmt.enabled and not user.auth0_user_id:
        auth0_user = await auth0_mgmt.get_user_by_email(email)
        if auth0_user.get("success"):
            user.auth0_user_id = auth0_user["user"]["user_id"]
            await db.commit()
        else:
            logger.warning(f"No Auth0 account found for {email}")
            if not user.zitadel_user_id:
                return success_message

    # Trigger Auth0 password reset email only when Auth0 is enabled.
    if auth0_mgmt.enabled and user.auth0_user_id:
        reset_result = await auth0_mgmt.send_password_reset_email(email)
        if reset_result.get("success"):
            logger.info(f"Password reset email sent to: {email}")
        else:
            logger.error(
                f"Failed to send password reset email to {email}: "
                f"{reset_result.get('error')}"
            )

    if not user.zitadel_user_id:
        zitadel_user = await zitadel_mgmt.get_user_by_email(email)
        if zitadel_user.get("success"):
            user.zitadel_user_id = zitadel_mgmt._extract_user_id(zitadel_user["user"])
            await db.commit()

    if user.zitadel_user_id:
        zitadel_reset_result = await zitadel_mgmt.send_password_reset_email(email)
        if zitadel_reset_result.get("success"):
            logger.info(f"Zitadel password reset email sent to: {email}")
        else:
            logger.error(
                f"Failed to send Zitadel password reset email to {email}: "
                f"{zitadel_reset_result.get('error')}"
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
        "organization_name": await get_organization_name(db, admin.organization_id),
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

@api_router.put("/my-organization", tags=["Org Admin"])
async def update_my_organization(
    data: OrganizationUpdate,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update onboarding fields for the current organization."""
    org = await get_approved_org_for_admin(payload, db)
    update_data = {k: v for k, v in payload_dict(data, exclude_unset=True).items() if v is not None}
    if "supported_domains" in update_data and isinstance(update_data["supported_domains"], list):
        update_data["supported_domains"] = json.dumps(update_data["supported_domains"])
    if "gateway_environments" in update_data and isinstance(update_data["gateway_environments"], list):
        update_data["gateway_environments"] = json.dumps(update_data["gateway_environments"])
    if "name" in update_data:
        update_data["name"] = update_data["name"].strip()
        if not update_data["name"]:
            raise HTTPException(status_code=400, detail="Organization name is required")
    if "domain" in update_data:
        update_data["domain"] = update_data["domain"].strip() if update_data["domain"] else None
        if update_data["domain"] and not org.supported_domains:
            org.supported_domains = supported_domains_from_domain(update_data["domain"])

    for key, value in update_data.items():
        if hasattr(org, key):
            setattr(org, key, normalize_onboarding_value(key, value))
    org.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"message": "Organization updated successfully", "organization": await organization_to_dict(db, org)}

@api_router.get("/my-organization/subscription", tags=["Org Admin"])
async def get_my_subscription(payload: dict = Depends(require_any_admin), db: AsyncSession = Depends(get_db)):
    """Get current organization's subscription (org admin only)"""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins don't have an organization")
    
    org_id = payload.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization linked to this account")
    
    result = await db.execute(
        valid_subscription_query()
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
    
    await ensure_standard_roles_for_organization(db, org_id)
    await db.commit()
    result = await db.execute(
        select(RoleModel)
        .where(RoleModel.organization_id.is_(None))
        .order_by(RoleModel.name.asc())
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
    response = [await business_unit_to_dict(db, bu) for bu in business_units]

    if include_projects and business_units:
        bu_ids = [bu.id for bu in business_units]
        projects_result = await db.execute(
            select(ProjectModel)
            .where(ProjectModel.organization_id == org.id, ProjectModel.business_unit_id.in_(bu_ids))
            .order_by(ProjectModel.name.asc())
        )
        projects_by_bu = {}
        for project in projects_result.scalars().all():
            projects_by_bu.setdefault(project.business_unit_id, []).append(await project_to_dict(db, project))

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

    return {
        "message": "Business unit created successfully",
        "business_unit": await business_unit_to_dict(db, business_unit),
    }

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
    response = await business_unit_to_dict(db, business_unit)
    response["projects"] = [await project_to_dict(db, project) for project in projects_result.scalars().all()]
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

    update_data = payload_dict(data, exclude_unset=True)
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
        if hasattr(business_unit, key):
            setattr(business_unit, key, normalize_onboarding_value(key, value))
    await upsert_business_unit_quotas(db, business_unit.id, update_data)
    business_unit.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {
        "message": "Business unit updated successfully",
        "business_unit": await business_unit_to_dict(db, business_unit),
    }

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
    return [await project_to_dict(db, project) for project in result.scalars().all()]

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
    return [await project_to_dict(db, project) for project in result.scalars().all()]

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
        ExternalProjectCreate(**payload_dict(data)),
        created_by=payload.get("sub")
    )
    await db.commit()

    return {"message": "Project created successfully", "project": await project_to_dict(db, project)}

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

    response = await project_to_dict(db, project)
    if project.business_unit_id:
        bu_result = await db.execute(
            select(BusinessUnitModel).where(
                BusinessUnitModel.id == project.business_unit_id,
                BusinessUnitModel.organization_id == org.id
            )
        )
        business_unit = bu_result.scalar_one_or_none()
        response["business_unit"] = await business_unit_to_dict(db, business_unit) if business_unit else None
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

    update_data = payload_dict(data, exclude_unset=True)
    if "name" in update_data:
        update_data["name"] = update_data["name"].strip()
        if not update_data["name"]:
            raise HTTPException(status_code=400, detail="Project name is required")
    if "code" in update_data:
        update_data["code"] = update_data["code"].strip() if update_data["code"] else None
    if "status" in update_data and update_data["status"] not in PROJECT_STATUS_VALUES:
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
        if hasattr(project, key):
            setattr(project, key, normalize_onboarding_value(key, value))
    await upsert_project_environments(db, project.id, update_data)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {"message": "Project updated successfully", "project": await project_to_dict(db, project)}

@api_router.get("/my-organization/applications", tags=["Org Admin - Applications"])
async def get_my_applications(
    project_id: Optional[str] = None,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get applications for the current approved organization."""
    org = await get_approved_org_for_admin(payload, db)
    query = select(ApplicationModel).where(ApplicationModel.organization_id == org.id)
    if project_id:
        query = query.where(ApplicationModel.project_id == project_id)
    result = await db.execute(query.order_by(ApplicationModel.application_name.asc()))
    return [await application_to_dict(db, application) for application in result.scalars().all()]

@api_router.post("/my-organization/applications", tags=["Org Admin - Applications"])
async def create_my_application(
    data: ApplicationCreate,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db),
):
    """Onboard an application under a project."""
    org = await get_approved_org_for_admin(payload, db)
    request_payload = payload_dict(data)
    project = await get_project_for_org(db, data.project_id, org.id)
    application_name = data.application_name.strip()
    if not application_name:
        raise HTTPException(status_code=400, detail="Application name is required")
    await assert_application_unique(db, project.id, application_name)

    application = ApplicationModel(
        project_id=project.id,
        organization_id=org.id,
        application_name=application_name,
        created_by=payload.get("sub"),
    )
    apply_onboarding_fields(application, request_payload, APPLICATION_FIELDS)
    application.api_count = max(application.api_count or 0, 0)
    await ensure_organization_api_capacity(db, org.id, application.api_count)
    db.add(application)
    await db.flush()
    await upsert_application_sections(db, application.id, request_payload)
    await db.commit()
    return {"message": "Application created successfully", "application": await application_to_dict(db, application)}

@api_router.get("/my-organization/applications/{application_id}", tags=["Org Admin - Applications"])
async def get_my_application(
    application_id: str,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get one application for the current approved organization."""
    org = await get_approved_org_for_admin(payload, db)
    application = await get_application_for_org(db, application_id, org.id)
    return await application_to_dict(db, application)

@api_router.put("/my-organization/applications/{application_id}", tags=["Org Admin - Applications"])
async def update_my_application(
    application_id: str,
    data: ApplicationUpdate,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update an application and its workbook-mapped sub-sections."""
    org = await get_approved_org_for_admin(payload, db)
    request_payload = payload_dict(data, exclude_unset=True)
    application = await get_application_for_org(db, application_id, org.id)
    if "project_id" in request_payload and request_payload["project_id"]:
        project = await get_project_for_org(db, request_payload["project_id"], org.id)
        application.project_id = project.id
    if "application_name" in request_payload:
        application_name = (request_payload["application_name"] or "").strip()
        if not application_name:
            raise HTTPException(status_code=400, detail="Application name is required")
        await assert_application_unique(db, application.project_id, application_name, exclude_id=application.id)
        application.application_name = application_name
    apply_onboarding_fields(application, request_payload, APPLICATION_FIELDS)
    if application.api_count is not None:
        application.api_count = max(application.api_count, 0)
    await ensure_organization_api_capacity(
        db,
        org.id,
        application.api_count or 0,
        exclude_application_id=application.id,
    )
    await upsert_application_sections(db, application.id, request_payload)
    application.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"message": "Application updated successfully", "application": await application_to_dict(db, application)}

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
        await assert_email_allowed_for_org(db, email, org)
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

class UserRoleUpdate(BaseModel):
    """Schema for updating a user's product role."""
    role_id: Optional[str] = None
    role_ids: Optional[List[str]] = None

async def update_user_role_assignment(
    db: AsyncSession,
    user_id: str,
    role_ids: List[str],
    payload: dict,
) -> dict:
    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    requester_role = payload.get("role")
    requester_org_id = payload.get("organization_id")
    if requester_role == "org_admin":
        if not requester_org_id:
            raise HTTPException(status_code=403, detail="Organization admin is not linked to an organization")
        if user.organization_id != requester_org_id:
            raise HTTPException(status_code=403, detail="Organization admins can only update users in their organization")
    elif requester_role != "super_admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    await ensure_standard_roles_for_organization(db, user.organization_id)
    roles = await get_standard_roles_by_ids(db, role_ids)

    previous_roles = await get_user_assigned_roles(db, user)
    previous_role_names = [role.name for role in previous_roles]
    await replace_user_role_assignments(db, user, roles)
    await db.flush()

    metadata_sync = None
    if user.zitadel_user_id:
        org = await get_user_organization(db, user)
        user_metadata = await build_probestack_user_metadata(db, user, user.email, org, roles[0].name)
        metadata_sync = await zitadel_mgmt.set_user_metadata(user.zitadel_user_id, user_metadata)

    await db.commit()
    await db.refresh(user)

    return {
        "message": "User roles updated successfully",
        "user": await user_to_dict(db, user),
        "previous_role_name": previous_role_names[0] if previous_role_names else None,
        "previous_role_names": previous_role_names,
        "role": model_to_dict(roles[0], ["permissions"]),
        "roles": roles_to_dict_list(roles),
        "metadata_sync": metadata_sync,
    }

async def add_user_role_assignment(
    db: AsyncSession,
    user_id: str,
    role_id: str,
    payload: dict,
) -> dict:
    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    current_roles = await get_user_assigned_roles(db, user)
    current_role_ids = [role.id for role in current_roles]
    if role_id in current_role_ids:
        raise HTTPException(status_code=409, detail="Role is already assigned to this user")

    response = await update_user_role_assignment(db, user_id, current_role_ids + [role_id], payload)
    response["message"] = "User role added successfully"
    return response

async def remove_user_role_assignment(
    db: AsyncSession,
    user_id: str,
    role_id: str,
    payload: dict,
) -> dict:
    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    current_roles = await get_user_assigned_roles(db, user)
    current_role_ids = [role.id for role in current_roles]
    if role_id not in current_role_ids:
        raise HTTPException(status_code=404, detail="Role is not assigned to this user")

    next_role_ids = [current_role_id for current_role_id in current_role_ids if current_role_id != role_id]
    if not next_role_ids:
        raise HTTPException(status_code=400, detail="A user must have at least one role")

    response = await update_user_role_assignment(db, user_id, next_role_ids, payload)
    response["message"] = "User role removed successfully"
    return response

@api_router.put("/my-organization/users/{user_id}/role", tags=["Org Admin"])
async def update_my_organization_user_role(
    user_id: str,
    data: UserRoleUpdate,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update a user role within the current org admin's organization."""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins should use /users/{id}/role")
    role_ids = data.role_ids if data.role_ids is not None else [data.role_id]
    return await update_user_role_assignment(db, user_id, role_ids, payload)

@api_router.post("/my-organization/users/{user_id}/roles/{role_id}", tags=["Org Admin"])
async def add_my_organization_user_role(
    user_id: str,
    role_id: str,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db),
):
    """Add one role to a user within the current org admin's organization."""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins should use /users/{id}/roles/{role_id}")
    return await add_user_role_assignment(db, user_id, role_id, payload)

@api_router.delete("/my-organization/users/{user_id}/roles/{role_id}", tags=["Org Admin"])
async def delete_my_organization_user_role(
    user_id: str,
    role_id: str,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db),
):
    """Remove one role from a user within the current org admin's organization."""
    if payload.get("role") == "super_admin":
        raise HTTPException(status_code=400, detail="Super admins should use /users/{id}/roles/{role_id}")
    return await remove_user_role_assignment(db, user_id, role_id, payload)

@api_router.post("/my-organization/user-requests/{request_id}/approve", tags=["Org Admin"])
async def approve_user_request_org_admin(
    request_id: str,
    role_id: str,
    project_id: Optional[str] = None,
    business_unit_id: Optional[str] = None,
    project_role: str = "member",
    identity_provider: Optional[str] = None,
    skip_auth0: bool = False,
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
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    request_org = org_result.scalar_one_or_none()
    if not request_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    await assert_email_allowed_for_org(db, req.email, request_org)
    
    await ensure_standard_roles_for_organization(db, org_id)
    # Validate role exists in the global standard role catalog.
    role_result = await db.execute(
        select(RoleModel).where(
            RoleModel.id == role_id,
            RoleModel.organization_id.is_(None),
        )
    )
    role = role_result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Standard role not found")
    selected_role_id = role.id
    role, onboarding_role_lookup = await resolve_new_user_role(db, request_org, req.email, role)
    role_id = role.id
    project_role = (project_role or "member").strip().lower()
    if project_role not in ["manager", "member", "viewer"]:
        raise HTTPException(status_code=400, detail="Project role must be manager, member, or viewer")
    business_unit = None
    project = None
    if project_id:
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
    req.approved_role_id = role.id
    req.approved_business_unit_id = business_unit.id if business_unit else None
    req.approved_project_id = project.id if project else None
    req.approved_project_role = project_role if project else None
    
    # Create user with verification fields
    user = UserModel(
        email=req.email,
        name=req.name,
        organization_id=org_id,
        role_id=role.id,
        status="pending_verification",
        email_verified=False,
        password_set=False,
        first_login_token=secrets.token_urlsafe(32)
    )
    db.add(user)
    await db.flush()
    await replace_user_role_assignments(db, user, [role])
    team_member = None
    if project:
        team_member = await assign_user_to_project_team(db, user, project, project_role, payload.get("sub"))
    
    provision_org = request_org
    active_provider = normalize_identity_provider(identity_provider or await get_active_identity_provider(db))
    if skip_auth0 and active_provider == "auth0":
        active_provider = "zitadel"
    if provision_org and provision_org.status == "approved":
        needs_provider_org = (
            (active_provider == "auth0" and not provision_org.auth0_org_id)
            or (active_provider == "zitadel" and not provision_org.zitadel_org_id)
        )
        org_provision_result = {"success": True, "skipped": True}
        if needs_provider_org:
            org_provision_result = await provision_organization_for_active_provider(db, provision_org, active_provider)
        if not org_provision_result.get("success"):
            raise HTTPException(
                status_code=502,
                detail=f"Failed to create organization in {active_provider.upper()}: {org_provision_result.get('error') or 'unknown error'}"
            )
    provider_user_result = await provision_user_for_active_provider(
        db,
        user,
        req.email,
        req.name,
        {
            "probestack_user_id": user.id,
            "organization_id": org_id,
            "organization_name": request_org.name,
        },
        provision_org,
        role.name,
        active_provider,
    )
    if not provider_user_result.get("success"):
        raise HTTPException(
            status_code=502,
            detail=f"Failed to create user in {active_provider.upper()}: {provider_user_result.get('error') or 'unknown error'}"
        )
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()
    
    # Generate setup account URL
    base_url = os.environ.get("APP_URL", "")
    setup_url = f"{base_url}/setup-account?email={req.email}&token={user.first_login_token}" if base_url else None

    try:
        email_result = send_request_decision_email(
            to_email=req.email,
            recipient_name=req.name,
            request_name="user access request",
            status="approved",
            organization_name=request_org.name,
            next_steps="Your access has been approved. Please set up your account, verify your email, and then sign in to ProbeStack.",
            action_url=setup_url,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "User request approval email was not sent for %s: %s. To: %s. Bcc: %s",
                req.id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc"),
            )
    except Exception as exc:
        logger.error("Failed to build user request approval email for %s: %s", req.id, exc)
    
    return {
        "message": "User request approved",
        "user_id": user.id,
        "user": {
            "name": user.name,
            "email": user.email,
            "role": role.name,
            "auth0_user_id": user.auth0_user_id,
            "zitadel_user_id": user.zitadel_user_id,
            "status": user.status
        },
        "identity_provider": active_provider,
        "auth0_skipped": should_skip_auth0(active_provider, skip_auth0),
        "selected_role_id": selected_role_id,
        "assigned_role_id": role.id,
        "assigned_role_name": role.name,
        "role_source": "mongodb" if onboarding_role_lookup else "admin_selection",
        "mongodb_role_lookup": onboarding_role_lookup,
        "business_unit": model_to_dict(business_unit, ["tags"]) if business_unit else None,
        "team": model_to_dict(project) if project else None,
        "team_member": await project_team_member_to_dict(db, team_member) if team_member else None,
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
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    request_org = org_result.scalar_one_or_none()
    
    now = datetime.now(timezone.utc)
    req.status = "rejected"
    req.rejected_at = now
    req.updated_at = now
    req.rejection_reason = reason
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    organization_name = request_org.name if request_org else "your organization"
    try:
        email_result = send_request_decision_email(
            to_email=req.email,
            recipient_name=req.name,
            request_name="user access request",
            status="rejected",
            organization_name=organization_name,
            reason=reason,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "User request rejection email was not sent for %s: %s. To: %s. Bcc: %s",
                req.id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc"),
            )
    except Exception as exc:
        logger.error("Failed to build user request rejection email for %s: %s", req.id, exc)
    
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
    role_count = await db.scalar(select(func.count()).select_from(RoleModel).where(RoleModel.organization_id.is_(None)))
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
    
    requested_selections = normalize_plan_selections(data)
    created_requests, requested_plans_details = await create_product_upgrade_requests(
        db,
        org=org,
        organization_id=org_id,
        selections=requested_selections,
        reason=data.reason,
        requested_by=payload["sub"],
    )
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    try:
        email_result = send_plan_upgrade_request_email(
            organization_name=org.name,
            request_id=created_requests[0].id,
            requested_by_email=payload.get("email"),
            requested_details=requested_plans_details,
            reason=data.reason,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "Plan upgrade request email was not sent for %s: %s. To: %s. Bcc: %s",
                created_requests[0].id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc"),
            )
    except Exception as exc:
        logger.error("Failed to build plan upgrade request email for %s: %s", created_requests[0].id, exc)

    request_dicts = [await upgrade_request_to_dict(db, request) for request in created_requests]
    all_tools = []
    from_plan_names = []
    for detail in requested_plans_details:
        all_tools.extend(detail["tools"])
        from_plan_names.extend(detail["current_plan_names"])
    
    return {
        "request_id": created_requests[0].id if len(created_requests) == 1 else None,
        "request_ids": [request.id for request in created_requests],
        "status": "pending",
        "message": "Upgrade request submitted successfully",
        "requests": request_dicts,
        "upgrade": {
            "from_plans_by_product": [
                {
                    "product_id": detail["product"].id,
                    "product_name": detail["product"].name,
                    "plans": detail["current_plan_names"],
                }
                for detail in requested_plans_details
            ],
            "from_plans": from_plan_names,
            "to_plans": [detail["plan"].name for detail in requested_plans_details],
            "requested_tools": all_tools,
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
            product = await get_plan_product(db, plan)
            if product:
                await cancel_active_real_org_subscriptions_for_product(db, req.organization_id, product.id)
            else:
                await cancel_active_real_org_subscription_for_plan(db, req.organization_id, plan.id)
            
            new_sub = SubscriptionModel(
                organization_id=req.organization_id,
                plan_id=plan.id,
                status="active",
                start_date=now,
                end_date=now + timedelta(days=30),
                billing_cycle="monthly",
                amount=total_price,
                quota=int(getattr(plan, "api_limit", 0) or 0),
                used_quota=0,
            )
            db.add(new_sub)
            await db.flush()
            await set_subscription_tools(db, new_sub.id, plan.id, tools)
            created_subs.append({"plan": plan.name, "tools": tools})
    await sync_organization_requested_from_active_subscriptions(db, req.organization_id)
    
    # Create notification
    plan_names = [p.get("plan_name", p.get("plan_id", "Unknown")) for p in requested_plans]
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == req.organization_id))
    organization = org_result.scalar_one_or_none()
    organization_name = organization.name if organization else await get_organization_name(db, req.organization_id)
    notif = NotificationModel(
        title="Upgrade Request Approved",
        message=f"{organization_name or req.organization_id} upgraded to: {', '.join(plan_names)}",
        type="success"
    )
    db.add(notif)
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    if organization and organization.email:
        try:
            email_result = send_request_decision_email(
                to_email=organization.email,
                recipient_name=organization.contact_person or organization.name,
                request_name="plan upgrade request",
                status="approved",
                organization_name=organization.name,
                next_steps=f"Your plan upgrade has been approved for: {', '.join(plan_names)}. Our team will follow up with any onboarding or billing details.",
                action_url=f"{APP_URL.rstrip('/')}/admin/my-subscription",
                notification_emails=notification_emails,
            )
            if not email_result.get("sent"):
                logger.warning(
                    "Upgrade approval email was not sent for %s: %s. To: %s. Bcc: %s",
                    req.id,
                    email_result.get("reason", "unknown reason"),
                    email_result.get("to"),
                    email_result.get("bcc"),
                )
        except Exception as exc:
            logger.error("Failed to build upgrade approval email for %s: %s", req.id, exc)
    
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
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == req.organization_id))
    organization = org_result.scalar_one_or_none()
    organization_name = organization.name if organization else await get_organization_name(db, req.organization_id)
    notif = NotificationModel(
        title="Upgrade Request Rejected",
        message=f"Upgrade request from {organization_name or req.organization_id} was rejected",
        type="warning"
    )
    db.add(notif)
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    if organization and organization.email:
        try:
            email_result = send_request_decision_email(
                to_email=organization.email,
                recipient_name=organization.contact_person or organization.name,
                request_name="plan upgrade request",
                status="rejected",
                organization_name=organization.name,
                reason=reason,
                notification_emails=notification_emails,
            )
            if not email_result.get("sent"):
                logger.warning(
                    "Upgrade rejection email was not sent for %s: %s. To: %s. Bcc: %s",
                    req.id,
                    email_result.get("reason", "unknown reason"),
                    email_result.get("to"),
                    email_result.get("bcc"),
                )
        except Exception as exc:
            logger.error("Failed to build upgrade rejection email for %s: %s", req.id, exc)
    
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
    created_requests, requested_plans_details = await create_product_upgrade_requests(
        db,
        org=org,
        organization_id=org_id,
        selections=requested_selections,
        reason=data.reason,
        requested_by=payload["sub"],
    )
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    try:
        email_result = send_plan_upgrade_request_email(
            organization_name=org.name,
            request_id=created_requests[0].id,
            requested_by_email=payload.get("email"),
            requested_details=requested_plans_details,
            reason=data.reason,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "Plan upgrade request email was not sent for %s: %s. To: %s. Bcc: %s",
                created_requests[0].id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc"),
            )
    except Exception as exc:
        logger.error("Failed to build plan upgrade request email for %s: %s", created_requests[0].id, exc)

    request_dicts = [await upgrade_request_to_dict(db, request) for request in created_requests]
    if len(request_dicts) == 1:
        return request_dicts[0]
    return {
        "message": "Upgrade requests submitted successfully",
        "request_ids": [request.id for request in created_requests],
        "requests": request_dicts,
    }

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
        product = await get_plan_product(db, plan)
        if product:
            await cancel_active_real_org_subscriptions_for_product(db, request.organization_id, product.id)
        else:
            await cancel_active_real_org_subscription_for_plan(db, request.organization_id, plan.id)
        subscription = SubscriptionModel(
            organization_id=request.organization_id,
            plan_id=plan.id,
            status="active",
            start_date=now,
            end_date=now + timedelta(days=30),
            billing_cycle="monthly",
            amount=total_price,
            quota=int(getattr(plan, "api_limit", 0) or 0),
            used_quota=0,
        )
        db.add(subscription)
        await db.flush()
        await set_subscription_tools(db, subscription.id, plan.id, tools)
    await sync_organization_requested_from_active_subscriptions(db, request.organization_id)
    
    # Create notification
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == request.organization_id))
    organization = org_result.scalar_one_or_none()
    organization_name = organization.name if organization else await get_organization_name(db, request.organization_id)
    plan_names = [item.get("plan_name", item.get("plan_id", "Unknown")) for item in request_items]
    notif = NotificationModel(
        title="Plan Upgrade Approved",
        message=f"{organization_name or request.organization_id} plan upgrade approved",
        type="success"
    )
    db.add(notif)
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    if organization and organization.email:
        try:
            email_result = send_request_decision_email(
                to_email=organization.email,
                recipient_name=organization.contact_person or organization.name,
                request_name="plan upgrade request",
                status="approved",
                organization_name=organization.name,
                next_steps=f"Your plan upgrade has been approved for: {', '.join(plan_names)}. Our team will follow up with any onboarding or billing details.",
                action_url=f"{APP_URL.rstrip('/')}/admin/my-subscription",
                notification_emails=notification_emails,
            )
            if not email_result.get("sent"):
                logger.warning(
                    "Plan upgrade approval email was not sent for %s: %s. To: %s. Bcc: %s",
                    request.id,
                    email_result.get("reason", "unknown reason"),
                    email_result.get("to"),
                    email_result.get("bcc"),
                )
        except Exception as exc:
            logger.error("Failed to build plan upgrade approval email for %s: %s", request.id, exc)
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
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == request.organization_id))
    organization = org_result.scalar_one_or_none()
    organization_name = organization.name if organization else await get_organization_name(db, request.organization_id)
    notif = NotificationModel(
        title="Plan Upgrade Rejected",
        message=f"{organization_name or request.organization_id} plan upgrade rejected",
        type="warning"
    )
    db.add(notif)
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    if organization and organization.email:
        try:
            email_result = send_request_decision_email(
                to_email=organization.email,
                recipient_name=organization.contact_person or organization.name,
                request_name="plan upgrade request",
                status="rejected",
                organization_name=organization.name,
                reason=reason,
                notification_emails=notification_emails,
            )
            if not email_result.get("sent"):
                logger.warning(
                    "Plan upgrade rejection email was not sent for %s: %s. To: %s. Bcc: %s",
                    request.id,
                    email_result.get("reason", "unknown reason"),
                    email_result.get("to"),
                    email_result.get("bcc"),
                )
        except Exception as exc:
            logger.error("Failed to build plan upgrade rejection email for %s: %s", request.id, exc)
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
    
    # Calculate product distribution from active subscriptions in the current catalog.
    distribution_result = await db.execute(
        select(ProductModel.name, func.count(SubscriptionModel.id))
        .select_from(SubscriptionModel)
        .join(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .join(ProductModel, PlanModel.product_id == ProductModel.id)
        .where(
            SubscriptionModel.status == "active",
            PlanModel.is_active == True,
            ProductModel.is_active == True,
        )
        .group_by(ProductModel.id, ProductModel.name, ProductModel.display_order)
        .order_by(ProductModel.display_order, ProductModel.name)
    )
    sub_distribution = [
        {"name": product_name, "value": count}
        for product_name, count in distribution_result.all()
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
    business_units = [await business_unit_to_dict(db, bu) for bu in bu_result.scalars().all()]

    project_result = await db.execute(
        select(ProjectModel)
        .where(ProjectModel.organization_id == org_id)
        .order_by(ProjectModel.name.asc())
    )
    teams = [await project_to_dict(db, project) for project in project_result.scalars().all()]

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

    user_result = await db.execute(
        select(UserModel, RoleModel)
        .outerjoin(RoleModel, UserModel.role_id == RoleModel.id)
        .where(UserModel.organization_id == org_id)
        .order_by(UserModel.created_at.desc())
    )
    user_rows = user_result.all()
    users_by_id = {}
    users_by_email = {}
    user_ids = []
    user_emails = []
    for user, role in user_rows:
        entry = {
            "user": user,
            "role": role,
            "business_units_by_id": {},
        }
        users_by_id[user.id] = entry
        users_by_email[user.email.lower()] = entry
        user_ids.append(user.id)
        user_emails.append(user.email)

    if user_rows:
        user_member_result = await db.execute(
            select(ProjectTeamMemberModel, ProjectModel, BusinessUnitModel)
            .join(ProjectModel, ProjectTeamMemberModel.project_id == ProjectModel.id)
            .outerjoin(BusinessUnitModel, ProjectModel.business_unit_id == BusinessUnitModel.id)
            .where(
                ProjectTeamMemberModel.organization_id == org_id,
                ProjectModel.organization_id == org_id,
                ProjectTeamMemberModel.status == "active",
                (
                    ProjectTeamMemberModel.user_id.in_(user_ids)
                    | ProjectTeamMemberModel.email.in_(user_emails)
                ),
            )
            .order_by(BusinessUnitModel.name.asc(), ProjectModel.name.asc())
        )
        for member, project, business_unit in user_member_result.all():
            entry = users_by_id.get(member.user_id) or users_by_email.get((member.email or "").lower())
            if not entry or not business_unit:
                continue
            bu_entry = entry["business_units_by_id"].setdefault(
                business_unit.id,
                {
                    "id": business_unit.id,
                    "name": business_unit.name,
                    "code": business_unit.code,
                    "role": "member",
                    "projects": [],
                },
            )
            if not any(item["id"] == project.id for item in bu_entry["projects"]):
                bu_entry["projects"].append({
                    "id": project.id,
                    "name": project.name,
                    "code": project.code,
                    "role": member.project_role,
                    "team_member_id": member.id,
                    "status": member.status,
                })

    users = [
        await public_user_detail_to_dict(
            db,
            entry["user"],
            entry["role"],
            list(entry["business_units_by_id"].values()),
        )
        for entry in users_by_id.values()
    ]

    return {
        "organization": await organization_to_dict(db, org),
        "user_count": len(users),
        "users": users,
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
    response = [await business_unit_to_dict(db, bu) for bu in business_units]

    if include_teams and business_units:
        bu_ids = [bu.id for bu in business_units]
        projects_result = await db.execute(
            select(ProjectModel)
            .where(ProjectModel.organization_id == org_id, ProjectModel.business_unit_id.in_(bu_ids))
            .order_by(ProjectModel.name.asc())
        )
        projects_by_bu = {}
        for project in projects_result.scalars().all():
            projects_by_bu.setdefault(project.business_unit_id, []).append(await project_to_dict(db, project))
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
    return [add_identity_aliases(model_to_dict(project), "project") for project in result.scalars().all()]

@api_router.get("/organizations/{org_id}/users-with-roles")
async def get_organization_users_with_roles(
    org_id: str,
    status: Optional[str] = None,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get organization users with compact org, Business unit, and team role details."""
    if payload.get("role") == "org_admin" and payload.get("organization_id") != org_id:
        raise HTTPException(status_code=403, detail="Organization admin access required for this organization")

    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    query = (
        select(UserModel, RoleModel)
        .outerjoin(RoleModel, UserModel.role_id == RoleModel.id)
        .where(UserModel.organization_id == org_id)
    )
    if status:
        query = query.where(UserModel.status == status)

    result = await db.execute(query.order_by(UserModel.created_at.desc()))
    user_rows = result.all()

    summaries_by_user_id = {}
    user_ids = []
    user_emails = []
    for user, role in user_rows:
        summaries_by_user_id[user.id] = {
            "user": user,
            "role": role,
            "business_units_by_id": {},
        }
        user_ids.append(user.id)
        user_emails.append(user.email)

    if user_rows:
        member_result = await db.execute(
            select(ProjectTeamMemberModel, ProjectModel, BusinessUnitModel)
            .join(ProjectModel, ProjectTeamMemberModel.project_id == ProjectModel.id)
            .outerjoin(BusinessUnitModel, ProjectModel.business_unit_id == BusinessUnitModel.id)
            .where(
                ProjectTeamMemberModel.organization_id == org_id,
                ProjectModel.organization_id == org_id,
                ProjectTeamMemberModel.status == "active",
                (
                    ProjectTeamMemberModel.user_id.in_(user_ids)
                    | ProjectTeamMemberModel.email.in_(user_emails)
                ),
            )
            .order_by(BusinessUnitModel.name.asc(), ProjectModel.name.asc())
        )
        summaries_by_email = {
            entry["user"].email.lower(): entry
            for entry in summaries_by_user_id.values()
        }
        for member, project, business_unit in member_result.all():
            summary = summaries_by_user_id.get(member.user_id) or summaries_by_email.get(member.email.lower())
            if not summary or not business_unit:
                continue

            bu_entry = summary["business_units_by_id"].setdefault(
                business_unit.id,
                {
                    "bu_name": business_unit.name,
                    "bu_role": "member",
                    "teams": [],
                },
            )
            if not any(team["team_name"] == project.name for team in bu_entry["teams"]):
                bu_entry["teams"].append({
                    "team_name": project.name,
                    "team_role": member.project_role,
                })

    return [
        await user_access_summary_to_dict(
            db,
            entry["user"],
            entry["role"],
            list(entry["business_units_by_id"].values()),
        )
        for entry in summaries_by_user_id.values()
    ]

@api_router.get("/organizations/{org_id}/api-counts")
async def get_organization_api_counts(
    org_id: str,
    payload: dict = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    access_scope = await get_subscription_access_scope(db, payload)
    if access_scope["scope"] != "all" and access_scope.get("organization_id") != org_id:
        raise HTTPException(status_code=403, detail="Not allowed to access this organization")

    org = await get_organization_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    return await get_organization_api_count_summary(db, org)

@api_router.get("/organizations/{org_id}/quotas")
async def get_organization_quotas(
    org_id: str,
    payload: dict = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    access_scope = await get_subscription_access_scope(db, payload)
    if access_scope["scope"] != "all" and access_scope.get("organization_id") != org_id:
        raise HTTPException(status_code=403, detail="Not allowed to access this organization")

    org = await get_organization_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    return await get_organization_api_count_summary(db, org)

@api_router.get("/organizations/{org_id}/quotas/{product_identifier}")
async def get_organization_product_quota(
    org_id: str,
    product_identifier: str,
    payload: dict = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    access_scope = await get_subscription_access_scope(db, payload)
    if access_scope["scope"] != "all" and access_scope.get("organization_id") != org_id:
        raise HTTPException(status_code=403, detail="Not allowed to access this organization")

    subscription, plan, product = await get_active_subscription_for_product_identifier(db, org_id, product_identifier)
    data = await subscription_to_dict(db, subscription)
    data["plan_quota"] = int(getattr(plan, "api_limit", 0) or 0) if plan else 0
    data["quota"] = get_subscription_quota_limit(subscription, plan)
    data["used_quota"] = get_subscription_used_quota(subscription)
    data["remaining_quota"] = None if data["quota"] is None else max(data["quota"] - data["used_quota"], 0)
    data["product_id"] = product.id if product else data.get("product_id")
    data["product_key"] = product.key if product else data.get("product_key")
    data["product_name"] = product.name if product else data.get("product_name")
    return data

@api_router.put("/organizations/{org_id}/quotas")
async def update_organization_quotas(
    org_id: str,
    data: OrganizationQuotaUpdate,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    org = await get_organization_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    updated_subscription_ids = await update_organization_subscription_quotas(db, org_id, data)
    await db.commit()
    summary = await get_organization_api_count_summary(db, org)
    return {
        "message": "Organization quota updated",
        "updated_subscription_ids": updated_subscription_ids,
        **summary,
    }

@api_router.put("/organizations/{org_id}/quotas/{product_identifier}/usage")
async def update_organization_product_usage_quota(
    org_id: str,
    product_identifier: str,
    data: SubscriptionQuotaUpdate,
    payload: dict = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    access_scope = await get_subscription_access_scope(db, payload)
    if access_scope["scope"] != "all" and access_scope.get("organization_id") != org_id:
        raise HTTPException(status_code=403, detail="Not allowed to update this organization quota")

    subscription, plan, product = await get_active_subscription_for_product_identifier(db, org_id, product_identifier)
    apply_subscription_usage_update(subscription, data)
    enforce_subscription_quota_bounds(subscription, plan)
    await db.commit()
    response = await subscription_to_dict(db, subscription)
    response["message"] = "Usage quota updated"
    response["product_id"] = product.id if product else response.get("product_id")
    response["product_key"] = product.key if product else response.get("product_key")
    response["product_name"] = product.name if product else response.get("product_name")
    return response

@api_router.put("/organizations/{org_id}/api-counts")
async def update_organization_api_counts(
    org_id: str,
    data: OrganizationApiCountUpdate,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    org = await get_organization_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if data.api_count is not None and data.api_count < 0:
        raise HTTPException(status_code=400, detail="api_count cannot be negative")

    quota_update = OrganizationQuotaUpdate(
        quota=data.api_count,
        subscription_id=data.subscription_id,
        subscriptions=[
            OrganizationSubscriptionQuotaUpdate(subscription_id=item.subscription_id, quota=item.api_count)
            for item in data.subscriptions
        ] if data.subscriptions else None,
    )
    updated_subscription_ids = await update_organization_subscription_quotas(db, org_id, quota_update)
    await db.commit()
    summary = await get_organization_api_count_summary(db, org)
    return {
        "message": "Organization quota updated",
        "updated_subscription_ids": updated_subscription_ids,
        **summary,
    }

@api_router.get("/organizations/{org_id}")
async def get_organization(org_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return await organization_to_dict(db, org)

@api_router.post("/organizations")
async def create_organization(data: OrganizationCreate, db: AsyncSession = Depends(get_db)):
    validate_required_organization_create_fields(payload_dict(data))
    plan_selections = normalize_organization_plan_selections(data)

    plan_ids = [selection.plan_id for selection in plan_selections]
    plans = {}
    if plan_ids:
        plans_result = await db.execute(select(PlanModel).where(PlanModel.id.in_(plan_ids)))
        plans = {plan.id: plan for plan in plans_result.scalars().all()}
    invalid_plans = [plan_id for plan_id in plan_ids if plan_id not in plans]
    if invalid_plans:
        raise HTTPException(status_code=400, detail=f"Invalid requested plans: {invalid_plans}")

    for tool in data.requested_tools or []:
        matched_selection = None
        for selection in plan_selections:
            if await resolve_plan_tool(db, selection.plan_id, tool):
                matched_selection = selection
                break
        if not matched_selection:
            raise HTTPException(status_code=400, detail=f"Tool '{tool}' is not available for selected plans")
        if tool not in matched_selection.tool_ids:
            matched_selection.tool_ids.append(tool)

    selected_tools = []
    for selection in plan_selections:
        for tool in selection.tool_ids or []:
            if not await resolve_plan_tool(db, selection.plan_id, tool):
                raise HTTPException(status_code=400, detail=f"Tool '{tool}' is not available for plan '{selection.plan_id}'")
            if tool not in selected_tools:
                selected_tools.append(tool)

    org = OrganizationModel(
        name=data.name, email=data.email, domain=data.domain,
        contact_person=data.contact_person, phone=data.phone, address=data.address,
        description=data.description,
        supported_domains=supported_domains_from_domain(data.domain),
        gateway_region=data.gateway_region,
        gateway_organization_name=data.gateway_organization_name,
        gateway_environment_type=data.gateway_environment_type,
        gateway_environments=json.dumps(data.gateway_environments) if data.gateway_environments else None
    )
    apply_onboarding_fields(org, payload_dict(data), ORGANIZATION_ONBOARDING_FIELDS)
    if org.organization_code and not org.external_org_id:
        org.external_org_id = org.organization_code
    db.add(org)
    await db.flush()
    await ensure_standard_roles_for_organization(db, org.id)
    if plan_selections:
        await create_organization_subscription_request_from_selections(
            db,
            org.id,
            plan_selections,
            status=org.status
        )
    
    plan_names = [plans[plan_id].name for plan_id in plan_ids]
    notif = NotificationModel(
        title="New Organization Request",
        message=f"{data.name} has requested to join" + (f" with {', '.join(plan_names)} plan(s)" if plan_names else ""),
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

    individual_org = await get_or_create_individual_users_org(db)
    await db.commit()

    # No matching organization found; unknown domains can continue as Individual Users.
    return {
        "found": False,
        "email": data.email,
        "domain": email_domain,
        "domain_known": False,
        "individual_user_allowed": True,
        "subscription_model": "per_user",
        "organization": {
            "external_org_id": individual_org.external_org_id,
            "name": individual_org.name,
            "id": individual_org.id,
        },
        "message": "No organization found for this email domain. User can be added under Individual Users."
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
        org_name = user_org.name if user_org else None

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
        if user.zitadel_user_id:
            await zitadel_mgmt.send_verification_email(user.zitadel_user_id)

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
    individual_org_id = await get_individual_users_org_id(db)
    individual_org_name = await get_individual_users_org_name(db)
    result = await db.execute(
        select(OrganizationModel).where(
            OrganizationModel.status == "approved",
            OrganizationModel.supported_domains.isnot(None),
            OrganizationModel.id != individual_org_id,
            OrganizationModel.name != individual_org_name,
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
        individual_request = await create_individual_request_for_unknown_domain(
            db,
            email=email,
            name=derive_name_from_email(email),
            notes="Created from login initiation for unknown organization domain.",
        )
        individual_org = await get_or_create_individual_users_org(db)
        default_role = await get_standard_role(db, individual_org.id)
        await db.commit()
        return {
            "success": True,
            "next_step": "pending_individual_approval",
            "message": f"No organization domain matched {email_domain}. Request routed to Individual Users for approval.",
            "request_id": individual_request.id,
            "organization": {
                "id": individual_org.id,
                "name": individual_org.name,
            },
            "subscription_model": "per_user",
            "user": {
                "email": email,
                "name": individual_request.name,
                "organization_id": individual_org.id,
                "organization_name": individual_org.name,
            },
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
    default_role = await get_standard_role(db, matched_org.id)
    user_request = UserRequestModel(
        email=email,
        name=email.split("@")[0].replace(".", " ").title(),
        organization_id=matched_org.id,
        requested_role=default_role.name,
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

    notification_emails = await get_notification_group_emails(db)
    org_admin_emails = await get_org_admin_emails(db, matched_org.id)
    await db.commit()

    try:
        email_result = send_user_request_admin_email(
            organization_name=matched_org.name,
            request_id=user_request.id,
            requester_name=user_request.name,
            requester_email=email,
            requested_role=default_role.name,
            job_title=None,
            department=None,
            phone=None,
            notes=None,
            to_emails=org_admin_emails,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "User request email was not sent for %s: %s. To: %s. Bcc: %s",
                user_request.id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc"),
            )
    except Exception as exc:
        logger.error("Failed to build user request email for %s: %s", user_request.id, exc)

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


# ==================== IDENTITY PROVIDER SETTINGS ====================

@api_router.get("/identity-provider", tags=["Admin - Identity Provider"])
async def get_identity_provider_setting(
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get the active identity provider setting (Super Admin only)."""
    active_provider = await get_active_identity_provider(db)
    return {
        "active_provider": active_provider,
        "providers": [
            identity_provider_config("zitadel"),
            identity_provider_config("auth0"),
        ],
    }

@api_router.put("/identity-provider", tags=["Admin - Identity Provider"])
async def update_identity_provider_setting(
    data: IdentityProviderUpdate,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    """Switch the active identity provider for onboarding and generic auth APIs."""
    setting = await set_active_identity_provider(db, data.provider, payload.get("sub"))
    await db.commit()
    active_provider = normalize_identity_provider(setting.value)
    return {
        "message": f"Identity provider switched to {active_provider}",
        "active_provider": active_provider,
        "providers": [
            identity_provider_config("zitadel"),
            identity_provider_config("auth0"),
        ],
        "updated_at": setting.updated_at.isoformat() if setting.updated_at else None,
    }

@api_router.get("/public/identity-provider", tags=["Public API"])
async def get_public_identity_provider(db: AsyncSession = Depends(get_db)):
    """Return the active identity provider for external applications."""
    active_provider = await get_active_identity_provider(db)
    return {
        "active_provider": active_provider,
        "configured": identity_provider_config(active_provider)["configured"],
    }

# ==================== PUBLIC API - Authentication ====================

@api_router.get("/public/auth0-config", tags=["Public API"])
async def get_auth0_config():
    """
    Get current Auth0 environment configuration (for debugging).
    Does not expose secrets.
    """
    return {
        "enabled": auth0_mgmt.enabled,
        "domain": AUTH0_MGMT_DOMAIN,
        "db_connection_name": AUTH0_DB_CONNECTION_NAME,
        "db_connection_id": AUTH0_DB_CONNECTION_ID[:10] + "..." if AUTH0_DB_CONNECTION_ID else None,
        "environment": "dev" if "dev" in AUTH0_DB_CONNECTION_NAME.lower() else 
                       "test" if "test" in AUTH0_DB_CONNECTION_NAME.lower() else 
                       "prod" if "prod" in AUTH0_DB_CONNECTION_NAME.lower() else "unknown"
    }

def resolve_auth0_redirect_uri(product: Optional[str] = None, redirect_uri: Optional[str] = None) -> tuple[str, str]:
    product_key = (product or "probestack").strip().lower()
    if product_key in {"localhost", "dev"}:
        product_key = "local"
    if product_key not in AUTH0_REDIRECT_URIS:
        raise HTTPException(status_code=400, detail=f"Unsupported Auth0 product: {product or product_key}")

    if redirect_uri:
        selected_redirect_uri = redirect_uri.strip()
        matching_products = [
            key for key, allowed_redirect_uri in AUTH0_REDIRECT_URIS.items()
            if allowed_redirect_uri == selected_redirect_uri
        ]
        if not matching_products:
            raise HTTPException(status_code=400, detail="redirect_uri is not registered for Auth0 login")
        if selected_redirect_uri != AUTH0_REDIRECT_URIS[product_key]:
            raise HTTPException(status_code=400, detail="redirect_uri does not match the selected Auth0 product")
    else:
        selected_redirect_uri = AUTH0_REDIRECT_URIS[product_key]

    return product_key, selected_redirect_uri

def resolve_auth0_post_logout_uri(
    product: Optional[str] = None,
    post_logout_redirect_uri: Optional[str] = None,
) -> tuple[str, str]:
    product_key = (product or "probestack").strip().lower()
    if product_key in {"localhost", "dev"}:
        product_key = "local"
    if product_key not in AUTH0_POST_LOGOUT_URIS:
        raise HTTPException(status_code=400, detail=f"Unsupported Auth0 product: {product or product_key}")

    if post_logout_redirect_uri:
        selected_post_logout_uri = post_logout_redirect_uri.strip()
        matching_products = [
            key for key, allowed_uri in AUTH0_POST_LOGOUT_URIS.items()
            if allowed_uri == selected_post_logout_uri
        ]
        if not matching_products:
            raise HTTPException(status_code=400, detail="post_logout_redirect_uri is not registered for Auth0 logout")
        if selected_post_logout_uri != AUTH0_POST_LOGOUT_URIS[product_key]:
            raise HTTPException(status_code=400, detail="post_logout_redirect_uri does not match the selected Auth0 product")
    else:
        selected_post_logout_uri = AUTH0_POST_LOGOUT_URIS[product_key]

    return product_key, selected_post_logout_uri

def normalize_auth_product(product: Optional[str] = None) -> str:
    requested_product = (product or "probestack").strip().lower().replace("-", "")
    return {
        "probe": "probestack",
        "probestack": "probestack",
        "localhost": "local",
        "local": "local",
        "dev": "local",
        "catalog": "forgecatalog",
        "forgecatalog": "forgecatalog",
        "fuzz": "forgefuzz",
        "forgefuzz": "forgefuzz",
        "console": "console",
    }.get(requested_product, requested_product)

def resolve_product_auth_return_url(product: Optional[str] = None) -> str:
    product_key = normalize_auth_product(product)
    return PRODUCT_AUTH_RETURN_URLS.get(product_key) or PRODUCT_AUTH_RETURN_URLS["probestack"]

@api_router.post("/public/auth/init", tags=["Public API - Identity"])
async def auth0_init(data: Auth0InitRequest, db: AsyncSession = Depends(get_db)):
    """
    Step 1: Initialize the active identity-provider authentication flow.
    
    - Takes user email
    - Identifies organization from email domain
    - Returns Auth0 authorize URL with the correct organization parameter
    
    The frontend should redirect the user to the returned authorize_url.
    """
    active_provider = await get_active_identity_provider(db)
    if active_provider == "zitadel":
        return await zitadel_init(
            ZitadelInitRequest(email=data.email, state=data.state, product=data.product, redirect_uri=data.redirect_uri),
            db,
        )
    require_identity_provider_configured("auth0")
    if not data.email or "@" not in data.email:
        raise HTTPException(status_code=400, detail="Invalid email format")
    product_key, redirect_uri = resolve_auth0_redirect_uri(data.product, data.redirect_uri)
    product_redirect_url = resolve_product_auth_return_url(product_key)

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
        "redirect_uri": redirect_uri,
        "organization": found_org.auth0_org_id,  # Auth0 org_id like org_SVFows90OrYpzdIs
    }

    # Add state if provided (for CSRF protection)
    if data.state:
        auth0_params["state"] = data.state
    else:
        auth0_params["state"] = encode_product_oauth_state(product_key, product_redirect_url)

    authorize_url = f"https://{AUTH0_DOMAIN}/authorize?{urlencode(auth0_params)}"

    return {
        "success": True,
        "identity_provider": "auth0",
        "authorize_url": authorize_url,
        "organization": {
            "id": found_org.id,
            "name": found_org.name,
            "external_org_id": found_org.external_org_id,
            "auth0_org_id": found_org.auth0_org_id
        },
        "email": data.email,
        "domain": email_domain,
        "product": product_key,
        "redirect_uri": redirect_uri,
        "product_redirect_url": product_redirect_url,
        "return_to": product_redirect_url,
    }

@api_router.post("/public/auth/callback", tags=["Public API - Identity"])
async def auth0_callback(
    data: Auth0CallbackRequest,
    fastapi_response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Step 2: Exchange the active identity-provider authorization code for tokens.
    
    - Takes the code from Auth0 callback
    - Exchanges code for access_token, id_token
    - Decodes id_token to extract user info
    - Saves login record to database
    - Returns tokens to the frontend
    """
    active_provider = await get_active_identity_provider(db)
    if active_provider == "zitadel":
        return await zitadel_callback(
            ZitadelCallbackRequest(code=data.code, email=data.email, product=data.product, redirect_uri=data.redirect_uri),
            fastapi_response,
            db,
        )
    require_identity_provider_configured("auth0")
    if not data.code:
        raise HTTPException(status_code=400, detail="Authorization code is required")
    product_key, redirect_uri = resolve_auth0_redirect_uri(data.product, data.redirect_uri)
    product_redirect_url = resolve_product_auth_return_url(product_key)

    # Exchange code for tokens
    token_url = f"https://{AUTH0_DOMAIN}/oauth/token"
    token_payload = {
        "grant_type": "authorization_code",
        "client_id": AUTH0_CLIENT_ID,
        "client_secret": AUTH0_CLIENT_SECRET,
        "code": data.code,
        "redirect_uri": redirect_uri
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

        await ensure_standard_roles_for_organization(db, org.id)
        for role_name in auth0_roles:
            if not role_name:
                continue
            standard_name = await map_to_standard_role_name(db, role_name, DEFAULT_CONSUMER_ROLE_SLUG)
            role = await get_standard_role(db, org.id, standard_name)
            role_payload = {"id": role.id, "name": role.name}
            if role_payload not in synced_roles:
                synced_roles.append(role_payload)

        # Determine the primary role (first role or default)
        primary_role = synced_roles[0] if synced_roles else None

        if existing_user:
            # Update existing user
            existing_user.name = user_info.get("name") or existing_user.name
            if auth0_user_id and not existing_user.auth0_user_id:
                existing_user.auth0_user_id = auth0_user_id
            existing_user.last_login = datetime.now(timezone.utc)
            synced_user = existing_user
            primary_role = {
                "id": existing_user.role_id,
                "name": await get_role_name(db, existing_user.role_id, "API/Agent Consumer"),
            }
        else:
            # Create new user with a standard role.
            if not primary_role:
                default_role = await get_standard_role(db, org.id)
                primary_role = {"id": default_role.id, "name": default_role.name}
            requested_role = await get_standard_role(db, org.id, primary_role["name"])
            resolved_role, onboarding_role_lookup = await resolve_new_user_role(db, org, email, requested_role)
            primary_role = {"id": resolved_role.id, "name": resolved_role.name}

            new_user = UserModel(
                email=email,
                name=user_info.get("name") or user_info.get("nickname") or email.split("@")[0],
                organization_id=org.id,
                role_id=primary_role["id"],
                status="active",
                last_login=datetime.now(timezone.utc),
                auth0_user_id=auth0_user_id,
                email_verified=bool(user_info.get("email_verified")),
                password_set=True,
            )
            db.add(new_user)
            synced_user = new_user
    await db.commit()

    product_token = id_token or tokens.get("access_token")

    return {
        "success": True,
        "identity_provider": "auth0",
        "token": product_token,
        "access_token": product_token,
        "oauth_access_token": tokens.get("access_token"),
        "id_token": id_token,
        "token_type": tokens.get("token_type"),
        "expires_in": expires_in,
        "scope": tokens.get("scope"),
        "user": user_info,
        "product": product_key,
        "redirect_uri": redirect_uri,
        "product_redirect_url": product_redirect_url,
        "return_to": product_redirect_url,
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
            "role": (primary_role or {}).get("name") if synced_user else None
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
            "organization_name": await get_organization_name(db, r.organization_id),
            "external_org_id": r.external_org_id,
            "auth0_org_id": r.auth0_org_id,
            "auth0_user_id": r.auth0_user_id,
            "name": r.name,
            "login_at": r.login_at.isoformat() if r.login_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None
        }
        for r in records
    ]

@api_router.get("/public/zitadel-config", tags=["Public API"])
async def get_zitadel_config():
    """
    Get current Zitadel environment configuration (for debugging).
    Does not expose secrets.
    """
    return {
        "domain": zitadel_mgmt.base_url,
        "default_org_id": ZITADEL_DEFAULT_ORG_ID[:10] + "..." if ZITADEL_DEFAULT_ORG_ID else None,
        "project_id": ZITADEL_PROJECT_ID[:10] + "..." if ZITADEL_PROJECT_ID else None,
        "redirect_uris": ZITADEL_REDIRECT_URIS,
        "post_logout_uris": ZITADEL_POST_LOGOUT_URIS,
        "configured": zitadel_mgmt.enabled,
    }

def resolve_zitadel_redirect_uri(product: Optional[str] = None, redirect_uri: Optional[str] = None) -> tuple[str, str]:
    requested_product = (product or "probestack").strip().lower().replace("-", "")
    product_key = {
        "probe": "probestack",
        "probestack": "probestack",
        "localhost": "local",
        "local": "local",
        "dev": "local",
        "catalog": "forgecatalog",
        "forgecatalog": "forgecatalog",
        "fuzz": "forgefuzz",
        "forgefuzz": "forgefuzz",
        "console": "console",
    }.get(requested_product, requested_product)

    if product_key not in ZITADEL_REDIRECT_URIS:
        raise HTTPException(status_code=400, detail=f"Unsupported Zitadel product: {product or product_key}")

    if redirect_uri:
        selected_redirect_uri = redirect_uri.strip()
        allowed_redirect_uris = set(ZITADEL_REDIRECT_URIS.values())
        if ZITADEL_SHARED_CALLBACK_URI:
            allowed_redirect_uris.add(ZITADEL_SHARED_CALLBACK_URI)
        if selected_redirect_uri not in allowed_redirect_uris:
            raise HTTPException(status_code=400, detail="redirect_uri is not registered for Zitadel login")
    else:
        selected_redirect_uri = ZITADEL_REDIRECT_URIS[product_key]

    return product_key, selected_redirect_uri

def resolve_zitadel_post_logout_uri(
    product: Optional[str] = None,
    post_logout_redirect_uri: Optional[str] = None
) -> tuple[str, str]:
    requested_product = (product or "probestack").strip().lower().replace("-", "")
    product_key = {
        "probe": "probestack",
        "probestack": "probestack",
        "localhost": "local",
        "local": "local",
        "dev": "local",
        "catalog": "forgecatalog",
        "forgecatalog": "forgecatalog",
        "fuzz": "forgefuzz",
        "forgefuzz": "forgefuzz",
        "console": "console",
    }.get(requested_product, requested_product)

    if product_key not in ZITADEL_POST_LOGOUT_URIS:
        raise HTTPException(status_code=400, detail=f"Unsupported Zitadel product: {product or product_key}")

    if post_logout_redirect_uri:
        selected_post_logout_uri = post_logout_redirect_uri.strip()
        matching_products = [
            key for key, allowed_post_logout_uri in ZITADEL_POST_LOGOUT_URIS.items()
            if allowed_post_logout_uri == selected_post_logout_uri
        ]
        if not matching_products:
            raise HTTPException(status_code=400, detail="post_logout_redirect_uri is not registered for Zitadel logout")
        if selected_post_logout_uri != ZITADEL_POST_LOGOUT_URIS[product_key]:
            raise HTTPException(status_code=400, detail="post_logout_redirect_uri does not match the selected Zitadel product")
    else:
        selected_post_logout_uri = ZITADEL_POST_LOGOUT_URIS[product_key]

    return product_key, selected_post_logout_uri

@api_router.post("/public/zitadel/auth/init", tags=["Public API - Zitadel"])
async def zitadel_init(data: ZitadelInitRequest, db: AsyncSession = Depends(get_db)):
    """
    Step 1: Initialize Zitadel authentication flow.
    """
    if not ZITADEL_CLIENT_ID or not zitadel_mgmt.base_url:
        raise HTTPException(status_code=500, detail="Zitadel login is not configured")
    if not data.email or "@" not in data.email:
        raise HTTPException(status_code=400, detail="Invalid email format")
    product_key, redirect_uri = resolve_zitadel_redirect_uri(data.product, data.redirect_uri)
    product_redirect_url = resolve_product_auth_return_url(product_key)

    email = data.email.lower().strip()
    email_domain = "@" + email.split("@")[1]

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
        raise HTTPException(status_code=404, detail=f"No organization found for email domain {email_domain}")

    selected_zitadel_org_id = None
    existing_user_result = await db.execute(select(UserModel).where(UserModel.email == email))
    existing_user = existing_user_result.scalar_one_or_none()
    if existing_user:
        zitadel_user = None
        if existing_user.zitadel_user_id:
            zitadel_user_result = await zitadel_mgmt.get_user_by_id(existing_user.zitadel_user_id)
            if zitadel_user_result.get("success"):
                zitadel_user = zitadel_user_result.get("user") or {}

        if not zitadel_user:
            zitadel_user_result = await zitadel_mgmt.get_user_by_email(
                email,
                organization_id=None,
                use_default_org=False,
            )
            if zitadel_user_result.get("success"):
                zitadel_user = zitadel_user_result.get("user") or {}
                zitadel_user_id = zitadel_user.get("userId") or zitadel_user.get("id")
                if zitadel_user_id and existing_user.zitadel_user_id != zitadel_user_id:
                    existing_user.zitadel_user_id = zitadel_user_id

        selected_zitadel_org_id = extract_zitadel_resource_owner(zitadel_user)
        if selected_zitadel_org_id:
            if (
                found_org.zitadel_org_id != selected_zitadel_org_id
                and (not found_org.zitadel_org_id or found_org.zitadel_org_id == ZITADEL_DEFAULT_ORG_ID)
            ):
                logger.info(
                    "Updating %s Zitadel org id from %s to %s based on user %s",
                    found_org.name,
                    found_org.zitadel_org_id,
                    selected_zitadel_org_id,
                    email,
                )
                found_org.zitadel_org_id = selected_zitadel_org_id
                found_org.updated_at = datetime.now(timezone.utc)
            if db.is_modified(found_org) or db.is_modified(existing_user):
                await db.commit()

    selected_zitadel_org_id = selected_zitadel_org_id or found_org.zitadel_org_id or ZITADEL_DEFAULT_ORG_ID
    if not selected_zitadel_org_id:
        raise HTTPException(
            status_code=400,
            detail=f"Organization {found_org.name} does not have Zitadel organization configured"
        )

    scope = " ".join([
        "openid",
        "profile",
        "email",
        "offline_access",
        "urn:zitadel:iam:user:resourceowner",
        f"urn:zitadel:iam:org:id:{selected_zitadel_org_id}",
    ])
    zitadel_params = {
        "client_id": ZITADEL_CLIENT_ID,
        "response_type": "code",
        "scope": scope,
        "redirect_uri": redirect_uri,
        "login_hint": email,
        "organization": selected_zitadel_org_id,
    }
    if data.state:
        zitadel_params["state"] = data.state
    else:
        zitadel_params["state"] = encode_product_oauth_state(product_key, product_redirect_url)

    authorize_url = f"{zitadel_mgmt.base_url}/oauth/v2/authorize?{urlencode(zitadel_params)}"

    return {
        "success": True,
        "identity_provider": "zitadel",
        "authorize_url": authorize_url,
        "organization": {
            "id": found_org.id,
            "name": found_org.name,
            "external_org_id": found_org.external_org_id,
            "zitadel_org_id": selected_zitadel_org_id,
        },
        "email": email,
        "domain": email_domain,
        "product": product_key,
        "redirect_uri": redirect_uri,
        "product_redirect_url": product_redirect_url,
        "return_to": product_redirect_url,
    }

def extract_zitadel_roles(decoded_token: dict) -> list[str]:
    role_claims = [
        decoded_token.get("urn:zitadel:iam:org:project:roles"),
        decoded_token.get("urn:zitadel:iam:org:projects:roles"),
        decoded_token.get("roles"),
    ]
    roles = []
    for claim in role_claims:
        if isinstance(claim, list):
            for item in claim:
                if isinstance(item, str):
                    roles.append(item)
                elif isinstance(item, dict):
                    roles.extend([key for key in item.keys() if key])
        elif isinstance(claim, dict):
            roles.extend([key for key in claim.keys() if key])
    return list(dict.fromkeys(roles))

def extract_zitadel_resource_owner(zitadel_user: dict) -> Optional[str]:
    if not zitadel_user:
        return None
    return (
        (zitadel_user.get("details") or {}).get("resourceOwner")
        or zitadel_user.get("resourceOwner")
        or zitadel_user.get("resourceOwnerId")
        or zitadel_user.get("organizationId")
    )

def encode_product_oauth_state(product: str, return_to: Optional[str] = None) -> str:
    state = {"product": product}
    if return_to:
        state["returnTo"] = return_to
        state["return_to"] = return_to
    payload = json.dumps(state, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

def token_hash(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def datetime_from_jwt_timestamp(value: Any) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError, OSError):
        return None

def get_login_record_identity(login_record) -> dict:
    if not login_record:
        return {}
    if isinstance(login_record, ZitadelLoginRecordModel):
        return {
            "provider": "zitadel",
            "subject": login_record.zitadel_user_id,
            "issuer": normalized_issuer_url(ZITADEL_DOMAIN),
        }
    if isinstance(login_record, Auth0LoginRecordModel):
        return {
            "provider": "auth0",
            "subject": login_record.auth0_user_id,
            "issuer": normalized_issuer_url(AUTH0_DOMAIN),
        }
    return {}

async def record_identity_session_revocation(
    db: AsyncSession,
    provider: str,
    token: Optional[str],
    login_record=None,
    reason: str = "logout",
) -> Optional[IdentitySessionRevocationModel]:
    decoded = decode_unverified_jwt_claims(token)
    record_identity = get_login_record_identity(login_record)
    issuer = normalized_issuer_url(decoded.get("iss") or record_identity.get("issuer") or expected_provider_issuer(provider))
    subject = decoded.get("sub") or record_identity.get("subject")
    if not issuer or not subject:
        return None

    expires_at = datetime_from_jwt_timestamp(decoded.get("exp"))
    if not expires_at and login_record and login_record.expires_at:
        expires_at = login_record.expires_at

    revocation = IdentitySessionRevocationModel(
        identity_provider=provider,
        issuer=issuer,
        subject=subject,
        session_id=decoded.get("sid"),
        token_hash=token_hash(token),
        login_record_id=login_record.id if login_record else None,
        email=(login_record.email if login_record else decoded.get("email")),
        reason=reason,
        expires_at=expires_at,
    )
    db.add(revocation)
    return revocation

async def get_identity_session_revocation(
    db: AsyncSession,
    provider: str,
    decoded_token: dict,
    token: Optional[str],
) -> Optional[IdentitySessionRevocationModel]:
    issuer = normalized_issuer_url(decoded_token.get("iss") or expected_provider_issuer(provider))
    subject = decoded_token.get("sub")
    if not issuer or not subject:
        return None

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    issued_at = datetime_from_jwt_timestamp(decoded_token.get("iat"))
    hashed = token_hash(token)

    exact_token_query = select(IdentitySessionRevocationModel).where(
        IdentitySessionRevocationModel.identity_provider == provider,
        IdentitySessionRevocationModel.issuer == issuer,
        IdentitySessionRevocationModel.token_hash == hashed,
        or_(
            IdentitySessionRevocationModel.expires_at.is_(None),
            IdentitySessionRevocationModel.expires_at > now,
        ),
    )
    if hashed:
        exact_result = await db.execute(exact_token_query.limit(1))
        exact_revocation = exact_result.scalar_one_or_none()
        if exact_revocation:
            return exact_revocation

    subject_query = select(IdentitySessionRevocationModel).where(
        IdentitySessionRevocationModel.identity_provider == provider,
        IdentitySessionRevocationModel.issuer == issuer,
        IdentitySessionRevocationModel.subject == subject,
        or_(
            IdentitySessionRevocationModel.expires_at.is_(None),
            IdentitySessionRevocationModel.expires_at > now,
        ),
    )
    if issued_at:
        subject_query = subject_query.where(IdentitySessionRevocationModel.revoked_at >= issued_at)
    subject_query = subject_query.order_by(IdentitySessionRevocationModel.revoked_at.desc()).limit(1)
    result = await db.execute(subject_query)
    return result.scalar_one_or_none()

def set_product_auth_cookies(response: Response, token: Optional[str], expires_in: Any = None) -> None:
    if not token:
        return
    try:
        cookie_max_age = max(1, min(int(float(expires_in or 86400)), 86400))
    except (TypeError, ValueError):
        cookie_max_age = 86400
    for cookie_name, cookie_value in {
        "ps_auth_token": token,
        "ps_auth_session": "true",
    }.items():
        response.set_cookie(
            key=cookie_name,
            value=cookie_value,
            max_age=cookie_max_age,
            path="/",
            domain=".probestack.io",
            secure=True,
            httponly=True,
            samesite="lax",
        )

def clear_product_auth_cookies(response: Response) -> None:
    for cookie_name in ("ps_auth_token", "ps_auth_session"):
        response.delete_cookie(
            key=cookie_name,
            path="/",
            domain=".probestack.io",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        response.delete_cookie(
            key=cookie_name,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )

def decode_unverified_jwt_claims(token: Optional[str]) -> dict:
    if not token:
        return {}
    try:
        return jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
            },
        )
    except Exception:
        return {}

def infer_identity_provider_from_token(token: Optional[str], requested_provider: Optional[str] = None) -> Optional[str]:
    if requested_provider:
        return normalize_identity_provider(requested_provider)
    decoded = decode_unverified_jwt_claims(token)
    issuer = (decoded.get("iss") or "").strip()
    if not issuer:
        return None
    if normalized_issuer_url(issuer) == normalized_issuer_url(PROBESTACK_TOKEN_ISSUER):
        return None
    return infer_identity_provider_from_issuer(issuer)

def is_probestack_context_token_claims(decoded: dict) -> bool:
    if not decoded:
        return False
    return (
        decoded.get("token_type") == "probestack_user_context"
        or normalized_issuer_url(decoded.get("iss") or "") == normalized_issuer_url(PROBESTACK_TOKEN_ISSUER)
    )

def verify_context_token_claims(token: Optional[str]) -> dict:
    if not token:
        return {}
    unverified = decode_unverified_jwt_claims(token)
    if not is_probestack_context_token_claims(unverified):
        return {}
    try:
        return jwt.decode(
            token,
            get_context_token_public_key(),
            algorithms=[PROBESTACK_CONTEXT_TOKEN_ALGORITHM],
            issuer=PROBESTACK_TOKEN_ISSUER,
            options={"verify_aud": False},
        )
    except Exception:
        return {}

async def get_latest_logout_record_for_context(
    db: AsyncSession,
    provider: str,
    context_claims: dict,
):
    model = ZitadelLoginRecordModel if provider == "zitadel" else Auth0LoginRecordModel
    email = (context_claims.get("email") or context_claims.get("userEmail") or "").strip().lower()
    organization_id = context_claims.get("organization_id") or context_claims.get("userOrgId")
    if not email:
        return None

    query = select(model).where(func.lower(model.email) == email)
    if organization_id:
        query = query.where(model.organization_id == organization_id)
    result = await db.execute(query.order_by(model.login_at.desc()).limit(1))
    record = result.scalar_one_or_none()
    if record:
        return record

    result = await db.execute(
        select(model)
        .where(func.lower(model.email) == email)
        .order_by(model.login_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()

async def get_logout_login_record_from_context(
    db: AsyncSession,
    provider: Optional[str],
    context_claims: dict,
) -> tuple[Optional[str], Any]:
    providers = [provider] if provider in SUPPORTED_IDENTITY_PROVIDERS else ["zitadel", "auth0"]
    best_provider = None
    best_record = None
    best_login_at = 0.0

    for candidate_provider in providers:
        record = await get_latest_logout_record_for_context(db, candidate_provider, context_claims)
        if not record:
            continue
        try:
            login_at = record.login_at.timestamp() if record.login_at else 0.0
        except Exception:
            login_at = 0.0
        if not best_record or login_at >= best_login_at:
            best_provider = candidate_provider
            best_record = record
            best_login_at = login_at

    return best_provider, best_record

def infer_logout_product(
    provider: str,
    product: Optional[str],
    post_logout_redirect_uri: Optional[str],
) -> str:
    if product:
        return product
    selected_uri = (post_logout_redirect_uri or "").strip()
    if selected_uri:
        uri_map = ZITADEL_POST_LOGOUT_URIS if provider == "zitadel" else AUTH0_POST_LOGOUT_URIS
        for product_key, allowed_uri in uri_map.items():
            if allowed_uri == selected_uri:
                return product_key
    return "probestack"

async def get_logout_login_record(
    db: AsyncSession,
    provider: str,
    login_record_id: Optional[str],
    token: Optional[str],
):
    model = ZitadelLoginRecordModel if provider == "zitadel" else Auth0LoginRecordModel
    if login_record_id:
        result = await db.execute(select(model).where(model.id == login_record_id))
        record = result.scalar_one_or_none()
        if record:
            return record

    if not token:
        return None

    result = await db.execute(
        select(model)
        .where(model.id_token == token)
        .order_by(model.login_at.desc())
        .limit(1)
    )
    record = result.scalar_one_or_none()
    if record:
        return record

    result = await db.execute(
        select(model)
        .where(model.access_token == token)
        .order_by(model.login_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()

async def revoke_provider_token(provider: str, token: Optional[str]) -> dict:
    if not token:
        return {"success": False, "skipped": True, "reason": "no_token"}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            if provider == "zitadel":
                if not ZITADEL_CLIENT_ID or not ZITADEL_CLIENT_SECRET or not zitadel_mgmt.base_url:
                    return {"success": False, "skipped": True, "reason": "zitadel_not_configured"}
                response = await client.post(
                    f"{zitadel_mgmt.base_url}/oauth/v2/revoke",
                    data={
                        "client_id": ZITADEL_CLIENT_ID,
                        "client_secret": ZITADEL_CLIENT_SECRET,
                        "token": token,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            else:
                if not AUTH0_CLIENT_ID or not AUTH0_CLIENT_SECRET or not AUTH0_DOMAIN:
                    return {"success": False, "skipped": True, "reason": "auth0_not_configured"}
                response = await client.post(
                    f"https://{AUTH0_DOMAIN}/oauth/revoke",
                    json={
                        "client_id": AUTH0_CLIENT_ID,
                        "client_secret": AUTH0_CLIENT_SECRET,
                        "token": token,
                    },
                    headers={"Content-Type": "application/json"},
                )
    except httpx.RequestError as exc:
        logger.warning(f"{provider} token revocation request failed: {exc}")
        return {"success": False, "error": str(exc)}

    if response.status_code in (200, 204):
        return {"success": True, "status_code": response.status_code}

    logger.warning(f"{provider} token revocation failed: {response.text}")
    return {"success": False, "status_code": response.status_code, "error": response.text}

def clear_login_record_tokens(login_record) -> None:
    if not login_record:
        return
    login_record.access_token = None
    login_record.id_token = None
    if hasattr(login_record, "refresh_token"):
        login_record.refresh_token = None
    login_record.expires_at = datetime.now(timezone.utc)
    login_record.expires_in = 0

@api_router.post("/public/zitadel/auth/callback", tags=["Public API - Zitadel"])
async def zitadel_callback(
    data: ZitadelCallbackRequest,
    fastapi_response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Step 2: Exchange Zitadel authorization code for tokens and sync user locally.
    """
    if not data.code:
        raise HTTPException(status_code=400, detail="Authorization code is required")
    if not ZITADEL_CLIENT_ID or not ZITADEL_CLIENT_SECRET or not zitadel_mgmt.base_url:
        raise HTTPException(status_code=500, detail="Zitadel login is not configured")
    product_key, redirect_uri = resolve_zitadel_redirect_uri(data.product, data.redirect_uri)
    product_redirect_url = resolve_product_auth_return_url(product_key)

    token_payload = {
        "grant_type": "authorization_code",
        "client_id": ZITADEL_CLIENT_ID,
        "client_secret": ZITADEL_CLIENT_SECRET,
        "code": data.code,
        "redirect_uri": redirect_uri,
    }

    async with httpx.AsyncClient() as client:
        try:
            token_response = await client.post(
                f"{zitadel_mgmt.base_url}/oauth/v2/token",
                data=token_payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0,
            )
            if token_response.status_code != 200:
                error_detail = token_response.text
                try:
                    error_json = token_response.json()
                    error_detail = error_json.get("error_description", error_json.get("error", token_response.text))
                except Exception:
                    pass
                raise HTTPException(
                    status_code=token_response.status_code,
                    detail=f"Zitadel token exchange failed: {error_detail}"
                )
            tokens = token_response.json()
        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Failed to connect to Zitadel: {str(e)}")

    id_token = tokens.get("id_token")
    user_info = {}
    decoded = {}
    zitadel_org_id = None
    zitadel_user_id = None
    zitadel_roles = []

    if id_token:
        try:
            decoded = jwt.decode(id_token, options={"verify_signature": False})
            user_info = {
                "email": decoded.get("email"),
                "name": decoded.get("name") or decoded.get("preferred_username"),
                "nickname": decoded.get("preferred_username"),
                "picture": decoded.get("picture"),
                "email_verified": decoded.get("email_verified"),
            }
            zitadel_org_id = (
                decoded.get("urn:zitadel:iam:user:resourceowner:id")
                or decoded.get("org_id")
            )
            zitadel_user_id = decoded.get("sub")
            zitadel_roles = extract_zitadel_roles(decoded)
        except Exception as e:
            logging.warning(f"Failed to decode Zitadel id_token: {e}")

    access_token = tokens.get("access_token")
    if access_token and (not user_info.get("email") or not user_info.get("name")):
        try:
            async with httpx.AsyncClient() as client:
                userinfo_response = await client.get(
                    f"{zitadel_mgmt.base_url}/oidc/v1/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=30.0,
                )
            if userinfo_response.status_code == 200:
                userinfo = userinfo_response.json()
                user_info = {
                    "email": user_info.get("email") or userinfo.get("email"),
                    "name": user_info.get("name") or userinfo.get("name") or userinfo.get("preferred_username"),
                    "nickname": user_info.get("nickname") or userinfo.get("preferred_username"),
                    "picture": user_info.get("picture") or userinfo.get("picture"),
                    "email_verified": (
                        user_info.get("email_verified")
                        if user_info.get("email_verified") is not None
                        else userinfo.get("email_verified")
                    ),
                }
                zitadel_org_id = (
                    zitadel_org_id
                    or userinfo.get("urn:zitadel:iam:user:resourceowner:id")
                    or userinfo.get("org_id")
                )
                zitadel_user_id = zitadel_user_id or userinfo.get("sub")
                zitadel_roles = list(dict.fromkeys(zitadel_roles + extract_zitadel_roles(userinfo)))
            else:
                logger.warning(f"Zitadel userinfo lookup failed: {userinfo_response.text}")
        except httpx.RequestError as e:
            logger.warning(f"Failed to connect to Zitadel userinfo endpoint: {e}")

    email = user_info.get("email") or data.email
    org = None

    if zitadel_org_id:
        result = await db.execute(
            select(OrganizationModel).where(OrganizationModel.zitadel_org_id == zitadel_org_id)
        )
        org = result.scalar_one_or_none()

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

    expires_in = tokens.get("expires_in", 86400)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    login_record = ZitadelLoginRecordModel(
        email=email or "unknown",
        organization_id=org.id if org else "unknown",
        external_org_id=org.external_org_id if org else zitadel_org_id,
        zitadel_org_id=zitadel_org_id,
        zitadel_user_id=zitadel_user_id,
        name=user_info.get("name"),
        picture=user_info.get("picture"),
        access_token=tokens.get("access_token"),
        refresh_token=tokens.get("refresh_token"),
        id_token=id_token,
        token_type=tokens.get("token_type"),
        expires_in=expires_in,
        expires_at=expires_at,
    )
    db.add(login_record)

    synced_user = None
    synced_roles = []
    primary_role = None
    metadata_sync = {}

    if org and email:
        result = await db.execute(
            select(UserModel).where(
                UserModel.email == email,
                UserModel.organization_id == org.id,
            )
        )
        existing_user = result.scalar_one_or_none()

        await ensure_standard_roles_for_organization(db, org.id)
        for role_name in zitadel_roles:
            standard_name = await map_to_standard_role_name(db, role_name, DEFAULT_CONSUMER_ROLE_SLUG)
            role = await get_standard_role(db, org.id, standard_name)
            role_payload = {"id": role.id, "name": role.name}
            if role_payload not in synced_roles:
                synced_roles.append(role_payload)

        primary_role = synced_roles[0] if synced_roles else None
        if existing_user:
            existing_user.name = user_info.get("name") or existing_user.name
            if zitadel_user_id and not existing_user.zitadel_user_id:
                existing_user.zitadel_user_id = zitadel_user_id
            existing_user.last_login = datetime.now(timezone.utc)
            synced_user = existing_user
            primary_role = {
                "id": existing_user.role_id,
                "name": await get_role_name(db, existing_user.role_id, "API/Agent Consumer"),
            }
        else:
            if not primary_role:
                default_role = await get_standard_role(db, org.id)
                primary_role = {"id": default_role.id, "name": default_role.name}
            requested_role = await get_standard_role(db, org.id, primary_role["name"])
            resolved_role, onboarding_role_lookup = await resolve_new_user_role(db, org, email, requested_role)
            primary_role = {"id": resolved_role.id, "name": resolved_role.name}
            new_user = UserModel(
                email=email,
                name=user_info.get("name") or user_info.get("nickname") or email.split("@")[0],
                organization_id=org.id,
                role_id=primary_role["id"],
                status="active",
                last_login=datetime.now(timezone.utc),
                zitadel_user_id=zitadel_user_id,
                email_verified=bool(user_info.get("email_verified")),
                password_set=True,
            )
            db.add(new_user)
            synced_user = new_user

    if org and org.zitadel_org_id:
        metadata_sync["organization"] = await zitadel_mgmt.set_organization_metadata(
            org.zitadel_org_id,
            build_probestack_org_metadata(org),
        )

    if synced_user and zitadel_user_id:
        await db.flush()
        if not synced_user.zitadel_user_id:
            synced_user.zitadel_user_id = zitadel_user_id
        role_name_for_metadata = (primary_role or {}).get("name") or await get_role_name(
            db,
            synced_user.role_id,
            "API/Agent Consumer",
        )
        user_metadata = await build_probestack_user_metadata(
            db,
            synced_user,
            synced_user.email,
            org,
            role_name_for_metadata,
        )
        metadata_sync["user"] = await zitadel_mgmt.set_user_metadata(zitadel_user_id, user_metadata)

    admin_login = None
    if email:
        admin_result = await db.execute(select(AdminModel).where(AdminModel.email == email))
        admin = admin_result.scalar_one_or_none()
        if admin and admin.is_active:
            organization_name = await get_organization_name(db, admin.organization_id)
            admin_login = {
                "token": create_token(admin.id, admin.email, admin.role, admin.organization_id),
                "admin": {
                    "id": admin.id,
                    "email": admin.email,
                    "name": admin.name,
                    "role": admin.role,
                    "organization_id": admin.organization_id,
                    "organization_name": organization_name,
                    "is_active": admin.is_active,
                },
            }

    await db.commit()

    product_token = id_token or tokens.get("access_token")
    admin_token = admin_login["token"] if admin_login else None

    return {
        "success": True,
        "identity_provider": "zitadel",
        "token": product_token,
        "admin_token": admin_token,
        "admin": admin_login["admin"] if admin_login else None,
        "access_token": product_token,
        "oauth_access_token": tokens.get("access_token"),
        "refresh_token": tokens.get("refresh_token"),
        "id_token": id_token,
        "token_type": tokens.get("token_type"),
        "expires_in": expires_in,
        "scope": tokens.get("scope"),
        "user": user_info,
        "product": product_key,
        "redirect_uri": redirect_uri,
        "product_redirect_url": product_redirect_url,
        "return_to": product_redirect_url,
        "organization": {
            "id": org.id if org else None,
            "name": org.name if org else None,
            "external_org_id": org.external_org_id if org else zitadel_org_id,
        },
        "login_record_id": login_record.id,
        "metadata_sync": metadata_sync,
        "synced_user": {
            "id": synced_user.id if synced_user else None,
            "email": synced_user.email if synced_user else None,
            "name": synced_user.name if synced_user else None,
            "role": (primary_role or {}).get("name") if synced_user else None,
        } if synced_user else None,
        "synced_roles": synced_roles,
        "zitadel_roles": zitadel_roles,
    }

@api_router.post("/public/zitadel/auth/refresh", tags=["Public API - Zitadel"])
async def zitadel_refresh_token(data: ZitadelRefreshTokenRequest):
    """
    Exchange a Zitadel refresh token for a new access token.
    """
    if not data.refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token is required")
    if not ZITADEL_CLIENT_ID or not ZITADEL_CLIENT_SECRET or not zitadel_mgmt.base_url:
        raise HTTPException(status_code=500, detail="Zitadel refresh is not configured")

    token_payload = {
        "grant_type": "refresh_token",
        "client_id": ZITADEL_CLIENT_ID,
        "client_secret": ZITADEL_CLIENT_SECRET,
        "refresh_token": data.refresh_token,
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{zitadel_mgmt.base_url}/oauth/v2/token",
                data=token_payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0,
            )
            if response.status_code != 200:
                error_detail = response.text
                try:
                    error_json = response.json()
                    error_detail = error_json.get("error_description", error_json.get("error", response.text))
                except Exception:
                    pass
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Zitadel refresh token exchange failed: {error_detail}"
                )
            tokens = response.json()
        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Failed to connect to Zitadel: {str(e)}")

    return {
        "success": True,
        "identity_provider": "zitadel",
        "access_token": tokens.get("access_token"),
        "refresh_token": tokens.get("refresh_token"),
        "id_token": tokens.get("id_token"),
        "token_type": tokens.get("token_type"),
        "expires_in": tokens.get("expires_in"),
        "scope": tokens.get("scope"),
    }

@api_router.get("/public/zitadel/auth/logout-url", tags=["Public API - Zitadel"])
async def zitadel_logout_url(
    product: Optional[str] = "probestack",
    post_logout_redirect_uri: Optional[str] = None,
    id_token_hint: Optional[str] = None,
    state: Optional[str] = None,
    logout_hint: Optional[str] = None,
):
    """
    Build a Zitadel RP-initiated logout URL for the selected product.
    """
    if not ZITADEL_CLIENT_ID or not zitadel_mgmt.base_url:
        raise HTTPException(status_code=500, detail="Zitadel logout is not configured")

    product_key, selected_post_logout_uri = resolve_zitadel_post_logout_uri(product, post_logout_redirect_uri)
    logout_params = {
        "client_id": ZITADEL_CLIENT_ID,
        "post_logout_redirect_uri": selected_post_logout_uri,
    }
    if id_token_hint:
        logout_params["id_token_hint"] = id_token_hint
    if state:
        logout_params["state"] = state
    if logout_hint:
        logout_params["logout_hint"] = logout_hint

    return {
        "success": True,
        "identity_provider": "zitadel",
        "logout_url": f"{zitadel_mgmt.base_url}/oidc/v1/end_session?{urlencode(logout_params)}",
        "product": product_key,
        "post_logout_redirect_uri": selected_post_logout_uri,
    }

@api_router.post("/public/auth/refresh", tags=["Public API - Identity"])
async def refresh_active_identity_provider_token(
    data: ZitadelRefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    """Refresh tokens through the active identity provider when supported."""
    active_provider = await get_active_identity_provider(db)
    if active_provider == "zitadel":
        return await zitadel_refresh_token(data)
    raise HTTPException(status_code=400, detail="Auth0 refresh is not implemented for the generic identity endpoint")

@api_router.post("/public/auth/session/validate", tags=["Public API - Identity"])
async def validate_identity_provider_session(
    data: IdentitySessionValidateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify a provider ID token and check central logout revocation state.

    Products should call this before accepting a stored provider token. If
    active=false, clear local storage/cookies and send the user to login.
    """
    token = data.id_token or data.token or request.cookies.get("ps_auth_token")
    if not token:
        return {"success": True, "active": False, "reason": "missing_token"}

    context_claims = verify_context_token_claims(token)
    if context_claims:
        requested_provider = normalize_identity_provider(data.identity_provider) if data.identity_provider else None
        provider, login_record = await get_logout_login_record_from_context(db, requested_provider, context_claims)
        provider = provider or requested_provider or await get_active_identity_provider(db)
        revocation = await get_identity_session_revocation(db, provider, context_claims, token)
        if revocation:
            return {
                "success": True,
                "active": False,
                "reason": "revoked",
                "identity_provider": provider,
                "token_type": "probestack_user_context",
                "revoked_at": revocation.revoked_at.isoformat() if revocation.revoked_at else None,
                "revocation_id": revocation.id,
            }

        return {
            "success": True,
            "active": True,
            "identity_provider": provider,
            "token_type": "probestack_user_context",
            "issuer": context_claims.get("iss"),
            "subject": context_claims.get("sub"),
            "session_id": context_claims.get("jti"),
            "email": context_claims.get("email"),
            "expires_at": context_claims.get("exp"),
            "login_record_id": login_record.id if login_record else None,
        }

    decoded, provider = verify_provider_id_token(token, data.identity_provider)
    revocation = await get_identity_session_revocation(db, provider, decoded, token)
    if revocation:
        return {
            "success": True,
            "active": False,
            "reason": "revoked",
            "identity_provider": provider,
            "revoked_at": revocation.revoked_at.isoformat() if revocation.revoked_at else None,
            "revocation_id": revocation.id,
        }

    return {
        "success": True,
        "active": True,
        "identity_provider": provider,
        "issuer": decoded.get("iss"),
        "subject": decoded.get("sub"),
        "session_id": decoded.get("sid"),
        "email": decoded.get("email"),
        "expires_at": decoded.get("exp"),
    }

@api_router.get("/public/auth/logout-url", tags=["Public API - Identity"])
async def active_identity_provider_logout_url(
    product: Optional[str] = "probestack",
    post_logout_redirect_uri: Optional[str] = None,
    id_token_hint: Optional[str] = None,
    state: Optional[str] = None,
    logout_hint: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Build a logout URL for the active identity provider."""
    active_provider = await get_active_identity_provider(db)
    if active_provider == "zitadel":
        return await zitadel_logout_url(product, post_logout_redirect_uri, id_token_hint, state, logout_hint)

    require_identity_provider_configured("auth0")
    product_key, return_to = resolve_auth0_post_logout_uri(product, post_logout_redirect_uri)
    logout_params = {
        "client_id": AUTH0_CLIENT_ID,
        "returnTo": return_to,
    }
    if state:
        logout_params["state"] = state
    return {
        "success": True,
        "identity_provider": "auth0",
        "logout_url": f"https://{AUTH0_DOMAIN}/v2/logout?{urlencode(logout_params)}",
        "product": product_key,
        "post_logout_redirect_uri": return_to,
    }

@api_router.post("/public/auth/logout", tags=["Public API - Identity"])
async def logout_identity_provider_session(
    request: Request,
    fastapi_response: Response,
    data: Optional[IdentityLogoutRequest] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Clear product auth locally and return the provider logout URL.

    The caller must redirect the browser to logout_url so Auth0/Zitadel can
    clear its own SSO cookie. JWT access/id tokens remain valid until exp.
    """
    data = data or IdentityLogoutRequest()
    clear_product_auth_cookies(fastapi_response)

    cookie_context_token = request.cookies.get("ps_auth_token")
    context_token = cookie_context_token
    context_claims = verify_context_token_claims(context_token)
    if not context_claims:
        for candidate_token in (data.token, data.id_token):
            candidate_claims = verify_context_token_claims(candidate_token)
            if candidate_claims:
                context_token = candidate_token
                context_claims = candidate_claims
                break

    provider_token = data.id_token
    if not provider_token and (not context_claims or data.token != context_token):
        provider_token = data.token
    token = provider_token or context_token
    provider = infer_identity_provider_from_token(provider_token, data.identity_provider)
    login_record = None

    if context_claims:
        context_provider, context_record = await get_logout_login_record_from_context(db, provider, context_claims)
        if context_record:
            provider = context_provider
            login_record = context_record

    if not provider and data.login_record_id:
        for candidate_provider in ("zitadel", "auth0"):
            candidate_record = await get_logout_login_record(db, candidate_provider, data.login_record_id, None)
            if candidate_record:
                provider = candidate_provider
                login_record = candidate_record
                break

    if not provider:
        provider = await get_active_identity_provider(db)

    if not login_record:
        login_record = await get_logout_login_record(db, provider, data.login_record_id, provider_token or context_token)

    id_token_hint = data.id_token
    token_claims = decode_unverified_jwt_claims(provider_token)
    if not id_token_hint and token_claims.get("iss") and not is_probestack_context_token_claims(token_claims):
        id_token_hint = provider_token
    if not id_token_hint and login_record:
        id_token_hint = login_record.id_token

    logout_hint = data.logout_hint or (login_record.email if login_record else None) or context_claims.get("email")
    product = infer_logout_product(provider, data.product, data.post_logout_redirect_uri)

    refresh_token = data.refresh_token
    if not refresh_token and login_record and hasattr(login_record, "refresh_token"):
        refresh_token = login_record.refresh_token

    revoke_token = refresh_token
    if not revoke_token and provider == "zitadel" and login_record:
        revoke_token = login_record.access_token

    provider_revocation = await revoke_provider_token(provider, revoke_token)
    session_revocation = await record_identity_session_revocation(
        db,
        provider,
        id_token_hint or (None if context_claims else token),
        login_record,
    )
    context_session_revocation = None
    if context_claims and context_token:
        context_session_revocation = await record_identity_session_revocation(
            db,
            provider,
            context_token,
            login_record,
        )

    if login_record:
        clear_login_record_tokens(login_record)
    if login_record or session_revocation or context_session_revocation:
        await db.commit()

    if provider == "zitadel":
        if not ZITADEL_CLIENT_ID or not zitadel_mgmt.base_url:
            raise HTTPException(status_code=500, detail="Zitadel logout is not configured")
        product_key, post_logout_uri = resolve_zitadel_post_logout_uri(product, data.post_logout_redirect_uri)
        logout_params = {
            "client_id": ZITADEL_CLIENT_ID,
            "post_logout_redirect_uri": post_logout_uri,
        }
        if id_token_hint:
            logout_params["id_token_hint"] = id_token_hint
        if data.state:
            logout_params["state"] = data.state
        if logout_hint:
            logout_params["logout_hint"] = logout_hint
        logout_url = f"{zitadel_mgmt.base_url}/oidc/v1/end_session?{urlencode(logout_params)}"
    else:
        require_identity_provider_configured("auth0")
        product_key, post_logout_uri = resolve_auth0_post_logout_uri(product, data.post_logout_redirect_uri)
        logout_params = {
            "client_id": AUTH0_CLIENT_ID,
            "returnTo": post_logout_uri,
        }
        if data.state:
            logout_params["state"] = data.state
        logout_url = f"https://{AUTH0_DOMAIN}/v2/logout?{urlencode(logout_params)}"

    return {
        "success": True,
        "identity_provider": provider,
        "logout_url": logout_url,
        "redirect_required": True,
        "cleared_cookies": True,
        "revocation": provider_revocation,
        "session_revocation": {
            "id": (session_revocation or context_session_revocation).id,
            "subject": (session_revocation or context_session_revocation).subject,
            "revoked_at": (session_revocation or context_session_revocation).revoked_at.isoformat()
            if (session_revocation or context_session_revocation).revoked_at else None,
        } if (session_revocation or context_session_revocation) else None,
        "product": product_key,
        "post_logout_redirect_uri": post_logout_uri,
        "login_record_id": login_record.id if login_record else None,
    }

@api_router.get("/public/auth/logout/redirect", tags=["Public API - Identity"])
async def logout_identity_provider_session_redirect(
    request: Request,
    identity_provider: Optional[str] = None,
    login_record_id: Optional[str] = None,
    product: Optional[str] = None,
    post_logout_redirect_uri: Optional[str] = None,
    state: Optional[str] = None,
    logout_hint: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Browser-facing logout route.

    Use this when the browser should receive cookie deletion headers directly
    and then be redirected through the upstream provider logout endpoint.
    """
    token = request.cookies.get("ps_auth_token")
    context_claims = verify_context_token_claims(token)
    provider = infer_identity_provider_from_token(token, identity_provider)
    login_record = None

    if context_claims:
        context_provider, context_record = await get_logout_login_record_from_context(db, provider, context_claims)
        if context_record:
            provider = context_provider
            login_record = context_record

    if not provider and login_record_id:
        for candidate_provider in ("zitadel", "auth0"):
            candidate_record = await get_logout_login_record(db, candidate_provider, login_record_id, None)
            if candidate_record:
                provider = candidate_provider
                login_record = candidate_record
                break

    if not provider:
        provider = await get_active_identity_provider(db)

    if not login_record:
        login_record = await get_logout_login_record(db, provider, login_record_id, token)

    token_claims = decode_unverified_jwt_claims(token)
    id_token_hint = token if token_claims.get("iss") and not is_probestack_context_token_claims(token_claims) else None
    if not id_token_hint and login_record:
        id_token_hint = login_record.id_token

    selected_logout_hint = logout_hint or (login_record.email if login_record else None) or context_claims.get("email")
    selected_product = infer_logout_product(provider, product, post_logout_redirect_uri)

    revoke_token = None
    if login_record and hasattr(login_record, "refresh_token"):
        revoke_token = login_record.refresh_token
    if not revoke_token and provider == "zitadel" and login_record:
        revoke_token = login_record.access_token
    await revoke_provider_token(provider, revoke_token)
    session_revocation = await record_identity_session_revocation(
        db,
        provider,
        id_token_hint or (None if context_claims else token),
        login_record,
    )
    context_session_revocation = None
    if context_claims and token:
        context_session_revocation = await record_identity_session_revocation(
            db,
            provider,
            token,
            login_record,
        )

    if login_record:
        clear_login_record_tokens(login_record)
    if login_record or session_revocation or context_session_revocation:
        await db.commit()

    if provider == "zitadel":
        if not ZITADEL_CLIENT_ID or not zitadel_mgmt.base_url:
            raise HTTPException(status_code=500, detail="Zitadel logout is not configured")
        _, post_logout_uri = resolve_zitadel_post_logout_uri(selected_product, post_logout_redirect_uri)
        logout_params = {
            "client_id": ZITADEL_CLIENT_ID,
            "post_logout_redirect_uri": post_logout_uri,
        }
        if id_token_hint:
            logout_params["id_token_hint"] = id_token_hint
        if state:
            logout_params["state"] = state
        if selected_logout_hint:
            logout_params["logout_hint"] = selected_logout_hint
        logout_url = f"{zitadel_mgmt.base_url}/oidc/v1/end_session?{urlencode(logout_params)}"
    else:
        require_identity_provider_configured("auth0")
        _, post_logout_uri = resolve_auth0_post_logout_uri(selected_product, post_logout_redirect_uri)
        logout_params = {
            "client_id": AUTH0_CLIENT_ID,
            "returnTo": post_logout_uri,
        }
        if state:
            logout_params["state"] = state
        logout_url = f"https://{AUTH0_DOMAIN}/v2/logout?{urlencode(logout_params)}"

    redirect_response = RedirectResponse(url=logout_url, status_code=302)
    clear_product_auth_cookies(redirect_response)
    return redirect_response

@api_router.get("/zitadel-logins", tags=["Admin - Zitadel"])
async def get_zitadel_logins(
    organization_id: Optional[str] = None,
    limit: int = 100,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get Zitadel login records (Super Admin only)"""
    query = select(ZitadelLoginRecordModel).order_by(ZitadelLoginRecordModel.login_at.desc())

    if organization_id:
        query = query.where(ZitadelLoginRecordModel.organization_id == organization_id)

    query = query.limit(limit)
    result = await db.execute(query)
    records = result.scalars().all()

    return [
        {
            "id": r.id,
            "email": r.email,
            "organization_id": r.organization_id,
            "organization_name": await get_organization_name(db, r.organization_id),
            "external_org_id": r.external_org_id,
            "zitadel_org_id": r.zitadel_org_id,
            "zitadel_user_id": r.zitadel_user_id,
            "name": r.name,
            "login_at": r.login_at.isoformat() if r.login_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
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
    - `requested_plans`: List of Plan IDs (required) - e.g., ['plan_forgeq_enterprise', 'plan_agentic_ai_enterprise_plus']
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
    """Approve an individual user request with the active identity provider."""
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
    
    no_org = await get_or_create_individual_users_org(db)
    
    role = await get_standard_role(db, no_org.id)
    role, onboarding_role_lookup = await resolve_new_user_role(db, no_org, request.email, role)
    
    # Create user with first_login_token for setup flow
    user = UserModel(
        email=request.email,
        name=request.name,
        organization_id=no_org.id,
        role_id=role.id,
        status="pending_verification",
        email_verified=False,
        password_set=False,
        first_login_token=secrets.token_urlsafe(32)
    )
    db.add(user)
    await db.flush()
    await replace_user_role_assignments(db, user, [role])
    
    active_provider = await get_active_identity_provider(db)
    provider_user_result = await provision_user_for_active_provider(
        db,
        user,
        request.email,
        request.name,
        {
            "probestack_user_id": user.id,
            "organization_id": no_org.id,
            "organization_name": no_org.name,
        },
        no_org,
        role.name,
        active_provider,
    )
    if not provider_user_result.get("success"):
        raise HTTPException(
            status_code=502,
            detail=f"Failed to create user in {active_provider.upper()}: {provider_user_result.get('error') or 'unknown error'}"
        )
    
    requested_tools = json.loads(request.requested_tools) if request.requested_tools else []
    subscription = await create_individual_user_subscription(
        db,
        user=user,
        plan=plan,
        requested_tools=requested_tools,
        source_request=request,
    )
    
    # Update request
    request.status = "approved"
    request.approved_at = datetime.now(timezone.utc)
    request.assigned_user_id = user.id
    request.updated_at = datetime.now(timezone.utc)
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()
    
    # Generate setup account URL for the user
    setup_account_url = build_setup_account_url(user.email, user.first_login_token) or f"/setup-account?email={user.email}&token={user.first_login_token}"

    try:
        email_result = send_request_decision_email(
            to_email=request.email,
            recipient_name=request.name,
            request_name="individual user request",
            status="approved",
            organization_name=no_org.name,
            next_steps="Your access has been approved. Please set up your account, verify your email, and then sign in to ProbeStack.",
            action_url=setup_account_url,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "Individual user approval email was not sent for %s: %s. To: %s. Bcc: %s",
                request.id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc"),
            )
    except Exception as exc:
        logger.error("Failed to build individual user approval email for %s: %s", request.id, exc)
    
    return {
        "message": f"Individual user request approved for {request.name}",
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "organization_name": no_org.name,
            "auth0_user_id": user.auth0_user_id,
            "zitadel_user_id": user.zitadel_user_id,
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

    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    try:
        email_result = send_request_decision_email(
            to_email=request.email,
            recipient_name=request.name,
            request_name="individual user request",
            status="rejected",
            organization_name="ProbeStack",
            reason=reason,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "Individual user rejection email was not sent for %s: %s. To: %s. Bcc: %s",
                request.id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc"),
            )
    except Exception as exc:
        logger.error("Failed to build individual user rejection email for %s: %s", request.id, exc)

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
    await ensure_standard_roles_for_organization(db, org.id)
    active_provider = await get_active_identity_provider(db)
    provider_result = await provision_organization_for_active_provider(db, org, active_provider)
    if not provider_result.get("success"):
        raise HTTPException(
            status_code=502,
            detail=f"Failed to create organization in {active_provider.upper()}: {provider_result.get('error') or 'unknown error'}"
        )
    
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
            plan_id=plan.id,
            status="active",
            start_date=now,
            end_date=now + timedelta(days=30),
            amount=plan_amount,
            quota=int(getattr(plan, "api_limit", 0) or 0),
            used_quota=0,
        )
        db.add(subscription)
        await db.flush()
        await set_subscription_tools(db, subscription_id, plan.id, tools)
        subscription_ids.append(subscription_id)

        billing = BillingModel(
            organization_id=org_id,
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
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    try:
        email_result = send_organization_approval_email(
            organization_name=org.name,
            organization_email=org.email,
            contact_person=org.contact_person,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "Organization approval email was not sent for %s: %s. To: %s. Bcc: %s",
                org.id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc")
            )
    except Exception as exc:
        logger.error("Failed to build organization approval email for %s: %s", org.id, exc)

    return {
        "message": "Organization approved",
        "identity_provider": active_provider,
        "auth0_org_id": org.auth0_org_id,
        "zitadel_org_id": org.zitadel_org_id,
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
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    try:
        email_result = send_request_decision_email(
            to_email=org.email,
            recipient_name=org.contact_person or org.name,
            request_name="organization request",
            status="rejected",
            organization_name=org.name,
            reason=reason,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "Organization rejection email was not sent for %s: %s. To: %s. Bcc: %s",
                org.id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc"),
            )
    except Exception as exc:
        logger.error("Failed to build organization rejection email for %s: %s", org.id, exc)

    return {"message": "Organization rejected"}

@api_router.delete("/organizations/{org_id}")
async def delete_organization(org_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    auth0_cleanup = None
    if org.auth0_org_id:
        auth0_cleanup = await auth0_mgmt.delete_organization(org.auth0_org_id)
        if not auth0_cleanup.get("success"):
            raise HTTPException(
                status_code=502,
                detail=f"Failed to delete organization in AUTH0: {auth0_cleanup.get('error') or 'unknown error'}"
            )

    subscription_ids = select(SubscriptionModel.id).where(SubscriptionModel.organization_id == org_id)
    org_request_ids = select(OrganizationSubscriptionRequestModel.id).where(
        OrganizationSubscriptionRequestModel.organization_id == org_id
    )
    org_request_item_ids = select(OrganizationSubscriptionRequestItemModel.id).where(
        OrganizationSubscriptionRequestItemModel.request_id.in_(org_request_ids)
    )
    upgrade_request_ids = select(PlanUpgradeRequestModel.id).where(PlanUpgradeRequestModel.organization_id == org_id)
    upgrade_request_item_ids = select(PlanUpgradeRequestItemModel.id).where(
        PlanUpgradeRequestItemModel.request_id.in_(upgrade_request_ids)
    )
    project_ids = select(ProjectModel.id).where(ProjectModel.organization_id == org_id)
    application_ids = select(ApplicationModel.id).where(ApplicationModel.organization_id == org_id)

    await db.execute(delete(OrganizationSubscriptionRequestToolModel).where(
        OrganizationSubscriptionRequestToolModel.request_item_id.in_(org_request_item_ids)
    ))
    await db.execute(delete(OrganizationSubscriptionRequestItemModel).where(
        OrganizationSubscriptionRequestItemModel.request_id.in_(org_request_ids)
    ))
    await db.execute(delete(OrganizationSubscriptionRequestModel).where(
        OrganizationSubscriptionRequestModel.organization_id == org_id
    ))

    await db.execute(delete(PlanUpgradeRequestToolModel).where(
        PlanUpgradeRequestToolModel.request_item_id.in_(upgrade_request_item_ids)
    ))
    await db.execute(delete(PlanUpgradeRequestItemModel).where(
        PlanUpgradeRequestItemModel.request_id.in_(upgrade_request_ids)
    ))
    await db.execute(delete(PlanUpgradeRequestModel).where(PlanUpgradeRequestModel.organization_id == org_id))

    await db.execute(delete(SubscriptionToolModel).where(SubscriptionToolModel.subscription_id.in_(subscription_ids)))
    await db.execute(delete(BillingModel).where(BillingModel.subscription_id.in_(subscription_ids)))
    await db.execute(delete(BillingModel).where(BillingModel.organization_id == org_id))
    await db.execute(delete(SubscriptionModel).where(SubscriptionModel.organization_id == org_id))

    await db.execute(delete(ProjectTeamMemberModel).where(ProjectTeamMemberModel.organization_id == org_id))
    await db.execute(delete(ProjectEnvironmentModel).where(ProjectEnvironmentModel.project_id.in_(project_ids)))
    await db.execute(delete(ApplicationAgentModel).where(ApplicationAgentModel.application_id.in_(application_ids)))
    await db.execute(delete(ApplicationMonitoringModel).where(ApplicationMonitoringModel.application_id.in_(application_ids)))
    await db.execute(delete(ApplicationSecurityModel).where(ApplicationSecurityModel.application_id.in_(application_ids)))
    await db.execute(delete(ApplicationBillingModel).where(ApplicationBillingModel.application_id.in_(application_ids)))
    await db.execute(delete(ApplicationModel).where(ApplicationModel.organization_id == org_id))
    await db.execute(delete(ProjectModel).where(ProjectModel.organization_id == org_id))
    await db.execute(delete(BusinessUnitModel).where(BusinessUnitModel.organization_id == org_id))

    await db.execute(delete(UserRequestModel).where(UserRequestModel.organization_id == org_id))
    await db.execute(delete(UserModel).where(UserModel.organization_id == org_id))
    await db.execute(delete(RoleModel).where(RoleModel.organization_id == org_id))
    await db.execute(delete(AdminModel).where(AdminModel.organization_id == org_id))
    await db.execute(delete(Auth0LoginRecordModel).where(Auth0LoginRecordModel.organization_id == org_id))
    await db.execute(delete(ZitadelLoginRecordModel).where(ZitadelLoginRecordModel.organization_id == org_id))
    await db.execute(delete(OrganizationModel).where(OrganizationModel.id == org_id))

    await db.commit()
    return {
        "message": "Organization deleted",
        "organization_id": org_id,
        "auth0_cleanup": auth0_cleanup,
        "zitadel_cleanup": {"skipped": True, "reason": "Zitadel organization delete is not configured"},
    }


class OrganizationFullUpdate(BaseModel):
    """Schema for super admin to fully edit an organization"""
    model_config = ConfigDict(extra="allow")

    name: Optional[str] = None
    email: Optional[str] = None
    domain: Optional[str] = None
    contact_person: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    description: Optional[str] = None
    external_org_id: Optional[str] = None
    auth0_org_id: Optional[str] = None
    zitadel_org_id: Optional[str] = None
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
    
    update_data = {k: v for k, v in payload_dict(data, exclude_unset=True).items() if v is not None}
    if "supported_domains" in update_data and isinstance(update_data["supported_domains"], list):
        update_data["supported_domains"] = json.dumps(update_data["supported_domains"]) if update_data["supported_domains"] else None
    if "gateway_environments" in update_data and isinstance(update_data["gateway_environments"], list):
        update_data["gateway_environments"] = json.dumps(update_data["gateway_environments"]) if update_data["gateway_environments"] else None
    if "name" in update_data:
        update_data["name"] = update_data["name"].strip()
        if not update_data["name"]:
            raise HTTPException(status_code=400, detail="Organization name is required")
    if "domain" in update_data:
        update_data["domain"] = update_data["domain"].strip() if update_data["domain"] else None
        if update_data["domain"] and not org.supported_domains:
            org.supported_domains = supported_domains_from_domain(update_data["domain"])
    if "external_org_id" in update_data and update_data["external_org_id"]:
        existing = await db.execute(
            select(OrganizationModel).where(
                OrganizationModel.external_org_id == update_data["external_org_id"],
                OrganizationModel.id != org_id,
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="External Org ID already in use by another organization")
    for key, value in update_data.items():
        if hasattr(org, key):
            setattr(org, key, normalize_onboarding_value(key, value))
    
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
            plan_id=plan.id,
            status="active",
            start_date=now,
            end_date=end_date,
            billing_cycle=data.billing_cycle,
            amount=total_price,
            quota=int(getattr(plan, "api_limit", 0) or 0),
            used_quota=0,
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
        await ensure_standard_roles_for_organization(db, user.organization_id)
        # Validate role exists in user's organization and belongs to the standard role catalog.
        roles = await get_standard_roles_by_ids(db, [data.role_id])
        await replace_user_role_assignments(db, user, roles)
    
    await db.commit()
    
    await db.refresh(user)
    return {"message": "User updated successfully", "user": await user_to_dict(db, user)}


@api_router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    data: UserRoleUpdate,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update a user's product role. Super admins can update any user; org admins can update users in their organization."""
    role_ids = data.role_ids if data.role_ids is not None else [data.role_id]
    return await update_user_role_assignment(db, user_id, role_ids, payload)

@api_router.post("/users/{user_id}/roles/{role_id}")
async def add_user_role(
    user_id: str,
    role_id: str,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db),
):
    """Add one product role to a user. Super admins can update any user; org admins can update users in their organization."""
    return await add_user_role_assignment(db, user_id, role_id, payload)

@api_router.delete("/users/{user_id}/roles/{role_id}")
async def delete_user_role(
    user_id: str,
    role_id: str,
    payload: dict = Depends(require_any_admin),
    db: AsyncSession = Depends(get_db),
):
    """Remove one product role from a user. Super admins can update any user; org admins can update users in their organization."""
    return await remove_user_role_assignment(db, user_id, role_id, payload)


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
    
    # Check if this is an individual user.
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == user.organization_id))
    org = org_result.scalar_one_or_none()
    is_individual = await is_individual_users_org(db, org)
    
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
            plan_id=plan.id,
            status="active",
            start_date=now,
            end_date=end_date,
            billing_cycle=data.billing_cycle,
            amount=total_price,
            quota=int(getattr(plan, "api_limit", 0) or 0),
            used_quota=0,
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

# ==================== SUBSCRIPTION ROUTES ====================

@api_router.get("/subscriptions")
async def get_subscriptions(status: Optional[str] = None, payload: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    access_scope = await get_subscription_access_scope(db, payload)

    if access_scope["scope"] == "individual":
        individual_org_id = await get_individual_users_org_id(db)
        subscriptions = await get_active_subscriptions_for_identity(
            db,
            email=access_scope["email"],
            organization_id=individual_org_id,
        )
        if status:
            subscriptions = [sub for sub in subscriptions if sub.status == status]
        return [await subscription_to_dict(db, s) for s in subscriptions]

    query = valid_subscription_query()
    if access_scope["scope"] == "organization":
        query = query.where(SubscriptionModel.organization_id == access_scope["organization_id"])
    if status:
        query = query.where(SubscriptionModel.status == status)
    result = await db.execute(query.order_by(SubscriptionModel.created_at.desc()))
    return [await subscription_to_dict(db, s) for s in result.scalars().all()]

@api_router.get("/subscriptions/{sub_id}")
async def get_subscription(sub_id: str, payload: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    access_scope = await get_subscription_access_scope(db, payload)
    query = valid_subscription_query().where(SubscriptionModel.id == sub_id)
    if access_scope["scope"] == "organization":
        query = query.where(SubscriptionModel.organization_id == access_scope["organization_id"])
    elif access_scope["scope"] == "individual":
        individual_org_id = await get_individual_users_org_id(db)
        allowed_subscriptions = await get_active_subscriptions_for_identity(
            db,
            email=access_scope["email"],
            organization_id=individual_org_id,
        )
        allowed_ids = {sub.id for sub in allowed_subscriptions}
        if sub_id not in allowed_ids:
            raise HTTPException(status_code=404, detail="Subscription not found")
    result = await db.execute(query)
    sub = result.scalar_one_or_none()
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return await subscription_to_dict(db, sub)

@api_router.put("/subscriptions/{sub_id}/api-count")
async def update_subscription_api_count(
    sub_id: str,
    data: SubscriptionApiCountUpdate,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(SubscriptionModel, PlanModel)
        .outerjoin(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .where(SubscriptionModel.id == sub_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub, plan = row
    if data.api_count is not None and data.api_count < 0:
        raise HTTPException(status_code=400, detail="api_count cannot be negative")
    apply_subscription_quota_update(sub, quota=data.api_count)
    enforce_subscription_quota_bounds(sub, plan)
    await db.commit()
    return {
        "message": "Subscription quota updated",
        "subscription": await subscription_to_dict(db, sub),
    }

@api_router.get("/subscriptions/{sub_id}/quota")
async def get_subscription_quota(
    sub_id: str,
    payload: dict = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    query = valid_subscription_query().where(SubscriptionModel.id == sub_id)
    access_scope = await get_subscription_access_scope(db, payload)
    if access_scope["scope"] != "all":
        query = query.where(SubscriptionModel.organization_id == access_scope["organization_id"])
    result = await db.execute(query)
    sub = result.scalar_one_or_none()
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return await subscription_to_dict(db, sub)

@api_router.put("/subscriptions/{sub_id}/quota")
async def update_subscription_quota(
    sub_id: str,
    data: SubscriptionQuotaUpdate,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(SubscriptionModel, PlanModel)
        .outerjoin(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .where(SubscriptionModel.id == sub_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub, plan = row
    apply_subscription_quota_update(sub, quota=data.quota, used_quota=data.used_quota)
    enforce_subscription_quota_bounds(sub, plan)
    await db.commit()
    return {
        "message": "Subscription quota updated",
        "subscription": await subscription_to_dict(db, sub),
    }

@api_router.put("/subscriptions/{sub_id}/usage-quota")
async def update_subscription_usage_quota(
    sub_id: str,
    data: SubscriptionQuotaUpdate,
    payload: dict = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(SubscriptionModel, PlanModel)
        .outerjoin(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .where(SubscriptionModel.id == sub_id)
    )
    access_scope = await get_subscription_access_scope(db, payload)
    if access_scope["scope"] != "all":
        query = query.where(SubscriptionModel.organization_id == access_scope["organization_id"])
    result = await db.execute(query)
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub, plan = row
    apply_subscription_usage_update(sub, data)
    enforce_subscription_quota_bounds(sub, plan)
    await db.commit()
    response = await subscription_to_dict(db, sub)
    response["message"] = "Usage quota updated"
    return response

@api_router.put("/subscriptions/{sub_id}/billing-settings")
async def update_subscription_billing_settings(
    sub_id: str,
    data: SubscriptionBillingSettingsUpdate,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(SubscriptionModel, PlanModel)
        .outerjoin(PlanModel, SubscriptionModel.plan_id == PlanModel.id)
        .where(SubscriptionModel.id == sub_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub, plan = row
    quota = data.quota if data.quota is not None else data.api_count
    if quota is not None and quota < 0:
        raise HTTPException(status_code=400, detail="quota cannot be negative")
    if data.used_quota is not None and data.used_quota < 0:
        raise HTTPException(status_code=400, detail="used_quota cannot be negative")
    if data.amount is not None and data.amount < 0:
        raise HTTPException(status_code=400, detail="amount cannot be negative")

    apply_subscription_quota_update(sub, quota=quota, used_quota=data.used_quota)
    enforce_subscription_quota_bounds(sub, plan)
    if data.amount is not None:
        sub.amount = float(data.amount)
    await db.commit()
    return {
        "message": "Subscription billing settings updated",
        "subscription": await subscription_to_dict(db, sub),
    }

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
async def get_products(
    include_plans: bool = False,
    include_inactive: bool = False,
    payload: Optional[dict] = Depends(optional_verify_token),
    db: AsyncSession = Depends(get_db),
):
    if include_inactive and (not payload or payload.get("role") != "super_admin"):
        raise HTTPException(status_code=403, detail="Super admin access required")
    query = select(ProductModel).order_by(ProductModel.display_order, ProductModel.name)
    if not include_inactive:
        query = query.where(ProductModel.is_active == True)
    result = await db.execute(query)
    products = []
    for product in result.scalars().all():
        product_dict = model_to_dict(product)
        plans_result = await db.execute(
            select(PlanModel).where(
                PlanModel.product_id == product.id,
                PlanModel.is_active == True,
            )
        )
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
async def get_plans(product_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """Get all active plans."""
    query = select(PlanModel).where(PlanModel.is_active == True)
    if product_id:
        product = await get_product_by_id_or_key(db, product_id)
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        query = query.where(PlanModel.product_id == product.id)
    result = await db.execute(query.order_by(PlanModel.created_at.desc()))
    plans = result.scalars().all()

    return [await plan_to_dict(db, plan) for plan in plans]

@api_router.get("/plans/inactive")
async def get_inactive_plans(product_id: Optional[str] = None, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    """Management-only list of deactivated plans so super admins can restore them."""
    query = select(PlanModel).where(PlanModel.is_active == False)
    if product_id:
        product = await get_product_by_id_or_key(db, product_id)
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        query = query.where(PlanModel.product_id == product.id)
    result = await db.execute(query.order_by(PlanModel.created_at.desc()))
    plans = result.scalars().all()
    return [await plan_to_dict(db, plan) for plan in plans]

@api_router.get("/plans/{plan_id}")
async def get_plan(plan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id, PlanModel.is_active == True))
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
    result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id, PlanModel.is_active == True))
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
    await db.commit()
    return await plan_to_dict(db, plan)

@api_router.post("/plans/{plan_id}/activate")
async def activate_plan(plan_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id))
    plan = plan_result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    plan.is_active = True
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
async def get_plan_tools(plan_id: str, db: AsyncSession = Depends(get_db)):
    """Get all tools for a specific plan"""
    # Verify plan exists
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id, PlanModel.is_active == True))
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
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id, PlanModel.is_active == True))
    plan = plan_result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    tool = PlanToolModel(
        plan_id=plan_id,
        name=data.name,
        description=data.description,
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
async def calculate_plan_price(plan_id: str, tool_ids: str = "", db: AsyncSession = Depends(get_db)):
    """
    Calculate total price for a plan based on selected tools.
    tool_ids: Comma-separated list of tool IDs
    """
    # Verify plan exists
    plan_result = await db.execute(select(PlanModel).where(PlanModel.id == plan_id, PlanModel.is_active == True))
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
            "price": plan.price_label or (f"${plan_cost:g}" if plan_cost else "$0"),
            "price_label": plan.price_label or (f"${plan_cost:g}" if plan_cost else "$0"),
            "period": plan.billing_period,
            "billing_period": plan.billing_period,
            "popular": bool(plan.is_popular),
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
        raise HTTPException(status_code=409, detail="A user with this email already exists")
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == data.organization_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    await assert_email_allowed_for_org(db, data.email, org)
    
    await ensure_standard_roles_for_organization(db, data.organization_id)
    role_result = await db.execute(
        select(RoleModel).where(
            RoleModel.id == data.role_id,
            RoleModel.organization_id.is_(None),
        )
    )
    role = role_result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Standard role not found")
    role, onboarding_role_lookup = await resolve_new_user_role(db, org, data.email, role)
    
    user = UserModel(
        email=data.email, name=data.name, organization_id=data.organization_id,
        role_id=role.id
    )
    db.add(user)
    await db.flush()
    await replace_user_role_assignments(db, user, [role])

    if await is_individual_users_org(db, org):
        plan = await get_default_individual_plan(db)
        individual_request = IndividualUserRequestModel(
            email=data.email,
            name=data.name,
            requested_tools=json.dumps([]),
            requested_plan=json.dumps([plan.id]),
            purpose="Created directly by superadmin under Individual Users.",
            company_name=data.email.split("@", 1)[1] if "@" in data.email else None,
            status="approved",
            approved_at=datetime.now(timezone.utc),
            assigned_user_id=user.id,
        )
        db.add(individual_request)
        await db.flush()
        await create_individual_user_subscription(
            db,
            user=user,
            plan=plan,
            requested_tools=[],
            source_request=individual_request,
        )

    active_provider = await get_active_identity_provider(db)
    if org.status == "approved":
        needs_provider_org = (
            (active_provider == "auth0" and not org.auth0_org_id)
            or (active_provider == "zitadel" and not org.zitadel_org_id)
        )
        org_provision_result = {"success": True, "skipped": True}
        if needs_provider_org:
            org_provision_result = await provision_organization_for_active_provider(db, org, active_provider)
        if not org_provision_result.get("success"):
            raise HTTPException(
                status_code=502,
                detail=f"Failed to create organization in {active_provider.upper()}: {org_provision_result.get('error') or 'unknown error'}",
            )
        provider_user_result = await provision_user_for_active_provider(
            db,
            user,
            data.email,
            data.name,
            {
                "probestack_user_id": user.id,
                "organization_id": org.id,
                "organization_name": org.name,
            },
            org,
            role.name,
            active_provider,
        )
        if not provider_user_result.get("success"):
            raise HTTPException(
                status_code=502,
                detail=f"Failed to create user in {active_provider.upper()}: {provider_user_result.get('error') or 'unknown error'}",
            )

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
    
    # If user is from the configured individual organization, delete their individual subscription
    if await is_individual_users_org_id(db, user.organization_id):
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
    await ensure_standard_roles_for_organization(db)
    await db.commit()
    query = select(RoleModel).where(RoleModel.organization_id.is_(None))
    result = await db.execute(query.order_by(RoleModel.name.asc()))
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
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Role name is required")
    existing = await db.execute(
        select(RoleModel).where(
            RoleModel.organization_id.is_(None),
            func.lower(RoleModel.name) == name.lower(),
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A global role with this name already exists")
    role = RoleModel(
        name=name,
        organization_id=None,
        permissions=json.dumps(data.permissions or []),
        description=data.description,
    )
    db.add(role)
    await db.commit()
    await db.refresh(role)
    return model_to_dict(role, ["permissions"])

@api_router.put("/roles/{role_id}")
async def update_role(role_id: str, data: RoleCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(RoleModel).where(
            RoleModel.id == role_id,
            RoleModel.organization_id.is_(None),
        )
    )
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Global role not found")
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Role name is required")
    duplicate = await db.execute(
        select(RoleModel).where(
            RoleModel.id != role_id,
            RoleModel.organization_id.is_(None),
            func.lower(RoleModel.name) == name.lower(),
        )
    )
    if duplicate.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A global role with this name already exists")
    role.name = name
    role.permissions = json.dumps(data.permissions or [])
    role.description = data.description
    await db.commit()
    await db.refresh(role)
    return model_to_dict(role, ["permissions"])

@api_router.delete("/roles/{role_id}")
async def delete_role(role_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(RoleModel).where(
            RoleModel.id == role_id,
            RoleModel.organization_id.is_(None),
        )
    )
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Global role not found")
    primary_user_result = await db.execute(select(UserModel.id).where(UserModel.role_id == role_id))
    assigned_user_result = await db.execute(
        select(UserRoleAssignmentModel.user_id).where(UserRoleAssignmentModel.role_id == role_id)
    )
    assigned_user_count = len(set(primary_user_result.scalars().all()) | set(assigned_user_result.scalars().all()))
    if assigned_user_count:
        raise HTTPException(status_code=409, detail=f"Role is assigned to {assigned_user_count} user(s)")
    await db.execute(delete(RoleModel).where(RoleModel.id == role_id))
    await db.commit()
    return {"message": "Role deleted successfully"}

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

@api_router.get("/billing/{billing_id}/invoice.xlsx")
async def download_billing_invoice(billing_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(BillingModel).where(BillingModel.id == billing_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Billing record not found")

    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == record.organization_id))
    organization = org_result.scalar_one_or_none()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    line_items = await build_invoice_line_items(db, record.organization_id)
    if not line_items:
        raise HTTPException(status_code=400, detail="No active subscriptions found for this organization")

    billing_date = record.billing_date
    if billing_date.tzinfo is None:
        billing_date = billing_date.replace(tzinfo=timezone.utc)
    period_start = datetime(billing_date.year, 1, 1, tzinfo=timezone.utc)
    period_end = datetime(billing_date.year, 12, 31, tzinfo=timezone.utc)
    invoice = {
        "invoice_number": record.invoice_number,
        "billing_date": billing_date,
        "due_date": record.due_date if record.due_date.tzinfo else record.due_date.replace(tzinfo=timezone.utc),
        "period_start": period_start,
        "period_end": period_end,
        "status": record.status,
        "organization": model_to_dict(organization, ["requested_tools", "supported_domains", "gateway_environments", "compliance_standards"]),
    }
    contents = build_invoice_workbook(invoice, line_items)
    filename = f"{record.invoice_number}.xlsx"
    return StreamingResponse(
        io.BytesIO(contents),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@api_router.get("/billing/{billing_id}/invoice.pdf")
async def download_billing_invoice_pdf(billing_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(BillingModel).where(BillingModel.id == billing_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Billing record not found")

    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == record.organization_id))
    organization = org_result.scalar_one_or_none()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    line_items = await build_invoice_line_items(db, record.organization_id)
    if not line_items:
        raise HTTPException(status_code=400, detail="No active subscriptions found for this organization")

    billing_date = record.billing_date
    if billing_date.tzinfo is None:
        billing_date = billing_date.replace(tzinfo=timezone.utc)
    invoice = {
        "invoice_number": record.invoice_number,
        "billing_date": billing_date,
        "due_date": record.due_date if record.due_date.tzinfo else record.due_date.replace(tzinfo=timezone.utc),
        "period_start": datetime(billing_date.year, 1, 1, tzinfo=timezone.utc),
        "period_end": datetime(billing_date.year, 12, 31, tzinfo=timezone.utc),
        "status": record.status,
        "organization": model_to_dict(organization, ["requested_tools", "supported_domains", "gateway_environments", "compliance_standards"]),
    }
    contents = build_invoice_pdf(invoice, line_items)
    filename = f"{record.invoice_number}.pdf"
    return StreamingResponse(
        io.BytesIO(contents),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@api_router.get("/billing/{billing_id}/email-recipients")
async def get_billing_invoice_email_recipients(billing_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(BillingModel).where(BillingModel.id == billing_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Billing record not found")
    return await get_billing_invoice_recipient_options(db, record.organization_id)

@api_router.post("/billing/{billing_id}/send-email")
async def send_billing_invoice_by_email(
    billing_id: str,
    data: BillingInvoiceEmailRequest,
    payload: dict = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    to_emails = normalize_email_recipients(data.emails)
    if not to_emails:
        raise HTTPException(status_code=400, detail="At least one recipient email is required")

    result = await db.execute(select(BillingModel).where(BillingModel.id == billing_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Billing record not found")

    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == record.organization_id))
    organization = org_result.scalar_one_or_none()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    line_items = await build_invoice_line_items(db, record.organization_id)
    if not line_items:
        raise HTTPException(status_code=400, detail="No active subscriptions found for this organization")

    billing_date = record.billing_date
    if billing_date.tzinfo is None:
        billing_date = billing_date.replace(tzinfo=timezone.utc)
    due_date = record.due_date if record.due_date.tzinfo else record.due_date.replace(tzinfo=timezone.utc)
    invoice = {
        "invoice_number": record.invoice_number,
        "billing_date": billing_date,
        "due_date": due_date,
        "period_start": datetime(billing_date.year, 1, 1, tzinfo=timezone.utc),
        "period_end": datetime(billing_date.year, 12, 31, tzinfo=timezone.utc),
        "status": record.status,
        "organization": model_to_dict(organization, ["requested_tools", "supported_domains", "gateway_environments", "compliance_standards"]),
    }
    pdf_contents = build_invoice_pdf(invoice, line_items)
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    email_result = send_billing_invoice_email(
        organization_name=organization.name,
        invoice_number=record.invoice_number,
        amount=float(record.amount or 0),
        due_date=due_date,
        to_emails=to_emails,
        notification_emails=notification_emails,
        pdf_contents=pdf_contents,
    )
    if not email_result.get("sent"):
        raise HTTPException(status_code=502, detail=email_result.get("reason", "Failed to send invoice email"))
    return {
        "message": "Invoice email sent successfully",
        "email": email_result,
    }

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

async def generate_annual_billing_records(db: AsyncSession) -> dict:
    """
    Generate one annual invoice record per organization with active subscriptions.
    Pending invoices for the same organization/year are refreshed and duplicate
    pending rows are removed so the Billing page shows one invoice per org.
    """
    now = datetime.now(timezone.utc)
    period_start = datetime(now.year, 1, 1, tzinfo=timezone.utc)
    period_end = datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
    due_date = now + timedelta(days=15)

    subs_result = await db.execute(
        select(SubscriptionModel)
        .where(SubscriptionModel.status == "active")
        .order_by(SubscriptionModel.organization_id.asc(), SubscriptionModel.created_at.asc())
    )
    active_subscriptions = subs_result.scalars().all()
    subscriptions_by_org: dict[str, list[SubscriptionModel]] = {}
    for subscription in active_subscriptions:
        subscriptions_by_org.setdefault(subscription.organization_id, []).append(subscription)

    bills_created = 0
    bills_updated = 0
    bills_skipped = 0

    for organization_id, org_subscriptions in subscriptions_by_org.items():
        amount = await calculate_organization_annual_invoice_amount(db, organization_id)
        if amount <= 0:
            bills_skipped += 1
            continue

        existing_bill = await db.execute(
            select(BillingModel)
            .where(
                BillingModel.organization_id == organization_id,
                BillingModel.billing_date >= period_start,
                BillingModel.billing_date < period_end
            )
            .order_by(BillingModel.created_at.asc())
        )
        bills = existing_bill.scalars().all()
        editable_bill = next((bill for bill in bills if bill.status == "pending"), None)
        if editable_bill:
            editable_bill.subscription_id = org_subscriptions[0].id
            editable_bill.amount = amount
            editable_bill.billing_date = now
            editable_bill.due_date = due_date
            duplicate_ids = [bill.id for bill in bills if bill.id != editable_bill.id and bill.status == "pending"]
            if duplicate_ids:
                await db.execute(delete(BillingModel).where(BillingModel.id.in_(duplicate_ids)))
            bills_updated += 1
            continue

        if any(bill.status == "paid" for bill in bills):
            bills_skipped += 1
            continue

        invoice_number = f"INV-{now.strftime('%Y')}-{organization_id[-8:].upper()}-{str(uuid.uuid4())[:4].upper()}"
        billing = BillingModel(
            organization_id=organization_id,
            subscription_id=org_subscriptions[0].id,
            amount=amount,
            status="pending",
            invoice_number=invoice_number,
            billing_date=now,
            due_date=due_date
        )
        db.add(billing)
        bills_created += 1

    await db.commit()

    return {
        "message": "Annual invoice generation complete",
        "bills_created": bills_created,
        "bills_updated": bills_updated,
        "bills_skipped": bills_skipped,
        "total_active_subscriptions": len(active_subscriptions),
        "total_organizations": len(subscriptions_by_org),
    }

@api_router.post("/billing/generate-annual")
async def generate_annual_bills(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    return await generate_annual_billing_records(db)

@api_router.post("/billing/generate-monthly")
async def generate_monthly_bills(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    return await generate_annual_billing_records(db)

# ==================== NOTIFICATIONS ROUTES (Super Admin Only) ====================

@api_router.get("/notifications/group-emails")
async def get_notification_group_email_records(payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    await ensure_notification_group_seeded(db)
    await db.commit()
    result = await db.execute(select(NotificationGroupEmailModel).order_by(NotificationGroupEmailModel.created_at.asc()))
    return [model_to_dict(email_record) for email_record in result.scalars().all()]

@api_router.post("/notifications/group-emails")
async def create_notification_group_email(data: NotificationGroupEmailCreate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    email = (data.email or "").strip()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    await ensure_notification_group_seeded(db)
    existing = await db.execute(
        select(NotificationGroupEmailModel).where(func.lower(NotificationGroupEmailModel.email) == email.lower())
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already exists in notification group")
    email_record = NotificationGroupEmailModel(
        email=email,
        name=(data.name or "").strip() or None,
        is_active=data.is_active if data.is_active is not None else True,
    )
    db.add(email_record)
    await db.commit()
    await db.refresh(email_record)
    return model_to_dict(email_record)

@api_router.put("/notifications/group-emails/{email_id}")
async def update_notification_group_email(email_id: str, data: NotificationGroupEmailUpdate, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    await ensure_notification_group_seeded(db)
    result = await db.execute(select(NotificationGroupEmailModel).where(NotificationGroupEmailModel.id == email_id))
    email_record = result.scalar_one_or_none()
    if not email_record:
        raise HTTPException(status_code=404, detail="Notification group email not found")
    if data.email is not None:
        email = data.email.strip()
        if not email:
            raise HTTPException(status_code=400, detail="Email is required")
        duplicate = await db.execute(
            select(NotificationGroupEmailModel).where(
                NotificationGroupEmailModel.id != email_id,
                func.lower(NotificationGroupEmailModel.email) == email.lower(),
            )
        )
        if duplicate.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already exists in notification group")
        email_record.email = email
    if data.name is not None:
        email_record.name = data.name.strip() or None
    if data.is_active is not None:
        email_record.is_active = data.is_active
    email_record.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(email_record)
    return model_to_dict(email_record)

@api_router.delete("/notifications/group-emails/{email_id}")
async def delete_notification_group_email(email_id: str, payload: dict = Depends(require_super_admin), db: AsyncSession = Depends(get_db)):
    await ensure_notification_group_seeded(db)
    result = await db.execute(delete(NotificationGroupEmailModel).where(NotificationGroupEmailModel.id == email_id))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Notification group email not found")
    await db.commit()
    return {"message": "Notification group email deleted"}

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

@api_router.get("/public/organizations", tags=["Public API"])
async def get_public_organizations(
    status: Optional[str] = "approved",
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get public organization directory details for products and onboarding screens."""
    query = select(OrganizationModel)
    if status:
        query = query.where(OrganizationModel.status == status)
    if search:
        query = query.where(
            (OrganizationModel.name.ilike(f"%{search}%"))
            | (OrganizationModel.domain.ilike(f"%{search}%"))
            | (OrganizationModel.external_org_id.ilike(f"%{search}%"))
        )
    query = query.order_by(OrganizationModel.name.asc())
    result = await db.execute(query)
    return [await public_organization_to_dict(db, org) for org in result.scalars().all()]

@api_router.post("/public/organizations/request", tags=["Public API"])
async def request_organization_subscription(data: OrganizationRequest, db: AsyncSession = Depends(get_db)):
    """
    Public API endpoint for external applications to submit organization subscription requests.
    Supports multiple plan selection.
    
    **Request Body:**
    - `name`: Organization name (required)
    - `email`: Organization email (required)
    - `domain`: Company domain (required)
    - `plans`: Optional product-plan selections from GET /api/public/plans, e.g.
      [{"id": "plan_forgeq_enterprise", "product_key": "forgeq", "tool_ids": ["pt_forgeq_enterprise"]}]
    - `requested_plans`: Alternate key for the same product-plan selection format
    - `plan_ids`: Legacy list of Plan IDs to subscribe to
    - `selected_tools`: Legacy flat list of selected tool IDs/names
    - `contact_person`: Primary contact name (required)
    - `contact_phone`: Contact phone number (required)
    - `company_address`: Company address (required)
    - `additional_notes`: Any additional notes (optional)
    - `description`: Organization description (required)
    
    **Flow:**
    1. Call GET /api/public/pricing to see products and plans
    2. Submit this request with selected plan_ids and tools
    """
    validate_required_organization_create_fields(payload_dict(data))
    plan_selections = normalize_organization_plan_selections(data)

    plan_ids = [selection.plan_id for selection in plan_selections]

    # Validate all plans exist
    plans = {}
    if plan_ids:
        plans_result = await db.execute(select(PlanModel).where(PlanModel.id.in_(plan_ids)))
        plans = {p.id: p for p in plans_result.scalars().all()}
    
    invalid_plans = [pid for pid in plan_ids if pid not in plans]
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

    # Get available tools from ALL selected plans for validation errors and legacy payload support.
    available_tool_rows = []
    if plan_ids:
        tools_result = await db.execute(
            select(PlanToolModel).where(
                PlanToolModel.plan_id.in_(plan_ids),
                PlanToolModel.is_active == True
            )
        )
        available_tool_rows = tools_result.scalars().all()
    available_tools = [
        {"id": t.id, "name": t.name, "plan_id": t.plan_id}
        for t in available_tool_rows
    ]

    # Legacy flat selected_tools are assigned to the first selected plan that owns the tool.
    invalid_legacy_tools = []
    for tool in data.selected_tools or []:
        matched_selection = None
        for selection in plan_selections:
            if await resolve_plan_tool(db, selection.plan_id, tool):
                matched_selection = selection
                break
        if not matched_selection:
            invalid_legacy_tools.append(tool)
            continue
        if tool not in matched_selection.tool_ids:
            matched_selection.tool_ids.append(tool)

    if invalid_legacy_tools:
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"Invalid tools for selected plans: {invalid_legacy_tools}",
                "available_tools": available_tools
            }
        )

    for selection in plan_selections:
        for tool in selection.tool_ids or []:
            if not await resolve_plan_tool(db, selection.plan_id, tool):
                plan_available_tools = [
                    tool_row for tool_row in available_tools
                    if tool_row["plan_id"] == selection.plan_id
                ]
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": f"Tool '{tool}' is not available for plan '{selection.plan_id}'",
                        "available_tools": plan_available_tools,
                    }
                )

    selected_tools = []
    for selection in plan_selections:
        for tool in selection.tool_ids or []:
            if tool not in selected_tools:
                selected_tools.append(tool)

    base_monthly = sum((getattr(plans[pid], "cost", None) or plans[pid].price_monthly or 0) for pid in plan_ids)
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
        contact_person=data.contact_person,
        phone=data.contact_phone,
        address=data.company_address,
        description=data.description,
        supported_domains=supported_domains_from_domain(data.domain),
        gateway_region=data.gateway_region,
        gateway_organization_name=data.gateway_organization_name,
        gateway_environment_type=data.gateway_environment_type,
        gateway_environments=json.dumps(data.gateway_environments) if data.gateway_environments else None
    )
    apply_onboarding_fields(org, payload_dict(data), ORGANIZATION_ONBOARDING_FIELDS)
    if org.organization_code and not org.external_org_id:
        org.external_org_id = org.organization_code
    db.add(org)
    await db.flush()
    await ensure_standard_roles_for_organization(db, org.id)
    if plan_selections:
        await create_organization_subscription_request_from_selections(
            db,
            org.id,
            plan_selections,
            status=org.status
        )
    
    # Create notification for admin
    tools_str = ', '.join(selected_tools[:3])
    if len(selected_tools) > 3:
        tools_str += f" +{len(selected_tools) - 3} more"
    plans_str = await format_selected_product_plan_lines(db, plan_ids, plans)
    notification_plans_str = plans_str.replace("\n", ", ")
    notif = NotificationModel(
        title="New Organization Request",
        message=f"{data.name} has requested organization onboarding" + (f" for {notification_plans_str}" if notification_plans_str else "") + (f" with tools: {tools_str}" if tools_str else ""),
        type="info",
        link=f"/pending-organizations"
    )
    db.add(notif)
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    try:
        email_result = send_new_organization_request_email(
            request_id=org.id,
            organization_name=org.name,
            organization_email=org.email,
            domain=org.domain,
            contact_person=org.contact_person,
            contact_phone=org.phone,
            company_address=org.address,
            description=org.description,
            additional_notes=data.additional_notes,
            plans=plans_str,
            selected_tools=tools_str,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "New organization request email was not sent for %s: %s. To: %s. Cc: %s",
                org.id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("cc")
            )
    except Exception as exc:
        logger.error("Failed to build new organization request email for %s: %s", org.id, exc)
    
    # Build response with plan details
    plan_names = []
    selected_tools_by_plan = {selection.plan_id: selection.tool_ids for selection in plan_selections}
    for pid in plan_ids:
        product = await get_plan_product(db, plans[pid])
        plan_names.append({
            "id": pid,
            "name": plans[pid].name,
            "product_id": product.id if product else plans[pid].product_id,
            "product_key": product.key if product else plans[pid].tool,
            "product_name": product.name if product else None,
            "selected_tools": selected_tools_by_plan.get(pid, []),
        })
    
    return {
        "request_id": org.id,
        "status": "pending",
        "message": f"Organization subscription request submitted successfully. Your request ID is {org.id}. An admin will review your request shortly.",
        "organization": {
            "name": org.name,
            "email": org.email,
            "plans": plan_names,
            "selected_tools": selected_tools,
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
    
    org_data = await organization_to_dict(db, org)
    response = {
        "request_id": org.id,
        "status": org.status,
        "organization_name": org.name,
        "requested_plan": org_data.get("requested_plan"),
        "requested_tools": org_data.get("requested_tools", []),
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

    users = await get_public_organization_users(db, organization_id)

    return {
        "organization": await organization_to_dict(db, org),
        "user_count": len(users),
        "users": users,
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
    return {"message": "Business unit created successfully", "business_unit": await business_unit_to_dict(db, business_unit)}

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
    response = await business_unit_to_dict(db, business_unit)
    teams_result = await db.execute(
        select(ProjectModel)
        .where(ProjectModel.organization_id == org.id, ProjectModel.business_unit_id == business_unit_id)
        .order_by(ProjectModel.name.asc())
    )
    response["teams"] = [await project_to_dict(db, project) for project in teams_result.scalars().all()]
    return response

@api_router.get("/public/onboarding/organizations/{organization_id}/teams", tags=["External Onboarding"])
async def external_get_teams(organization_id: str, business_unit_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """Fetch projects for an approved organization, optionally filtered by Business unit."""
    org = await get_approved_org_by_id(db, organization_id)
    query = select(ProjectModel).where(ProjectModel.organization_id == org.id)
    if business_unit_id:
        query = query.where(ProjectModel.business_unit_id == business_unit_id)
    result = await db.execute(query.order_by(ProjectModel.name.asc()))
    return [await project_to_dict(db, project) for project in result.scalars().all()]

@api_router.post("/public/onboarding/organizations/{organization_id}/teams", tags=["External Onboarding"])
async def external_create_team(organization_id: str, data: ExternalProjectCreate, db: AsyncSession = Depends(get_db)):
    """Onboard a Project for an approved organization. The Project must belong to a Business unit."""
    org = await get_approved_org_by_id(db, organization_id)
    project = await create_project_for_org(db, org, data)
    await db.commit()
    return {"message": "Project created successfully", "team": await project_to_dict(db, project)}

@api_router.get("/public/onboarding/organizations/{organization_id}/teams/{team_id}", tags=["External Onboarding"])
async def external_get_team(organization_id: str, team_id: str, db: AsyncSession = Depends(get_db)):
    """Fetch one Project with its Business unit and members."""
    org = await get_approved_org_by_id(db, organization_id)
    project = await get_project_for_org(db, team_id, org.id)
    response = await project_to_dict(db, project)
    response["business_unit"] = None
    if project.business_unit_id:
        bu_result = await db.execute(
            select(BusinessUnitModel).where(
                BusinessUnitModel.id == project.business_unit_id,
                BusinessUnitModel.organization_id == org.id
            )
        )
        business_unit = bu_result.scalar_one_or_none()
        response["business_unit"] = await business_unit_to_dict(db, business_unit) if business_unit else None
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
        .order_by(ProductModel.display_order, ProductModel.name)
    )
    products = []
    for product in products_result.scalars().all():
        plans_result = await db.execute(
            select(PlanModel)
            .where(
                PlanModel.product_id == product.id,
                PlanModel.is_active == True,
            )
            .order_by(PlanModel.cost, PlanModel.name, PlanModel.created_at)
        )
        plans = [await public_plan_to_dict(db, plan) for plan in plans_result.scalars().all()]
        products.append({
            "id": product.id,
            "key": product.key,
            "name": product.name,
            "description": product.description,
            "display_order": product.display_order,
            "plans": plans,
        })
    return {
        "source": "probestack-admin-backend",
        "products": products,
        "product_types": [{"id": product["key"], "name": product["name"]} for product in products],
    }

@api_router.get("/public/plans/api-counts", tags=["Public API"])
async def get_public_plan_api_counts(
    product_id: Optional[str] = None,
    product_key: Optional[str] = None,
    tool: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Public plan API-count catalog.
    Returns the configured API count limit for every active plan.
    """
    product_filter = product_id or product_key or tool
    query = (
        select(PlanModel, ProductModel)
        .join(ProductModel, PlanModel.product_id == ProductModel.id)
        .where(PlanModel.is_active == True, ProductModel.is_active == True)
    )
    if product_filter:
        product = await get_product_by_id_or_key(db, product_filter)
        if not product or not product.is_active:
            return {"source": "probestack-admin-backend", "plans": [], "products": []}
        query = query.where(PlanModel.product_id == product.id)

    result = await db.execute(query)
    rows = []
    for plan, product in result.all():
        api_count = int(getattr(plan, "api_limit", 0) or 0)
        rows.append({
            "id": plan.id,
            "name": plan.name,
            "product_id": product.id,
            "product_key": product.key,
            "product_name": product.name,
            "tool": product.key,
            "api_limit": api_count,
            "api_count": api_count,
            "is_active": bool(plan.is_active),
            "display_order": product.display_order,
        })

    rows.sort(
        key=lambda item: (
            item["display_order"],
            item["product_name"],
            item["name"],
        )
    )

    products_by_id = {}
    for row in rows:
        product = products_by_id.setdefault(row["product_id"], {
            "id": row["product_id"],
            "key": row["product_key"],
            "name": row["product_name"],
            "display_order": row["display_order"],
            "plans": [],
        })
        product["plans"].append({
            "id": row["id"],
            "name": row["name"],
            "api_limit": row["api_limit"],
            "api_count": row["api_count"],
        })

    compact_rows = [
        {key: value for key, value in row.items() if key != "display_order"}
        for row in rows
    ]

    return {
        "source": "probestack-admin-backend",
        "plans": compact_rows,
        "products": list(products_by_id.values()),
    }

@api_router.get("/public/individual-account/products", tags=["Public API"])
async def get_individual_account_products(db: AsyncSession = Depends(get_db)):
    """
    Public product list for individual account signup.
    Returns only active products that have an active Starter plan.
    """
    starter_result = await db.execute(
        select(PlanModel, ProductModel)
        .join(ProductModel, PlanModel.product_id == ProductModel.id)
        .where(
            ProductModel.is_active == True,
            PlanModel.is_active == True,
            func.lower(func.trim(PlanModel.name)) == "starter",
        )
        .order_by(ProductModel.display_order, ProductModel.name, PlanModel.created_at.desc())
    )
    products = []
    seen_product_ids = set()
    for starter_plan, product in starter_result.all():
        if product.id in seen_product_ids:
            continue
        seen_product_ids.add(product.id)
        starter_plan_dict = await public_plan_to_dict(db, starter_plan)
        starter_plan_dict["product_key"] = product.key
        starter_plan_dict["product_name"] = product.name
        starter_plan_dict["tool"] = product.key

        products.append({
            "id": product.id,
            "key": product.key,
            "name": product.name,
            "description": product.description,
            "display_order": product.display_order,
            "starter_plan": starter_plan_dict,
        })

    return {
        "source": "probestack-admin-backend",
        "products": products,
        "product_types": [{"id": product["key"], "name": product["name"]} for product in products],
    }

@api_router.get("/public/plans", tags=["Public API"])
async def get_public_plans(
    product_id: Optional[str] = None,
    product_key: Optional[str] = None,
    tool: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Public flat plan catalog for external onboarding pages.
    Returns only active plans attached to active products. Legacy tool-only
    rows are intentionally excluded from the public catalog.
    """
    query = (
        select(PlanModel)
        .join(ProductModel, PlanModel.product_id == ProductModel.id)
        .where(PlanModel.is_active == True, ProductModel.is_active == True)
    )
    product_filter = product_id or product_key or tool
    if product_filter:
        product = await get_product_by_id_or_key(db, product_filter)
        if not product or not product.is_active:
            return []
        query = query.where(PlanModel.product_id == product.id)

    result = await db.execute(
        query.order_by(ProductModel.display_order, ProductModel.name, PlanModel.cost, PlanModel.name)
    )
    plans = result.scalars().all()
    plan_rows = []
    for plan in plans:
        plan_dict = await public_plan_to_dict(db, plan)
        plan_rows.append(plan_dict)
    return plan_rows

# ==================== PUBLIC API - USER REQUESTS ====================

@api_router.post("/public/users/request", tags=["Public API"])
async def request_user_addition(data: UserRequestCreate, db: AsyncSession = Depends(get_db)):
    """
    Public API endpoint for external applications to request adding a user to an organization.
    
    **Request Body:**
    - `email`: User's email address (required)
    - `name`: User's full name (required)
    - `organization_id`: Organization ID to add user to (required)
    - `requested_role`: Role name from the global roles table (required)
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

    matched_domain_org = await find_real_org_by_email_domain(db, data.email)
    is_individual_org = await is_individual_users_org(db, org)
    if not is_individual_org and matched_domain_org and matched_domain_org.id != org.id:
        raise HTTPException(
            status_code=400,
            detail=f"Email {data.email} belongs to {matched_domain_org.name}. Use organization_id {matched_domain_org.id}"
        )

    if is_individual_org or not matched_domain_org:
        individual_request = await create_individual_request_for_unknown_domain(
            db,
            email=data.email,
            name=data.name,
            job_title=data.job_title,
            phone=data.phone,
            notes=data.notes,
        )
        individual_org = await get_or_create_individual_users_org(db)
        default_role = await get_standard_role(db, individual_org.id)
        await db.commit()
        return {
            "request_id": individual_request.id,
            "status": individual_request.status,
            "request_type": "individual_user",
            "routed_to": "individual_users",
            "subscription_model": "per_user",
            "message": f"User request routed to Individual Users. Request ID: {individual_request.id}",
            "user": {
                "name": individual_request.name,
                "email": individual_request.email,
                "organization": individual_org.name,
                "organization_id": individual_org.id,
                "requested_role": default_role.name,
            }
        }

    await assert_email_allowed_for_org(db, data.email, org)
    
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
    
    requested_role = await map_to_standard_role_name(db, data.requested_role, DEFAULT_CONSUMER_ROLE_SLUG)

    # Create user request
    user_request = UserRequestModel(
        email=data.email,
        name=data.name,
        organization_id=data.organization_id,
        requested_role=requested_role,
        job_title=data.job_title,
        department=data.department,
        phone=data.phone,
        notes=data.notes
    )
    db.add(user_request)
    
    # Create notification for admin
    notif = NotificationModel(
        title="New User Request",
        message=f"{data.name} ({data.email}) requested to join {org.name} as {requested_role}",
        type="info",
        link="/user-requests"
    )
    db.add(notif)
    
    notification_emails = await get_notification_group_emails(db)
    org_admin_emails = await get_org_admin_emails(db, org.id)
    await db.commit()

    try:
        email_result = send_user_request_admin_email(
            organization_name=org.name,
            request_id=user_request.id,
            requester_name=data.name,
            requester_email=data.email,
            requested_role=requested_role,
            job_title=data.job_title,
            department=data.department,
            phone=data.phone,
            notes=data.notes,
            to_emails=org_admin_emails,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "User request email was not sent for %s: %s. To: %s. Bcc: %s",
                user_request.id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc"),
            )
    except Exception as exc:
        logger.error("Failed to build user request email for %s: %s", user_request.id, exc)
    
    return {
        "request_id": user_request.id,
        "status": "pending",
        "message": f"User addition request submitted successfully. Request ID: {user_request.id}",
        "user": {
            "name": data.name,
            "email": data.email,
            "organization": org.name,
            "requested_role": requested_role
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
    
    organization_name = await get_organization_name(db, req.organization_id)
    response = {
        "request_id": req.id,
        "status": req.status,
        "user_name": req.name,
        "user_email": req.email,
        "organization_id": req.organization_id,
        "organization_name": organization_name,
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


@api_router.get("/.well-known/jwks.json", tags=["Public API"])
@api_router.get("/public/.well-known/jwks.json", tags=["Public API"])
@api_router.get("/public/users/context-token/jwks", tags=["Public API"])
async def get_user_context_token_jwks():
    return build_context_token_jwks()

@api_router.post("/public/users/context-token", tags=["Public API"])
async def issue_user_context_token(
    data: UserContextTokenRequest,
    fastapi_response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Issue a signed ProbeStack context token after probestack.io login.

    The JWT payload contains user, organization, org role, Business unit/project roles,
    admin flags, subscriptions, plans, and tools.
    """
    email = data.email.lower().strip() if data.email else None
    auth0_user_id = data.auth0_user_id
    zitadel_user_id = data.zitadel_user_id
    identity_provider = (data.identity_provider or "").lower().strip()

    if data.id_token:
        decoded, verified_provider = verify_provider_id_token(data.id_token, identity_provider)
        token_email = decoded.get("email")
        token_subject = decoded.get("sub")
        if email and token_email and email != token_email.lower():
            raise HTTPException(status_code=400, detail="email does not match id_token")
        email = email or (token_email.lower() if token_email else None)
        if verified_provider == "zitadel":
            zitadel_user_id = zitadel_user_id or token_subject
        else:
            auth0_user_id = auth0_user_id or token_subject
    elif not ALLOW_CONTEXT_TOKEN_EMAIL_FALLBACK:
        raise HTTPException(status_code=400, detail="id_token is required to issue a user context token")

    if not email and not auth0_user_id and not zitadel_user_id:
        raise HTTPException(status_code=400, detail="email, auth0_user_id, zitadel_user_id, or id_token is required")

    user_context = await build_user_context(
        db,
        email=email,
        auth0_user_id=auth0_user_id,
        zitadel_user_id=zitadel_user_id,
    )
    token, expires_at = create_user_context_token(user_context)
    cookie_max_age = max(1, expires_at - int(datetime.now(timezone.utc).timestamp()))
    set_product_auth_cookies(fastapi_response, token, cookie_max_age)
    await db.commit()

    return {
        "success": True,
        "token": token,
        "token_type": "Bearer",
        "token_algorithm": PROBESTACK_CONTEXT_TOKEN_ALGORITHM,
        "kid": PROBESTACK_CONTEXT_TOKEN_KID,
        "issuer": PROBESTACK_TOKEN_ISSUER,
        "audience": PROBESTACK_TOKEN_AUDIENCE,
        "jwks_uri": PROBESTACK_CONTEXT_TOKEN_JWKS_URI,
        "admin_backend_host": ADMIN_BACKEND_PUBLIC_URL,
        "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
        "cookie_set": True,
        "user": user_context,
    }


@api_router.get("/public/users/{email}", tags=["Public API"])
async def get_user_by_email(email: str, payload: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    """
    Get user details by email (public endpoint).
    Returns user info including role, permissions, plans, tools, and admin status.
    """
    access_scope = await get_authenticated_data_scope(db, payload)
    # Check in users table
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    user = result.scalar_one_or_none()
    
    if user:
        if not has_data_scope_access(access_scope, email=user.email, organization_id=user.organization_id):
            raise HTTPException(status_code=403, detail="Not allowed to access this user")
        mongodb_role_lookup = await sync_user_role_from_mongodb(db, user)
        # Get role permissions
        role_result = await db.execute(select(RoleModel).where(RoleModel.id == user.role_id))
        role = role_result.scalar_one_or_none()
        permissions = json.loads(role.permissions) if role and role.permissions else []
        role_name = await get_role_name(db, user.role_id)
        
        # Check if user is also an admin
        admin_result = await db.execute(select(AdminModel).where(AdminModel.email == email))
        admin = admin_result.scalar_one_or_none()
        
        # Get subscription details (plans and tools) based on organization type
        subscriptions = []
        plans = []
        tools = []
        user_type = "individual" if await is_individual_users_org_id(db, user.organization_id) else "organization"
        
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
            "organization_name": await get_organization_name(db, user.organization_id),
            "user_type": user_type,
            "role_id": user.role_id,
            "role_name": role_name,
            "role": admin.role if admin else (role_name or "user").lower().replace(" ", "_"),
            "permissions": permissions,
            "is_admin": admin is not None,
            "status": user.status,
            "theme_preference": getattr(user, 'theme_preference', 'light'),
            "mongodb_role_lookup": mongodb_role_lookup,
            "plans": plans,
            "tools": tools,
            "subscriptions": [
                {
                    "id": sub.id,
                    "plan_name": await get_plan_name(db, sub.plan_id),
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
                "organization_name": await get_organization_name(db, admin.organization_id),
                "theme_preference": getattr(admin, 'theme_preference', 'light'),
                "is_active": admin.is_active,
                "created_at": admin.created_at.isoformat() if admin.created_at else None
            }
        
        return response
    
    # Check in admins table
    result = await db.execute(select(AdminModel).where(AdminModel.email == email))
    admin = result.scalar_one_or_none()
    
    if admin:
        if not has_data_scope_access(access_scope, email=admin.email, organization_id=admin.organization_id):
            raise HTTPException(status_code=403, detail="Not allowed to access this user")
        # Get subscription based on organization type
        subscriptions = []
        plans = []
        tools = []
        user_type = "individual" if await is_individual_users_org_id(db, admin.organization_id) else "organization"
        
        if admin.organization_id and not await is_individual_users_org_id(db, admin.organization_id):
            # For organization admins, get all active org subscriptions
            sub_result = await db.execute(
                select(SubscriptionModel).where(
                    SubscriptionModel.organization_id == admin.organization_id,
                    SubscriptionModel.status == "active"
                ).order_by(SubscriptionModel.start_date.desc())
            )
            subscriptions = sub_result.scalars().all()
        elif await is_individual_users_org_id(db, admin.organization_id):
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
            "organization_name": await get_organization_name(db, admin.organization_id),
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
                    "plan_name": await get_plan_name(db, sub.plan_id),
                    "status": sub.status,
                    "start_date": sub.start_date.isoformat() if sub.start_date else None,
                    "end_date": sub.end_date.isoformat() if sub.end_date else None
                } for sub in subscriptions
            ],
            "created_at": admin.created_at.isoformat() if admin.created_at else None
        }
    
    raise HTTPException(status_code=404, detail="User not found")


@api_router.post("/public/users/lookup", tags=["Public API"])
async def lookup_users(data: dict, payload: dict = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    """
    Bulk lookup users by email addresses.
    Returns user info including plans and tools for each user.
    """
    emails = data.get("emails", [])
    if not emails:
        raise HTTPException(status_code=400, detail="No emails provided")
    
    found_users = []
    not_found = []
    forbidden = []
    access_scope = await get_authenticated_data_scope(db, payload)
    
    for email in emails:
        # Check users table
        result = await db.execute(select(UserModel).where(UserModel.email == email))
        user = result.scalar_one_or_none()
        
        if user:
            if not has_data_scope_access(access_scope, email=user.email, organization_id=user.organization_id):
                forbidden.append(email)
                continue
            mongodb_role_lookup = await sync_user_role_from_mongodb(db, user)
            # Get role permissions
            role_result = await db.execute(select(RoleModel).where(RoleModel.id == user.role_id))
            role = role_result.scalar_one_or_none()
            permissions = json.loads(role.permissions) if role and role.permissions else []
            role_name = await get_role_name(db, user.role_id)
            
            # Check if also admin
            admin_result = await db.execute(select(AdminModel).where(AdminModel.email == email))
            admin = admin_result.scalar_one_or_none()
            
            # Get subscription details based on organization type
            plans = []
            tools = []
            subscriptions = []
            user_type = "individual" if await is_individual_users_org_id(db, user.organization_id) else "organization"
            
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
                "organization_name": await get_organization_name(db, user.organization_id),
                "user_type": user_type,
                "role_id": user.role_id,
                "role_name": role_name,
                "role": admin.role if admin else (role_name or "user").lower().replace(" ", "_"),
                "permissions": permissions,
                "is_admin": admin is not None,
                "status": user.status,
                "theme_preference": getattr(user, 'theme_preference', 'light'),
                "mongodb_role_lookup": mongodb_role_lookup,
                "plans": plans,
                "tools": tools,
                "subscriptions": [
                    {
                        "id": sub.id,
                        "plan_name": await get_plan_name(db, sub.plan_id),
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
                    "organization_name": await get_organization_name(db, admin.organization_id),
                    "is_active": admin.is_active
                }
            
            found_users.append(user_data)
            continue
        
        # Check admins table
        result = await db.execute(select(AdminModel).where(AdminModel.email == email))
        admin = result.scalar_one_or_none()
        
        if admin:
            if not has_data_scope_access(access_scope, email=admin.email, organization_id=admin.organization_id):
                forbidden.append(email)
                continue
            plans = []
            tools = []
            subscriptions = []
            user_type = "individual" if await is_individual_users_org_id(db, admin.organization_id) else "organization"
            
            if admin.organization_id and not await is_individual_users_org_id(db, admin.organization_id):
                # For organization admins, get all active org subscriptions
                sub_result = await db.execute(
                    select(SubscriptionModel).where(
                        SubscriptionModel.organization_id == admin.organization_id,
                        SubscriptionModel.status == "active"
                    ).order_by(SubscriptionModel.start_date.desc())
                )
                subscriptions = sub_result.scalars().all()
            elif await is_individual_users_org_id(db, admin.organization_id):
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
                "organization_name": await get_organization_name(db, admin.organization_id),
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
                        "plan_name": await get_plan_name(db, sub.plan_id),
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
        "not_found": not_found,
        "forbidden": forbidden
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
    
    await ensure_standard_roles_for_organization(db)
    await db.commit()
    result = await db.execute(
        select(RoleModel)
        .where(RoleModel.organization_id.is_(None))
        .order_by(RoleModel.name.asc())
    )
    roles = result.scalars().all()
    
    return {
        "organization_id": org_id,
        "organization_name": org.name,
        "roles": [
            {
                "id": r.id,
                "name": r.name,
                "organization_id": r.organization_id,
                "permissions": parse_json_list(r.permissions),
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
    project_id: Optional[str] = None,
    business_unit_id: Optional[str] = None,
    project_role: str = "member",
    identity_provider: Optional[str] = None,
    skip_auth0: bool = False,
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
    org_result = await db.execute(select(OrganizationModel).where(OrganizationModel.id == req.organization_id))
    request_org = org_result.scalar_one_or_none()
    if not request_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    await assert_email_allowed_for_org(db, req.email, request_org)
    # Check if user with this email already exists
    existing_user = await db.execute(select(UserModel).where(UserModel.email == req.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="A user with this email already exists")
    await ensure_standard_roles_for_organization(db)
    # Validate role exists in the global standard role catalog.
    role_result = await db.execute(
        select(RoleModel).where(
            RoleModel.id == role_id,
            RoleModel.organization_id.is_(None),
        )
    )
    role = role_result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Standard role not found")
    selected_role_id = role.id
    role, onboarding_role_lookup = await resolve_new_user_role(db, request_org, req.email, role)
    role_id = role.id
    project_role = (project_role or "member").strip().lower()
    if project_role not in ["manager", "member", "viewer"]:
        raise HTTPException(status_code=400, detail="Project role must be manager, member, or viewer")
    business_unit = None
    project = None
    if project_id:
        business_unit, project = await validate_user_request_team_assignment(db, req.organization_id, project_id, business_unit_id)
    
    now = datetime.now(timezone.utc)
    
    # Update request status
    req.status = "approved"
    req.approved_at = now
    req.updated_at = now
    req.approved_role_id = role.id
    req.approved_business_unit_id = business_unit.id if business_unit else None
    req.approved_project_id = project.id if project else None
    req.approved_project_role = project_role if project else None
    
    # Create the user
    user = UserModel(
        email=req.email,
        name=req.name,
        organization_id=req.organization_id,
        role_id=role.id,
        status="pending_verification",
        email_verified=False,
        password_set=False,
        first_login_token=secrets.token_urlsafe(32)
    )
    db.add(user)
    await db.flush()
    await replace_user_role_assignments(db, user, [role])
    team_member = None
    if project:
        team_member = await assign_user_to_project_team(db, user, project, project_role, payload.get("sub"))
    
    provision_org = request_org
    active_provider = normalize_identity_provider(identity_provider or await get_active_identity_provider(db))
    if skip_auth0 and active_provider == "auth0":
        active_provider = "zitadel"
    if provision_org and provision_org.status == "approved":
        needs_provider_org = (
            (active_provider == "auth0" and not provision_org.auth0_org_id)
            or (active_provider == "zitadel" and not provision_org.zitadel_org_id)
        )
        org_provision_result = {"success": True, "skipped": True}
        if needs_provider_org:
            org_provision_result = await provision_organization_for_active_provider(db, provision_org, active_provider)
        if not org_provision_result.get("success"):
            raise HTTPException(
                status_code=502,
                detail=f"Failed to create organization in {active_provider.upper()}: {org_provision_result.get('error') or 'unknown error'}"
            )
    provider_user_result = await provision_user_for_active_provider(
        db,
        user,
        req.email,
        req.name,
        {
            "probestack_user_id": user.id,
            "organization_id": req.organization_id,
            "organization_name": request_org.name,
        },
        provision_org,
        role.name,
        active_provider,
    )
    if not provider_user_result.get("success"):
        raise HTTPException(
            status_code=502,
            detail=f"Failed to create user in {active_provider.upper()}: {provider_user_result.get('error') or 'unknown error'}"
        )
    
    # Create notification
    notif = NotificationModel(
        title="User Request Approved",
        message=f"{req.name} has been added to {request_org.name} as {role.name}",
        type="success"
    )
    db.add(notif)
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()
    
    # Generate setup account URL
    base_url = os.environ.get("APP_URL", "")
    setup_url = f"{base_url}/setup-account?email={req.email}&token={user.first_login_token}" if base_url else None

    try:
        email_result = send_request_decision_email(
            to_email=req.email,
            recipient_name=req.name,
            request_name="user access request",
            status="approved",
            organization_name=request_org.name,
            next_steps="Your access has been approved. Please set up your account, verify your email, and then sign in to ProbeStack.",
            action_url=setup_url,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "User request approval email was not sent for %s: %s. To: %s. Bcc: %s",
                req.id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc"),
            )
    except Exception as exc:
        logger.error("Failed to build user request approval email for %s: %s", req.id, exc)
    
    return {
        "message": "User request approved",
        "user_id": user.id,
        "user": {
            "name": user.name,
            "email": user.email,
            "organization": request_org.name,
            "role": role.name,
            "auth0_user_id": user.auth0_user_id,
            "zitadel_user_id": user.zitadel_user_id,
            "status": user.status
        },
        "identity_provider": active_provider,
        "auth0_skipped": should_skip_auth0(active_provider, skip_auth0),
        "selected_role_id": selected_role_id,
        "assigned_role_id": role.id,
        "assigned_role_name": role.name,
        "role_source": "mongodb" if onboarding_role_lookup else "admin_selection",
        "mongodb_role_lookup": onboarding_role_lookup,
        "business_unit": model_to_dict(business_unit, ["tags"]) if business_unit else None,
        "team": model_to_dict(project) if project else None,
        "team_member": await project_team_member_to_dict(db, team_member) if team_member else None,
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
    organization_name = await get_organization_name(db, req.organization_id)
    notif = NotificationModel(
        title="User Request Rejected",
        message=f"Request to add {req.name} to {organization_name or req.organization_id} was rejected",
        type="warning"
    )
    db.add(notif)
    
    notification_emails = await get_notification_group_emails(db)
    await db.commit()

    try:
        email_result = send_request_decision_email(
            to_email=req.email,
            recipient_name=req.name,
            request_name="user access request",
            status="rejected",
            organization_name=organization_name or "your organization",
            reason=reason,
            notification_emails=notification_emails,
        )
        if not email_result.get("sent"):
            logger.warning(
                "User request rejection email was not sent for %s: %s. To: %s. Bcc: %s",
                req.id,
                email_result.get("reason", "unknown reason"),
                email_result.get("to"),
                email_result.get("bcc"),
            )
    except Exception as exc:
        logger.error("Failed to build user request rejection email for %s: %s", req.id, exc)
    
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

@api_router.post("/admin/schema/runtime/apply", tags=["Admin Schema"])
async def apply_runtime_schema(payload: dict = Depends(require_super_admin)):
    """
    Apply runtime database schema updates.

    This is useful after granting ALTER permission to the backend DB user when a
    deployed instance is already running.
    """
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await ensure_runtime_schema(conn)
        return {
            "message": "Runtime schema applied",
            "database": DB_NAME,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        logger.exception("Runtime schema apply failed")
        raise HTTPException(status_code=500, detail=f"Runtime schema apply failed: {exc}")

# Include the router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=CORS_ORIGIN_REGEX,
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

async def ensure_mysql_column(conn, table_name: str, column_name: str, column_definition: str):
    if not await mysql_column_exists(conn, table_name, column_name):
        await conn.execute(text(f"ALTER TABLE `{table_name}` ADD COLUMN `{column_name}` {column_definition}"))

async def ensure_runtime_schema(conn):
    if not await mysql_column_exists(conn, "plans", "product_id"):
        await conn.execute(text("ALTER TABLE plans ADD COLUMN product_id VARCHAR(36) NULL AFTER name"))
    if not await mysql_column_exists(conn, "plans", "price_label"):
        await conn.execute(text("ALTER TABLE plans ADD COLUMN price_label VARCHAR(100) NULL AFTER price_yearly"))
    if not await mysql_column_exists(conn, "plans", "billing_period"):
        await conn.execute(text("ALTER TABLE plans ADD COLUMN billing_period VARCHAR(100) NULL AFTER price_label"))
    if not await mysql_column_exists(conn, "plans", "is_popular"):
        await conn.execute(text("ALTER TABLE plans ADD COLUMN is_popular BOOL NOT NULL DEFAULT FALSE AFTER cost"))
    await ensure_mysql_column(conn, "subscriptions", "api_count", "INT NULL")
    await ensure_mysql_column(conn, "subscriptions", "quota", "INT NULL")
    await ensure_mysql_column(conn, "subscriptions", "used_quota", "INT NOT NULL DEFAULT 0")
    await conn.execute(text("""
        UPDATE subscriptions s
        LEFT JOIN plans p ON s.plan_id = p.id
        SET s.quota = COALESCE(s.quota, s.api_count, p.api_limit, 0),
            s.used_quota = COALESCE(s.used_quota, 0)
        WHERE s.quota IS NULL OR s.used_quota IS NULL
    """))
    if await mysql_column_exists(conn, "plan_upgrade_requests", "current_plan_id"):
        await conn.execute(text("ALTER TABLE plan_upgrade_requests MODIFY COLUMN current_plan_id TEXT NOT NULL"))

    organization_columns = [
        ("organization_code", "VARCHAR(100) NULL"),
        ("legal_name", "VARCHAR(255) NULL"),
        ("industry", "VARCHAR(100) NULL"),
        ("business_type", "VARCHAR(50) NULL"),
        ("country", "VARCHAR(100) NULL"),
        ("region", "VARCHAR(100) NULL"),
        ("time_zone", "VARCHAR(100) NULL"),
        ("headquarters", "VARCHAR(255) NULL"),
        ("default_currency", "VARCHAR(20) NULL"),
        ("billing_account", "VARCHAR(255) NULL"),
        ("cost_center", "VARCHAR(100) NULL"),
        ("tax_id", "VARCHAR(100) NULL"),
        ("website", "VARCHAR(500) NULL"),
        ("logo_url", "TEXT NULL"),
        ("primary_contact_id", "VARCHAR(36) NULL"),
        ("executive_sponsor_id", "VARCHAR(36) NULL"),
        ("technical_contact_id", "VARCHAR(36) NULL"),
        ("security_contact_id", "VARCHAR(36) NULL"),
        ("identity_provider", "VARCHAR(50) NULL"),
        ("sso_enabled", "BOOL NOT NULL DEFAULT FALSE"),
        ("scim_enabled", "BOOL NOT NULL DEFAULT FALSE"),
        ("mfa_required", "BOOL NOT NULL DEFAULT FALSE"),
        ("default_api_gateway", "VARCHAR(255) NULL"),
        ("default_ai_gateway", "VARCHAR(255) NULL"),
        ("default_mcp_gateway", "VARCHAR(255) NULL"),
        ("default_api_design_tool", "VARCHAR(255) NULL"),
        ("default_api_testing_tool", "VARCHAR(255) NULL"),
        ("api_agent_lifecycle_stage", "VARCHAR(100) NULL"),
        ("default_api_inventory", "VARCHAR(255) NULL"),
        ("cloud_provider", "VARCHAR(100) NULL"),
        ("kubernetes_platform", "VARCHAR(100) NULL"),
        ("default_environment_strategy", "VARCHAR(255) NULL"),
        ("compliance_standards", "TEXT NULL"),
        ("encryption_standard", "VARCHAR(255) NULL"),
        ("data_residency", "VARCHAR(255) NULL"),
        ("created_by", "VARCHAR(36) NULL"),
    ]
    for column_name, column_definition in organization_columns:
        await ensure_mysql_column(conn, "organizations", column_name, column_definition)

    business_unit_columns = [
        ("display_name", "VARCHAR(255) NULL"),
        ("parent_business_unit_id", "VARCHAR(36) NULL"),
        ("division", "VARCHAR(255) NULL"),
        ("department", "VARCHAR(255) NULL"),
        ("line_of_business", "VARCHAR(255) NULL"),
        ("business_executive_id", "VARCHAR(36) NULL"),
        ("business_owner_id", "VARCHAR(36) NULL"),
        ("product_owner_id", "VARCHAR(36) NULL"),
        ("technical_owner_id", "VARCHAR(36) NULL"),
        ("enterprise_architect_id", "VARCHAR(36) NULL"),
        ("platform_owner_id", "VARCHAR(36) NULL"),
        ("security_owner_id", "VARCHAR(36) NULL"),
        ("compliance_officer_id", "VARCHAR(36) NULL"),
        ("support_team", "VARCHAR(255) NULL"),
        ("operations_team", "VARCHAR(255) NULL"),
        ("cost_center", "VARCHAR(100) NULL"),
        ("budget", "FLOAT NULL"),
        ("chargeback_model", "VARCHAR(255) NULL"),
        ("billing_account", "VARCHAR(255) NULL"),
        ("monthly_budget", "FLOAT NULL"),
        ("annual_budget", "FLOAT NULL"),
        ("ai_budget", "FLOAT NULL"),
        ("api_budget", "FLOAT NULL"),
        ("cloud_provider", "VARCHAR(100) NULL"),
        ("region", "VARCHAR(100) NULL"),
        ("kubernetes_cluster", "VARCHAR(255) NULL"),
        ("namespace", "VARCHAR(255) NULL"),
        ("api_gateway", "VARCHAR(255) NULL"),
        ("ai_gateway", "VARCHAR(255) NULL"),
        ("logging_platform", "VARCHAR(255) NULL"),
        ("monitoring_platform", "VARCHAR(255) NULL"),
        ("secret_manager", "VARCHAR(255) NULL"),
        ("approval_workflow", "VARCHAR(255) NULL"),
        ("risk_classification", "VARCHAR(50) NULL"),
        ("business_criticality", "VARCHAR(50) NULL"),
        ("data_classification", "VARCHAR(50) NULL"),
        ("regulatory_standards", "TEXT NULL"),
        ("retention_policy", "VARCHAR(255) NULL"),
        ("backup_policy", "VARCHAR(255) NULL"),
        ("dr_enabled", "BOOL NOT NULL DEFAULT FALSE"),
        ("sla_tier", "VARCHAR(50) NULL"),
    ]
    for column_name, column_definition in business_unit_columns:
        await ensure_mysql_column(conn, "business_units", column_name, column_definition)

    project_columns = [
        ("project_type", "VARCHAR(100) NULL"),
        ("portfolio", "VARCHAR(255) NULL"),
        ("project_manager_id", "VARCHAR(36) NULL"),
        ("product_manager_id", "VARCHAR(36) NULL"),
        ("scrum_master_id", "VARCHAR(36) NULL"),
        ("technical_lead_id", "VARCHAR(36) NULL"),
        ("security_lead_id", "VARCHAR(36) NULL"),
        ("devops_lead_id", "VARCHAR(36) NULL"),
        ("methodology", "VARCHAR(100) NULL"),
        ("sprint_duration", "VARCHAR(100) NULL"),
        ("repository", "VARCHAR(500) NULL"),
        ("cicd_tool", "VARCHAR(255) NULL"),
        ("issue_tracker", "VARCHAR(255) NULL"),
        ("documentation_url", "VARCHAR(500) NULL"),
        ("authentication_method", "VARCHAR(255) NULL"),
        ("authorization_method", "VARCHAR(255) NULL"),
        ("oauth_provider", "VARCHAR(255) NULL"),
        ("mtls_enabled", "BOOL NOT NULL DEFAULT FALSE"),
        ("jwt_enabled", "BOOL NOT NULL DEFAULT FALSE"),
        ("api_key_enabled", "BOOL NOT NULL DEFAULT FALSE"),
        ("secrets_vault", "VARCHAR(255) NULL"),
        ("pci_applicable", "BOOL NOT NULL DEFAULT FALSE"),
        ("standard_rules", "TEXT NULL"),
        ("custom_rules", "TEXT NULL"),
        ("owasp_top10_enabled", "BOOL NOT NULL DEFAULT FALSE"),
        ("linting_enabled", "BOOL NOT NULL DEFAULT FALSE"),
    ]
    for column_name, column_definition in project_columns:
        await ensure_mysql_column(conn, "projects", column_name, column_definition)

@app.on_event("startup")
async def startup():
    if not RUN_RUNTIME_SCHEMA_MIGRATIONS:
        logger.info("Runtime schema migrations are disabled by RUN_RUNTIME_SCHEMA_MIGRATIONS")
        return
    try:
        logger.info("Applying runtime database schema migrations")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await ensure_runtime_schema(conn)
        logger.info("Runtime database schema migrations applied")
    except Exception as e:
        logger.exception("Database initialization failed")
        if REQUIRE_RUNTIME_SCHEMA_MIGRATIONS:
            raise
        logger.warning(
            "Server is starting without successful runtime schema migration. "
            "Set REQUIRE_RUNTIME_SCHEMA_MIGRATIONS=true to fail startup on this error."
        )

@app.on_event("shutdown")
async def shutdown():
    await engine.dispose()
