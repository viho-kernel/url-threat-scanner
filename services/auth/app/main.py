import hashlib
import hmac
import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID, uuid4

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, status
from psycopg.errors import UniqueViolation
from psycopg_pool import ConnectionPool
from pwdlib import PasswordHash
from pydantic import BaseModel, EmailStr, Field

database_url = os.getenv("DATABASE_URL")
auth_service_token = os.getenv("AUTH_SERVICE_TOKEN", "")
jwt_secret = os.getenv("JWT_SECRET", "")
jwt_issuer = "url-threat-scanner-auth"
jwt_audience = "url-threat-scanner-api"
jwt_lifetime_minutes = 15

if not jwt_secret:
    raise RuntimeError("JWT_SECRET is required")

if not database_url:
    raise RuntimeError("DATABASE_URL is required")

database_pool = ConnectionPool(
    conninfo=database_url,
    min_size=1,
    max_size=5,
    timeout=2,
    open=False,
)

password_hasher = PasswordHash.recommended()

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("auth")


@asynccontextmanager
async def lifespan(app: FastAPI):
    database_pool.open(wait=False)
    yield
    database_pool.close()


app = FastAPI(
    title="URL Threat Scanner Auth",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class UserResponse(BaseModel):
    id: UUID
    email: EmailStr
    is_active: bool
    created_at: datetime


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class VerifyResponse(BaseModel):
    user_id: UUID
    active: bool


class APIKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    expires_in_days: int = Field(default=90, ge=1, le=365)


class APIKeyCreateResponse(BaseModel):
    id: UUID
    name: str
    key: str
    key_prefix: str
    created_at: datetime
    expires_at: datetime


def verify_service_token(
    x_service_token: Annotated[str | None, Header()] = None,
) -> None:
    if not auth_service_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="service authentication is not configured",
        )

    if x_service_token is None or not hmac.compare_digest(
        x_service_token,
        auth_service_token,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid service credentials",
        )


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "service": "auth",
        "status": "ok",
    }


@app.get("/ready")
def readiness() -> dict[str, str]:
    try:
        with database_pool.connection() as connection:
            connection.execute("SELECT 1")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database unavailable",
        )

    return {
        "service": "auth",
        "status": "ready",
        "database": "connected",
    }


@app.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    request: RegisterRequest,
    _: Annotated[None, Depends(verify_service_token)],
) -> UserResponse:
    email = str(request.email).lower()
    hashed_password = password_hasher.hash(request.password)

    try:
        with database_pool.connection() as connection:
            row = connection.execute(
                """
                INSERT INTO users (email, password_hash)
                VALUES (%s, %s)
                RETURNING id, email, is_active, created_at
                """,
                (email, hashed_password),
            ).fetchone()
    except UniqueViolation:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="user already exists",
        )

    user = UserResponse(
        id=row[0],
        email=row[1],
        is_active=row[2],
        created_at=row[3],
    )

    logger.info(
        json.dumps(
            {
                "event": "user_registered",
                "user_id": str(user.id),
            }
        )
    )

    return user


@app.post("/login", response_model=TokenResponse)
def login(
    request: LoginRequest,
    _: Annotated[None, Depends(verify_service_token)],
) -> TokenResponse:
    email = str(request.email).lower()

    with database_pool.connection() as connection:
        row = connection.execute(
            """
            SELECT id, password_hash, is_active
            FROM users
            WHERE LOWER(email) = %s
            """,
            (email,),
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid email or password",
        )

    user_id, stored_password_hash, is_active = row

    if not is_active or not password_hasher.verify(
        request.password,
        stored_password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid email or password",
        )

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=jwt_lifetime_minutes)

    access_token = jwt.encode(
        {
            "sub": str(user_id),
            "iss": jwt_issuer,
            "aud": jwt_audience,
            "iat": now,
            "exp": expires_at,
            "jti": str(uuid4()),
        },
        jwt_secret,
        algorithm="HS256",
    )

    logger.info(
        json.dumps(
            {
                "event": "user_login_succeeded",
                "user_id": str(user_id),
            }
        )
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=jwt_lifetime_minutes * 60,
    )

def require_access_token(authorization: str | None) -> UUID:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.removeprefix("Bearer ").strip()

    try:
        payload = jwt.decode(
            token,
            jwt_secret,
            algorithms=["HS256"],
            audience=jwt_audience,
            issuer=jwt_issuer,
        )

        user_id = UUID(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    with database_pool.connection() as connection:
        row = connection.execute(
            """
            SELECT is_active
            FROM users
            WHERE id = %s
            """,
            (user_id,),
        ).fetchone()

    if row is None or not row[0]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user_id


def require_api_key(raw_api_key: str | None) -> UUID:
    if (
        raw_api_key is None
        or not raw_api_key.startswith("uts_")
        or len(raw_api_key) > 256
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid API key",
        )

    key_hash = hashlib.sha256(raw_api_key.encode()).hexdigest()

    with database_pool.connection() as connection:
        row = connection.execute(
            """
            UPDATE api_keys
            SET last_used_at = NOW()
            FROM users
            WHERE api_keys.key_hash = %s
              AND api_keys.user_id = users.id
              AND users.is_active = TRUE
              AND api_keys.revoked_at IS NULL
              AND (
                    api_keys.expires_at IS NULL
                    OR api_keys.expires_at > NOW()
                  )
            RETURNING api_keys.user_id
            """,
            (key_hash,),
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid API key",
        )

    return row[0]


@app.get("/verify", response_model=VerifyResponse)
def verify_access_token(
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header()] = None,
    _: Annotated[None, Depends(verify_service_token)] = None,
) -> VerifyResponse:
    has_bearer_token = authorization is not None
    has_api_key = x_api_key is not None

    if has_bearer_token == has_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="provide exactly one authentication credential",
        )

    if has_bearer_token:
        user_id = require_access_token(authorization)
    else:
        user_id = require_api_key(x_api_key)

    return VerifyResponse(
        user_id=user_id,
        active=True,
    )


@app.post(
    "/api-keys",
    response_model=APIKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_api_key(
    request: APIKeyCreateRequest,
    authorization: Annotated[str | None, Header()] = None,
    _: Annotated[None, Depends(verify_service_token)] = None,
) -> APIKeyCreateResponse:
    user_id = require_access_token(authorization)

    key_name = request.name.strip()
    if not key_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key name cannot be empty",
        )

    raw_key = f"uts_{secrets.token_urlsafe(32)}"
    key_prefix = raw_key[:12]
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(days=request.expires_in_days)

    with database_pool.connection() as connection:
        row = connection.execute(
            """
            INSERT INTO api_keys (
                user_id,
                name,
                key_prefix,
                key_hash,
                created_at,
                expires_at
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                user_id,
                key_name,
                key_prefix,
                key_hash,
                created_at,
                expires_at,
            ),
        ).fetchone()

    logger.info(
        json.dumps(
            {
                "event": "api_key_created",
                "user_id": str(user_id),
                "api_key_id": str(row[0]),
                "key_prefix": key_prefix,
            }
        )
    )

    return APIKeyCreateResponse(
        id=row[0],
        name=key_name,
        key=raw_key,
        key_prefix=key_prefix,
        created_at=created_at,
        expires_at=expires_at,
    )

class APIKeyRevokeRequest(BaseModel):
    id: UUID


class APIKeyRevokeResponse(BaseModel):
    id: UUID
    revoked: bool
    revoked_at: datetime

@app.post(
    "/api-keys/revoke",
    response_model=APIKeyRevokeResponse,
)
def revoke_api_key(
    request: APIKeyRevokeRequest,
    authorization: Annotated[str | None, Header()] = None,
    _: Annotated[None, Depends(verify_service_token)] = None,
) -> APIKeyRevokeResponse:
    user_id = require_access_token(authorization)

    with database_pool.connection() as connection:
        row = connection.execute(
            """
            UPDATE api_keys
            SET revoked_at = NOW()
            WHERE id = %s
              AND user_id = %s
              AND revoked_at IS NULL
            RETURNING id, revoked_at
            """,
            (request.id, user_id),
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    logger.info(
        json.dumps(
            {
                "event": "api_key_revoked",
                "user_id": str(user_id),
                "api_key_id": str(row[0]),
            }
        )
    )

    return APIKeyRevokeResponse(
        id=row[0],
        revoked=True,
        revoked_at=row[1],
    )