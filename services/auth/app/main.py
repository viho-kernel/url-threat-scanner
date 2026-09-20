import hmac
import json
import jwt
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID, uuid4

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

@app.get("/verify", response_model=VerifyResponse)
def verify_access_token(
    authorization: Annotated[str | None, Header()] = None,
    _: Annotated[None, Depends(verify_service_token)] = None,
) -> VerifyResponse:
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

    return VerifyResponse(
        user_id=user_id,
        active=True,
    )