import hmac
import ipaddress
import json
import logging
import os
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="URL Threat Scanner",
    docs_url=None,
    redoc_url=None,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("scanner")

service_token = os.getenv("SERVICE_TOKEN", "")


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class AnalyzeResponse(BaseModel):
    verdict: str
    risk_score: int
    flags: list[str]


def verify_service_token(x_service_token: str | None) -> None:
    if not service_token:
        raise HTTPException(
            status_code=503,
            detail="service authentication is not configured",
        )

    if x_service_token is None or not hmac.compare_digest(
        x_service_token,
        service_token,
    ):
        raise HTTPException(
            status_code=401,
            detail="invalid service credentials",
        )


def analyze_url(raw_url: str) -> AnalyzeResponse:
    parsed = urlparse(raw_url)
    hostname = (parsed.hostname or "").lower()

    flags: list[str] = []
    score = 0

    if hostname.startswith("xn--") or ".xn--" in hostname:
        flags.append("punycode_hostname")
        score += 30

    try:
        ipaddress.ip_address(hostname)
        flags.append("ip_address_hostname")
        score += 20
    except ValueError:
        pass

    suspicious_words = (
        "login",
        "verify",
        "account",
        "secure",
        "password",
        "update",
        "wallet",
    )

    searchable_value = f"{hostname}{parsed.path}".lower()

    if any(word in searchable_value for word in suspicious_words):
        flags.append("suspicious_keyword")
        score += 20

    if hostname.count(".") >= 4:
        flags.append("excessive_subdomains")
        score += 15

    if "%" in raw_url:
        flags.append("encoded_characters")
        score += 10

    score = min(score, 100)

    # We say low-risk, not safe. Static analysis alone cannot prove safety.
    if score >= 40: 
        verdict = "suspicious"
    elif score >= 20:
        verdict = "review"
    else:
        verdict = "low-risk"

    return AnalyzeResponse(
        verdict=verdict,
        risk_score=score,
        flags=flags,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "service": "scanner",
        "status": "ok",
    }


@app.get("/ready")
def readiness() -> dict[str, str]:
    if not service_token:
        raise HTTPException(
            status_code=503,
            detail="service authentication is not configured",
        )

    return {
        "service": "scanner",
        "status": "ready",
    }


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(
    request: AnalyzeRequest,
    x_service_token: str | None = Header(default=None),
) -> AnalyzeResponse:
    verify_service_token(x_service_token)

    result = analyze_url(request.url)

    logger.info(
        json.dumps(
            {
                "event": "url_analyzed",
                "host": urlparse(request.url).hostname,
                "verdict": result.verdict,
                "risk_score": result.risk_score,
                "flag_count": len(result.flags),
            }
        )
    )

    return result