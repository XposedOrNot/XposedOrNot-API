"""Domain phishing check router module."""

import socket
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

import dnstwist
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, validator
from redis import Redis

from config.limiter import limiter, RATE_LIMIT_HELP
from config.settings import REDIS_HOST, REDIS_PORT, REDIS_DB
from models.responses import BaseResponse

router = APIRouter()

redis_client = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True
)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
STATIC_DIR = BASE_DIR / "static" / "static"
DICTIONARY_FILE = STATIC_DIR / "dictionary.txt"
TLD_FILE = STATIC_DIR / "tld.txt"

if not DICTIONARY_FILE.exists():
    raise FileNotFoundError(f"Dictionary file not found at {DICTIONARY_FILE}")
if not TLD_FILE.exists():
    raise FileNotFoundError(f"TLD file not found at {TLD_FILE}")


def validate_file_content(file_path: Path, min_lines: int = 1) -> None:
    """Validate file exists and has minimum required lines."""
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "r") as f:
        lines = [line.strip() for line in f if line.strip()]
        if len(lines) < min_lines:
            raise ValueError(
                f"File {file_path} has insufficient content (minimum {min_lines} lines required)"
            )


try:
    validate_file_content(DICTIONARY_FILE, min_lines=10)
    validate_file_content(TLD_FILE, min_lines=5)
except Exception as e:
    raise


class DomainPhishingRequest(BaseModel):
    """Domain phishing check request model."""

    domain: str = Field(..., description="Domain to check for phishing variants")

    @validator("domain")
    def validate_domain(cls, v: str) -> str:
        """Validate domain format."""
        if not v or not isinstance(v, str):
            raise ValueError("Domain must be a non-empty string")
        if len(v) > 255:
            raise ValueError("Domain length exceeds maximum allowed length")
        if "." not in v:
            raise ValueError("Invalid domain format")
        return v.lower().strip()


class DomainPhishingResponse(BaseResponse):
    """Domain phishing check response model."""

    total_scanned: int
    total_live: int = 0
    live_domains: List[str] = []
    raw_results: List[Dict[str, Any]]
    last_checked: Optional[str] = None


def is_domain_live(domain: str) -> bool:
    """Check if a domain is live by attempting to resolve its IP address."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False


def get_cached_result(domain: str) -> Optional[Dict]:
    """Get cached phishing check results for a domain."""
    cache_key = f"phishing_check:{domain}"
    cached_data = redis_client.get(cache_key)
    if cached_data:
        try:
            return json.loads(cached_data)
        except json.JSONDecodeError:
            return None
    return None


def cache_result(domain: str, result: Dict, expiry_hours: int = 24) -> None:
    """Cache phishing check results for a domain."""
    cache_key = f"phishing_check:{domain}"
    if isinstance(result.get("last_checked"), datetime):
        result["last_checked"] = result["last_checked"].isoformat()
    redis_client.setex(cache_key, timedelta(hours=expiry_hours), json.dumps(result))


@router.get(
    "/domain-phishing/{domain}",
    response_model=DomainPhishingResponse,
    include_in_schema=True,
)
@limiter.limit("10/minute")
async def check_domain_phishing(
    domain: str, request: Request
) -> DomainPhishingResponse:
    """Check a domain for potential phishing variants using dnstwist."""
    try:
        domain_request = DomainPhishingRequest(domain=domain)
        domain = domain_request.domain

        cached_result = get_cached_result(domain)
        if cached_result:
            return DomainPhishingResponse(**cached_result)

        try:
            options = {
                "registered": True,
                "format": "json",
                "threads": 8,
                "all": True,
                "mxcheck": True,
                "whois": True,
                "dictionary": str(DICTIONARY_FILE),
                "tld": str(TLD_FILE),
            }

            twist_results = dnstwist.run(domain=domain, **options)

            twist_results.sort(
                key=lambda x: (
                    x.get("fuzzer", "") != "*original",
                    x.get("domain-name", "") or x.get("domain", ""),
                )
            )

            live_domains = []
            for result in twist_results:
                domain_to_check = result.get("domain-name") or result.get("domain")
                if domain_to_check and is_domain_live(domain_to_check):
                    live_domains.append(domain_to_check)

            response = DomainPhishingResponse(
                status="success",
                total_scanned=len(twist_results),
                total_live=len(live_domains),
                live_domains=live_domains,
                raw_results=twist_results,
                last_checked=datetime.utcnow().isoformat(),
            )

            cache_result(domain, response.dict())
            return response

        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Error running domain check: {str(e)}"
            )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error processing domain: {str(e)}"
        )
