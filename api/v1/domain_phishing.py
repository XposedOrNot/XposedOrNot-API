"""Domain phishing check router module."""

import socket
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

import dnstwist
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel, Field, validator, EmailStr
from redis import Redis

from config.limiter import limiter, RATE_LIMIT_HELP
from config.settings import REDIS_HOST, REDIS_PORT, REDIS_DB
from models.responses import BaseResponse
from utils.validation import validate_email_with_tld, validate_variables
from utils.token import confirm_token
from google.cloud import datastore

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
    domain: str = Field(..., description="Domain to check for phishing variants")

    @validator("domain")
    def validate_domain(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("Domain must be a non-empty string")
        if len(v) > 255:
            raise ValueError("Domain length exceeds maximum allowed length")
        if "." not in v:
            raise ValueError("Invalid domain format")
        return v.lower().strip()


class DomainPhishingSummaryResponse(BaseResponse):
    total_scanned: int
    total_live: int = 0
    unique_fuzzers: int = 0
    last_checked: Optional[str] = None


class DomainPhishingResponse(BaseResponse):
    total_scanned: int
    total_live: int = 0
    unique_fuzzers: int = 0
    live_domains: List[str] = []
    raw_results: List[Dict[str, Any]]
    last_checked: Optional[str] = None


def is_domain_live(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False


def get_cached_result(domain: str) -> Optional[Dict]:
    cache_key = f"phishing_check:{domain}"
    cached_data = redis_client.get(cache_key)
    if cached_data:
        try:
            return json.loads(cached_data)
        except json.JSONDecodeError:
            return None
    return None


def cache_result(domain: str, result: Dict, expiry_hours: int = 24) -> None:
    cache_key = f"phishing_check:{domain}"
    if isinstance(result.get("last_checked"), datetime):
        result["last_checked"] = result["last_checked"].isoformat()
    redis_client.setex(cache_key, timedelta(hours=expiry_hours), json.dumps(result))


async def verify_user_access(email: str, token: str) -> bool:
    if not email or not token:
        return False
    try:
        verified_email = await confirm_token(token)
        if not verified_email or verified_email.lower() != email.lower():
            return False
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", email.lower())
        alert_record = datastore_client.get(alert_key)
        is_verified = bool(alert_record and alert_record.get("verified", False))
        return is_verified
    except Exception:
        return False


@router.get(
    "/domain-phishing/{domain}",
    response_model=None,
    responses={
        200: {
            "description": "Domain phishing check results",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "total_scanned": 10,
                        "total_live": 2,
                        "live_domains": ["example.com"],
                        "raw_results": [],
                        "last_checked": "2024-03-07T12:00:00",
                    }
                }
            },
        }
    },
    include_in_schema=True,
)
@limiter.limit("10/minute")
async def check_domain_phishing(
    domain: str,
    request: Request,
    email: Optional[EmailStr] = Query(None, description="Email for authentication"),
    token: Optional[str] = Query(None, description="Verification token"),
) -> Union[DomainPhishingSummaryResponse, DomainPhishingResponse]:
    try:
        domain_request = DomainPhishingRequest(domain=domain)
        domain = domain_request.domain
        is_authenticated = False
        if email and token:
            is_authenticated = await verify_user_access(email, token)
        cached_result = get_cached_result(domain)
        if cached_result:
            # Recalculate unique_fuzzers if missing or 0 and raw_results is present
            if (not cached_result.get("unique_fuzzers")) and cached_result.get(
                "raw_results"
            ):
                cached_result["unique_fuzzers"] = len(
                    set(
                        r.get("fuzzer", "")
                        for r in cached_result["raw_results"]
                        if "fuzzer" in r and r.get("fuzzer")
                    )
                )
            if is_authenticated:
                response = DomainPhishingResponse(**cached_result)
                return response
            response = DomainPhishingSummaryResponse(
                status="success",
                total_scanned=cached_result["total_scanned"],
                total_live=cached_result["total_live"],
                unique_fuzzers=cached_result.get("unique_fuzzers", 0),
                last_checked=cached_result["last_checked"],
            )
            return response
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
            unique_fuzzers = len(
                set(
                    r.get("fuzzer", "")
                    for r in twist_results
                    if "fuzzer" in r and r.get("fuzzer")
                )
            )
            response_data = {
                "status": "success",
                "total_scanned": len(twist_results),
                "total_live": len(live_domains),
                "unique_fuzzers": unique_fuzzers,
                "live_domains": live_domains,
                "raw_results": twist_results,
                "last_checked": datetime.utcnow().isoformat(),
            }
            cache_result(domain, response_data)
            if is_authenticated:
                response = DomainPhishingResponse(**response_data)
                return response
            response = DomainPhishingSummaryResponse(
                status="success",
                total_scanned=response_data["total_scanned"],
                total_live=response_data["total_live"],
                unique_fuzzers=response_data["unique_fuzzers"],
                last_checked=response_data["last_checked"],
            )
            return response
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Error running domain check: {str(e)}"
            )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error processing domain: {str(e)}"
        )
