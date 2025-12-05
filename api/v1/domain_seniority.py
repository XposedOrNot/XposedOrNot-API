"""Domain seniority endpoint for retrieving breach-exposed email seniority data."""

from collections import defaultdict
from enum import Enum
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from google.cloud import datastore
from pydantic import BaseModel, EmailStr, Field, validator

from models.base import BaseResponse
from services.send_email import send_exception_email
from utils.custom_limiter import custom_rate_limiter
from utils.token import confirm_token
from utils.validation import validate_email_with_tld, validate_token

router = APIRouter()


class SeniorityLevel(str, Enum):
    """Enum for seniority level filter options."""

    C_SUITE = "c_suite"
    VP = "vp"
    DIRECTOR = "director"
    ALL = "all"


class BreachInfo(BaseModel):
    """Model for breach information associated with a seniority record."""

    breach_name: str
    breach_date: Optional[str] = None  # Format: "Month Year" (e.g., "January 2020")
    xposed_data: List[str] = Field(default_factory=list)


class SeniorityRecord(BaseModel):
    """Model for individual seniority record."""

    email: str
    domain: str
    seniority: str
    breaches: List[BreachInfo] = Field(default_factory=list)


class DomainSeniorityData(BaseModel):
    """Model for seniority data of a single domain."""

    domain: str
    seniority_data: List[SeniorityRecord] = Field(default_factory=list)
    counts: Dict[str, int] = Field(default_factory=dict)


class DomainSeniorityResponse(BaseResponse):
    """Response model for single domain seniority request."""

    domain: str
    seniority_data: List[SeniorityRecord] = Field(default_factory=list)
    counts: Dict[str, int] = Field(default_factory=dict)


class AllDomainsSeniorityResponse(BaseResponse):
    """Response model for all domains seniority request."""

    domains: Dict[str, DomainSeniorityData] = Field(default_factory=dict)
    total_domains: int = 0


async def verify_user_access(email: str, token: str) -> bool:
    """Verify user access based on email and token."""
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


async def get_verified_domains_for_user(email: str) -> List[str]:
    """Get all verified domains for a user."""
    try:
        datastore_client = datastore.Client()
        query = datastore_client.query(kind="xon_domains")
        query.add_filter("email", "=", email.lower())
        query.add_filter("verified", "=", True)
        return [entity["domain"] for entity in query.fetch()]
    except Exception:
        return []


VALID_SENIORITY_LEVELS = {
    SeniorityLevel.C_SUITE.value,
    SeniorityLevel.VP.value,
    SeniorityLevel.DIRECTOR.value,
}


async def get_breach_info_for_email(
    datastore_client: datastore.Client,
    email: str,
    domain: str,
    breach_cache: Dict[str, dict],
) -> List[BreachInfo]:
    """Get breach information for a specific email and domain."""
    breaches = []

    # Query xon_domains_details to get breaches for this email
    query = datastore_client.query(kind="xon_domains_details")
    query.add_filter("email", "=", email.lower())
    query.add_filter("domain", "=", domain.lower())

    for entity in query.fetch():
        breach_name = entity.get("breach", "")
        if not breach_name or breach_name == "No_Breaches":
            continue

        # Get breach details from cache or fetch from datastore
        if breach_name not in breach_cache:
            breach_key = datastore_client.key("xon_breaches", breach_name)
            breach_entity = datastore_client.get(breach_key)
            if breach_entity:
                breach_cache[breach_name] = {
                    "breached_date": breach_entity.get("breached_date"),
                    "xposed_data": breach_entity.get("xposed_data", ""),
                }
            else:
                breach_cache[breach_name] = None

        breach_data = breach_cache.get(breach_name)
        breach_date = None
        xposed_data = []

        if breach_data:
            # Format breach date as "Month Year"
            if breach_data.get("breached_date"):
                breach_date = breach_data["breached_date"].strftime("%B %Y")

            # Parse xposed_data (semicolon-separated string)
            xposed_data_raw = breach_data.get("xposed_data", "")
            if isinstance(xposed_data_raw, str) and xposed_data_raw:
                xposed_data = [item.strip() for item in xposed_data_raw.split(";")]
            elif isinstance(xposed_data_raw, list):
                xposed_data = xposed_data_raw

        breaches.append(
            BreachInfo(
                breach_name=breach_name,
                breach_date=breach_date,
                xposed_data=xposed_data,
            )
        )

    return breaches


async def get_seniority_data(
    domain: str, seniority_filter: SeniorityLevel
) -> DomainSeniorityData:
    """Get seniority data for a specific domain."""
    datastore_client = datastore.Client()
    query = datastore_client.query(kind="xon_domains_seniority")
    query.add_filter("domain", "=", domain.lower())

    if seniority_filter != SeniorityLevel.ALL:
        query.add_filter("seniority", "=", seniority_filter.value)

    seniority_records = []
    counts = defaultdict(int)
    breach_cache: Dict[str, dict] = {}  # Cache breach details to avoid repeated lookups

    for entity in query.fetch():
        entity_seniority = entity.get("seniority", "")
        entity_email = entity.get("email", "")

        # For "all" filter, only include valid seniority levels (c_suite, vp, director)
        if seniority_filter == SeniorityLevel.ALL:
            if entity_seniority not in VALID_SENIORITY_LEVELS:
                continue

        # Get breach information for this email
        breaches = await get_breach_info_for_email(
            datastore_client, entity_email, domain, breach_cache
        )

        record = SeniorityRecord(
            email=entity_email,
            domain=domain,
            seniority=entity_seniority,
            breaches=breaches,
        )
        seniority_records.append(record)
        counts[entity_seniority] += 1

    counts["total"] = len(seniority_records)

    return DomainSeniorityData(
        domain=domain,
        seniority_data=seniority_records,
        counts=dict(counts),
    )


@router.get(
    "/domain-seniority",
    response_model=None,
    responses={
        200: {
            "description": "Domain seniority data retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "domain": "example.com",
                        "seniority_data": [
                            {
                                "email": "ceo@example.com",
                                "domain": "example.com",
                                "seniority": "c_suite",
                                "breaches": [
                                    {
                                        "breach_name": "ExampleBreach",
                                        "breach_date": "January 2020",
                                        "xposed_data": ["Email", "Password", "Name"],
                                    }
                                ],
                            },
                            {
                                "email": "vp.sales@example.com",
                                "domain": "example.com",
                                "seniority": "vp",
                                "breaches": [
                                    {
                                        "breach_name": "AnotherBreach",
                                        "breach_date": "March 2021",
                                        "xposed_data": ["Email", "Phone"],
                                    }
                                ],
                            },
                        ],
                        "counts": {"c_suite": 1, "vp": 1, "total": 2},
                    }
                }
            },
        },
        401: {"description": "Unauthorized - Invalid token or email"},
        404: {"description": "Not Found - Domain not verified or no data found"},
    },
    include_in_schema=False,
    operation_id="getDomainSeniority",
)
@custom_rate_limiter("10 per minute")
async def get_domain_seniority(
    request: Request,
    email: EmailStr = Query(..., description="User's email address"),
    token: str = Query(..., description="Authentication token"),
    domain: Optional[str] = Query(
        None,
        description="Specific domain to query (optional, returns all if not provided)",
    ),
    seniority: SeniorityLevel = Query(
        SeniorityLevel.ALL,
        description="Filter by seniority level: c_suite, vp, director, or all (default)",
    ),
):
    """
    Get seniority data for breach-exposed emails in verified domains.

    Returns email seniority information (c_suite, vp, director) for verified domains.
    If no domain is specified, returns data for all verified domains.
    """
    try:
        # Validate email format
        if not validate_email_with_tld(email):
            raise HTTPException(status_code=400, detail="Invalid email format")

        # Validate token format
        if not validate_token(token):
            raise HTTPException(status_code=400, detail="Invalid token format")

        # Verify user access (token + email match)
        is_authenticated = await verify_user_access(email, token)
        if not is_authenticated:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token. Please verify your email first.",
            )

        # Get user's verified domains
        verified_domains = await get_verified_domains_for_user(email)
        if not verified_domains:
            raise HTTPException(
                status_code=404,
                detail="No verified domains found for this user.",
            )

        # If specific domain requested, validate it's verified for this user
        if domain:
            domain_lower = domain.lower()
            if domain_lower not in [d.lower() for d in verified_domains]:
                raise HTTPException(
                    status_code=401,
                    detail="Domain not verified for this user. Please verify domain ownership first.",
                )

            # Get seniority data for single domain
            seniority_data = await get_seniority_data(domain_lower, seniority)

            return DomainSeniorityResponse(
                status="success",
                domain=seniority_data.domain,
                seniority_data=seniority_data.seniority_data,
                counts=seniority_data.counts,
            )

        # Get seniority data for all verified domains
        all_domains_data = {}
        for verified_domain in verified_domains:
            seniority_data = await get_seniority_data(
                verified_domain.lower(), seniority
            )
            all_domains_data[verified_domain] = seniority_data

        return AllDomainsSeniorityResponse(
            status="success",
            domains=all_domains_data,
            total_domains=len(all_domains_data),
        )

    except HTTPException:
        raise
    except Exception as exception_details:
        await send_exception_email(
            api_route="GET /v1/domain-seniority",
            error_message=str(exception_details),
            exception_type=type(exception_details).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={'provided' if email else 'missing'}, token={'provided' if token else 'missing'}, domain={domain or 'all'}, seniority={seniority.value}",
        )
        raise HTTPException(
            status_code=500, detail="An error occurred during processing"
        ) from exception_details
