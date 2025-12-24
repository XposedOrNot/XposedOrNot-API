"""Breach-related API endpoints."""

# Standard library imports
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, Optional, Union
from urllib.parse import urlparse

# Third-party imports
from fastapi import APIRouter, Header, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse, Response
from google.cloud import datastore
from redis import Redis

# Local imports
from config.settings import MAX_EMAIL_LENGTH, REDIS_DB, REDIS_HOST, REDIS_PORT
from models.responses import (
    BreachAnalyticsResponse,
    BreachAnalyticsV2Response,
    BreachDetailResponse,
    BreachListResponse,
    DomainBreachSummaryResponse,
    EmailBreachErrorResponse,
    EmailBreachResponse,
    EmptyBreachResponse,
)
from services.analytics import (
    get_ai_summary,
    get_summary_and_metrics,
)
from services.breach import get_breaches, get_exposure, get_sensitive_exposure
from services.send_email import send_exception_email
from utils.custom_limiter import custom_rate_limiter
from utils.helpers import (
    get_client_ip,
    string_to_boolean,
    validate_domain,
    validate_email_with_tld,
    validate_url,
)
from utils.validation import validate_variables

router = APIRouter()

# Redis client for caching
redis_client = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True
)

# Cache TTL: 24 hours
BREACH_CACHE_TTL_HOURS = 24


def get_breach_cache_key(breach_id: Optional[str], domain: Optional[str]) -> str:
    """Generate cache key based on query parameters."""
    if breach_id:
        return f"breaches:id:{breach_id.lower()}"
    elif domain:
        return f"breaches:domain:{domain.lower()}"
    return "breaches:all"


def get_cached_breaches(cache_key: str) -> Optional[Dict]:
    """Retrieve cached breach results from Redis."""
    try:
        cached_data = redis_client.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
    except Exception:
        pass
    return None


def cache_breaches(
    cache_key: str, result: Dict, expiry_hours: int = BREACH_CACHE_TTL_HOURS
) -> None:
    """Cache breach results in Redis."""
    try:
        redis_client.setex(cache_key, timedelta(hours=expiry_hours), json.dumps(result))
    except Exception:
        pass


def hash_email(email: str) -> str:
    """Hash email for privacy-safe cache keys."""
    return hashlib.sha256(email.lower().encode()).hexdigest()[:16]


@router.get("/breaches", response_model=BreachListResponse)
@custom_rate_limiter("2 per second;50 per hour;100 per day")
async def get_xposed_breaches(
    request: Request,
    domain: Optional[str] = None,
    breach_id: Optional[str] = None,
    if_modified_since: Optional[str] = Header(None),
) -> BreachListResponse:
    """
    Fetches and returns the details of data breaches for a specified domain,
    or for all domains if no domain is specified.
    """
    try:
        # Validate inputs first
        if breach_id:
            if not validate_variables([breach_id]):
                raise HTTPException(status_code=400, detail="Invalid Breach ID")
        elif domain:
            # Try to extract domain from URL if a full URL is provided
            if not validate_domain(domain):
                parsed = urlparse(domain)
                extracted = parsed.netloc or parsed.path.strip("/")
                if extracted and validate_domain(extracted):
                    domain = extracted
                else:
                    raise HTTPException(status_code=400, detail="Invalid Domain")

        # Check cache first
        cache_key = get_breach_cache_key(breach_id, domain)
        cached_result = get_cached_breaches(cache_key)
        if cached_result:
            return BreachListResponse(**cached_result)

        # Cache miss - query Datastore
        client = datastore.Client()
        query = client.query(kind="xon_breaches")

        if breach_id:
            query.key_filter(client.key("xon_breaches", breach_id), "=")
        elif domain:
            query.add_filter("domain", "=", domain)
        else:
            query.order = ["-timestamp"]

        entities = list(query.fetch())
        if not entities:
            return BreachListResponse(
                status="Not Found",
                message="No breaches found for the provided criteria",
            )

        breach_details = []
        for entity in entities:

            exposed_data = (
                entity.get("xposed_data", "").split(";")
                if entity.get("xposed_data")
                else []
            )

            # Convert string boolean values to actual booleans
            searchable = string_to_boolean(entity.get("searchable", "false"))
            sensitive = string_to_boolean(entity.get("sensitive", "false"))
            verified = string_to_boolean(entity.get("verified", "false"))

            # Format breach date
            breach_date = entity.get("breached_date")
            if breach_date:
                breach_date = breach_date.replace(microsecond=0).isoformat()

            breach_detail = BreachDetailResponse(
                breachID=entity.key.name or str(entity.key.id),
                breachedDate=breach_date,
                domain=entity.get("domain", ""),
                industry=entity.get("industry", ""),
                logo=entity.get("logo", ""),
                passwordRisk=entity.get("password_risk", ""),
                searchable=searchable,
                sensitive=sensitive,
                verified=verified,
                exposedData=exposed_data,
                exposedRecords=entity.get("xposed_records", 0),
                exposureDescription=entity.get("xposure_desc", ""),
                referenceURL=entity.get("references", ""),
            )
            breach_details.append(breach_detail)

        if not breach_details and domain:
            return BreachListResponse(
                status="notFound", message=f"No breaches found for domain {domain}"
            )

        # Build response and cache it
        response_data = {
            "status": "success",
            "exposedBreaches": [breach.model_dump() for breach in breach_details],
        }
        cache_breaches(cache_key, response_data)

        return BreachListResponse(status="success", exposedBreaches=breach_details)

    except HTTPException:
        raise
    except Exception as e:
        await send_exception_email(
            api_route="GET /v1/breaches",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=(
                f"domain={domain}, breach_id={breach_id}, "
                f"if_modified_since={'provided' if if_modified_since else 'not_provided'}"
            ),
        )
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.get("/v2/breach-analytics", response_model=BreachAnalyticsV2Response)
@custom_rate_limiter("2 per second;25 per hour;100 per day")
async def search_data_breaches_v2(
    request: Request, email: Optional[str] = None, token: Optional[str] = None
) -> BreachAnalyticsV2Response:
    """Returns AI summary and details of data breaches for a given email."""
    if (
        not email
        or not validate_email_with_tld(email)
        or not validate_url(request)
        or len(email) > MAX_EMAIL_LENGTH
    ):
        raise HTTPException(status_code=404, detail="Not found")

    try:
        email = email.lower()
        breach_data = await get_exposure(email)
        sensitive_data = await get_sensitive_exposure(email) if token else None

        if not breach_data and not sensitive_data:
            return EmptyBreachResponse(BreachesSummary={}, PastesSummary={})

        # Handle sensitive data if available
        if breach_data and sensitive_data and token:
            if isinstance(breach_data, dict) and isinstance(sensitive_data, dict):
                existing_sites = (
                    set(breach_data["site"].split(";"))
                    if "site" in breach_data and breach_data["site"]
                    else set()
                )
                sensitive_sites = (
                    set(sensitive_data["site"].split(";"))
                    if "site" in sensitive_data and sensitive_data["site"]
                    else set()
                )
                unique_sites = existing_sites.union(sensitive_sites)
                breach_data["site"] = ";".join(unique_sites)

        # Get summary and metrics
        (
            breach_summary,
            paste_summary,
            exposed_breaches,
            exposed_pastes,
            breach_metrics,
            paste_metrics,
        ) = await get_summary_and_metrics(breach_data, sensitive_data)

        if not (breach_summary or paste_summary):
            return EmptyBreachResponse(BreachesSummary={}, PastesSummary={})

        breach_data = {
            "ExposedBreaches": exposed_breaches,
            "BreachesSummary": breach_summary or {},
            "BreachMetrics": breach_metrics,
            "PastesSummary": paste_summary or {},
            "ExposedPastes": exposed_pastes,
            "PasteMetrics": paste_metrics,
        }

        ai_summary = get_ai_summary(breach_data)
        return BreachAnalyticsV2Response(AI_Summary=ai_summary)

    except HTTPException:
        raise
    except Exception as exc:
        await send_exception_email(
            api_route="GET /v1/v2/breach-analytics",
            error_message=str(exc),
            exception_type=type(exc).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={email}, token={'provided' if token else 'not_provided'}",
        )
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/breach-analytics", response_model=BreachAnalyticsResponse)
@custom_rate_limiter("2 per second;25 per hour;100 per day")
async def search_data_breaches(
    request: Request, email: Optional[str] = None, token: Optional[str] = None
) -> BreachAnalyticsResponse:
    """Returns summary and details of data breaches for a given email."""
    if (
        not email
        or not validate_email_with_tld(email)
        or not validate_url(request)
        or len(email) > MAX_EMAIL_LENGTH
    ):
        raise HTTPException(status_code=404, detail="Not found")

    try:
        email = email.lower()
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", email)
        alert_record = datastore_client.get(alert_key)

        if alert_record and alert_record.get("shieldOn", False):
            raise HTTPException(status_code=404, detail="Not found")

        # Validate token if provided
        if token:
            token_valid = bool(alert_record and alert_record.get("token") == token)
            if not token_valid:
                raise HTTPException(status_code=403, detail="Invalid token")

        breach_data = await get_exposure(email)
        sensitive_data = await get_sensitive_exposure(email) if token else None

        if not breach_data and not sensitive_data:
            return BreachAnalyticsResponse(
                BreachesSummary={"domain": "", "site": "", "tmpstmp": ""},
                PastesSummary={"cnt": 0, "domain": "", "tmpstmp": ""},
                ExposedBreaches=None,
                ExposedPastes=None,
                BreachMetrics=None,
                PasteMetrics=None,
            )

        if breach_data and sensitive_data and token:
            if isinstance(breach_data, dict) and isinstance(sensitive_data, dict):
                existing_sites = (
                    set(breach_data["site"].split(";"))
                    if "site" in breach_data and breach_data["site"]
                    else set()
                )
                sensitive_sites = (
                    set(sensitive_data["site"].split(";"))
                    if "site" in sensitive_data and sensitive_data["site"]
                    else set()
                )
                unique_sites = existing_sites.union(sensitive_sites)
                breach_data["site"] = ";".join(unique_sites)

        summary_result = await get_summary_and_metrics(breach_data, sensitive_data)
        (
            breach_summary,
            paste_summary,
            exposed_breaches,
            exposed_pastes,
            breach_metrics,
            paste_metrics,
        ) = summary_result

        if breach_summary or paste_summary:
            return BreachAnalyticsResponse(
                ExposedBreaches=exposed_breaches,
                BreachesSummary=breach_summary
                or {"domain": "", "site": "", "tmpstmp": ""},
                BreachMetrics=breach_metrics,
                PastesSummary=paste_summary or {"cnt": 0, "domain": "", "tmpstmp": ""},
                ExposedPastes=exposed_pastes,
                PasteMetrics=paste_metrics,
            )

        return BreachAnalyticsResponse(
            BreachesSummary={"domain": "", "site": "", "tmpstmp": ""},
            PastesSummary={"cnt": 0, "domain": "", "tmpstmp": ""},
            ExposedBreaches=None,
            ExposedPastes=None,
            BreachMetrics=None,
            PasteMetrics=None,
        )

    except HTTPException:
        raise
    except Exception as exc:
        await send_exception_email(
            api_route="GET /v1/breach-analytics",
            error_message=str(exc),
            exception_type=type(exc).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={email}, token={'provided' if token else 'not_provided'}",
        )
        raise HTTPException(status_code=404, detail="Not found") from exc


@router.get(
    "/check-email/{email}",
    response_model=Union[EmailBreachResponse, EmailBreachErrorResponse],
    responses={
        200: {
            "model": EmailBreachResponse,
            "description": "Successfully retrieved breach information",
        },
        404: {
            "model": EmailBreachErrorResponse,
            "description": "Email not found or invalid format",
        },
    },
    summary="Check Email for Breaches",
    description="""
    Check if an email address has been exposed in any known data breaches.
    
    This endpoint provides a comprehensive check of our breach database to identify if an email
    address has been compromised in any known data breaches. The response includes:
    - Number of breaches found
    - Breach dates and severity
    - Types of exposed data
    - Detailed breach information (optional)
    
    Rate Limit: 2 requests/second, 25/hour, 100/day
    """,
    tags=["breaches"],
    operation_id="check_email_breaches",
)
@custom_rate_limiter(
    "2 per second;25 per hour;100 per day",
    message=(
        "For faster checks, please consider upgrading to our paid plans. "
        "Visit https://plus.xposedornot.com/products/api for more details."
    ),
)
async def search_email(
    request: Request,
    email: str = Path(
        ...,
        description="Email address to check for breaches",
        example="user@example.com",
        max_length=MAX_EMAIL_LENGTH,
    ),
    details: bool = Query(
        False,
        description=(
            "Include detailed breach information in the response "
            "(case-insensitive: true/false, yes/no, 1/0)"
        ),
        example=False,
    ),
) -> Union[EmailBreachResponse, EmailBreachErrorResponse]:
    """Check if an email address appears in any known data breaches."""
    try:

        client_ip = get_client_ip(request)

        if not email or not validate_email_with_tld(email) or not validate_url(request):
            return EmailBreachErrorResponse(Error="Not found")

        email = email.lower()

        # Always check shieldOn first (privacy - can't cache this)
        data_store = datastore.Client()
        alert_key = data_store.key("xon_alert", email)
        alert_record = data_store.get(alert_key)

        if alert_record and alert_record.get("shieldOn", False):
            return JSONResponse(
                status_code=404,
                content={
                    "Error": "No breaches found",
                    "email": email,
                    "status": "failed",
                },
            )

        # Check cache (after shieldOn check passes)
        cache_key = f"check-email:{hash_email(email)}:{details}"
        cached_result = get_cached_breaches(cache_key)
        if cached_result:
            # Replace hashed email with actual email in response
            cached_result["email"] = email
            return JSONResponse(status_code=200, content=cached_result)

        breach_data = await get_exposure(email)

        if not breach_data:
            return EmailBreachErrorResponse(Error="Not found")

        xon_key = data_store.key("xon", email)
        xon_record = data_store.get(xon_key)

        if xon_record and "site" in xon_record:
            # Use set to filter out duplicate breaches
            domains = xon_record["site"].split(";")
            unique_domains = set(domain.strip() for domain in domains if domain.strip())
            filtered_domains = list(unique_domains)

            if filtered_domains:
                response_content = {
                    "breaches": [filtered_domains],
                    "email": email,
                    "status": "success",
                }

                if details:
                    # Pass deduplicated breaches to get_breaches
                    deduplicated_sites = ";".join(unique_domains)
                    raw_breaches = get_breaches(deduplicated_sites)
                    formatted_breaches = []

                    for breach in raw_breaches["breaches_details"]:
                        formatted_breach = {
                            "name": breach["breach"],
                            "records_exposed": breach["xposed_records"],
                            "description": breach["details"],
                            "breach_date": breach.get("breached_date", ""),
                            "company": {
                                "name": breach["domain"] or "Unknown",
                                "industry": breach["industry"] or "Unknown",
                                "logo_url": breach["logo"] or "",
                            },
                            "security": {
                                "password_risk": breach["password_risk"],
                                "is_searchable": breach["searchable"] == "Yes",
                                "is_verified": breach["verified"] == "Yes",
                            },
                            "exposed_data": (
                                breach["xposed_data"].split(";")
                                if breach["xposed_data"]
                                else []
                            ),
                        }
                        formatted_breaches.append(formatted_breach)

                    response_content["breach_details"] = formatted_breaches

                # Cache the response (use placeholder for email to avoid storing PII)
                cache_content = response_content.copy()
                cache_content["email"] = "__cached__"
                cache_breaches(cache_key, cache_content)

                return JSONResponse(status_code=200, content=response_content)

        return JSONResponse(
            status_code=404,
            content={"Error": "No breaches found", "email": email, "status": "failed"},
        )

    except Exception as exc:
        await send_exception_email(
            api_route=f"GET /v1/check-email/{email}",
            error_message=str(exc),
            exception_type=type(exc).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={email}, details={details}",
        )

        return JSONResponse(
            status_code=404,
            content={"Error": "Not found", "email": email, "status": "failed"},
        )


@router.get("/domain-breach-summary", response_model=DomainBreachSummaryResponse)
@custom_rate_limiter("2 per second;25 per hour;50 per day")
async def get_domain_breach_summary(
    request: Request,
    d: Optional[str] = Query(None, description="Domain to search for breaches"),
) -> DomainBreachSummaryResponse:
    """
    Returns exposed data at domain level including breach counts, email counts, and last seen dates.

    Args:
        request: FastAPI request object
        d: Domain to search for breaches

    Returns:
        DomainBreachSummaryResponse containing breach summary for the domain
    """
    if not d or not validate_domain(d) or not validate_url(request):
        raise HTTPException(status_code=404, detail="Not found")

    try:
        domain = d.lower().strip()

        # Check cache first
        cache_key = f"domain-breach-summary:{domain}"
        cached_result = get_cached_breaches(cache_key)
        if cached_result:
            return DomainBreachSummaryResponse(**cached_result)

        # Cache miss - query Datastore
        ds_xon = datastore.Client()

        # Query xon records for domain
        xon_rec = ds_xon.query(kind="xon")
        xon_rec.add_filter("domain", "=", domain)
        query_xon = xon_rec.fetch(limit=10000)

        unique_emails = set()
        unique_sites = set()
        total_records = 0

        # Process xon records
        for entity_xon in query_xon:
            email = entity_xon.key.name
            if len(unique_emails) <= 10000:
                unique_emails.add(email)
            if "site" in entity_xon:
                sites = entity_xon["site"].split(";")
                unique_sites.update(sites)
                total_records += len(sites)

        unique_sites.discard("")

        breach_count = len(unique_sites)
        emails_count = len(unique_emails)

        # Query paste records
        ds_paste = datastore.Client()
        paste_rec = ds_paste.query(kind="xon_paste")
        paste_rec.add_filter("domain", "=", domain)
        query_paste = paste_rec.fetch(limit=50)

        pastes_count = sum(1 for _ in query_paste)

        # Get latest breach date
        breach_last_seen = None
        if unique_sites:
            breach_dates = []
            ds_breaches = datastore.Client()
            for site in unique_sites:
                breach_rec = ds_breaches.query(kind="xon_breaches")
                breach_rec.add_filter(
                    "__key__", "=", ds_breaches.key("xon_breaches", site)
                )
                breach_rec.order = ["-breached_date"]
                query_breaches = list(breach_rec.fetch(limit=1))
                if query_breaches:
                    breach_dates.append(query_breaches[0]["breached_date"])

                if breach_dates:
                    breach_last_seen = max(breach_dates).strftime("%d-%b-%Y")

        breaches_dict = {
            "breaches_details": [
                {
                    "domain": domain,
                    "breach_pastes": pastes_count,
                    "breach_emails": emails_count,
                    "breach_total": total_records,
                    "breach_count": breach_count,
                    "breach_last_seen": breach_last_seen,
                }
            ]
        }

        # Cache the response
        response_data = {"sendDomains": breaches_dict, "SearchStatus": "Success"}
        cache_breaches(cache_key, response_data)

        return DomainBreachSummaryResponse(
            sendDomains=breaches_dict, SearchStatus="Success"
        )

    except Exception as exc:
        await send_exception_email(
            api_route="GET /v1/domain-breach-summary",
            error_message=str(exc),
            exception_type=type(exc).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"domain={d}",
        )
        raise HTTPException(status_code=404, detail="Not found") from exc


def _prepare_for_logging(data):
    """Helper function to prepare data for logging by converting non-serializable objects."""
    if not data:
        return data

    if isinstance(data, dict):
        return {k: _prepare_for_logging(v) for k, v in data.items()}

    if isinstance(data, list):
        return [_prepare_for_logging(item) for item in data]

    if hasattr(data, "isoformat"):  # Handle datetime objects
        return data.isoformat()

    # Handle other types
    if not isinstance(data, (str, int, float, bool, type(None))):
        return str(data)

    return data


def _format_log_data(data):
    """Helper function to format data for logging in a compact way."""
    if not data:
        return data
    try:

        prepared_data = _prepare_for_logging(data)

        return json.dumps(prepared_data, separators=(",", ":"))

    except (ValueError, TypeError, KeyError) as e:
        return f"Error formatting data: {str(e)}"
