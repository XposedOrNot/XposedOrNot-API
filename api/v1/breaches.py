"""Breach-related API endpoints."""

# Standard library imports
import hashlib
import json
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse

# Third-party imports
from fastapi import APIRouter, Header, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse, Response
from config.clients import ds_client, redis_client

# Local imports
from config.settings import MAX_EMAIL_LENGTH
from models.responses import (
    BreachAnalyticsAuthResponse,
    BreachAnalyticsResponse,
    BreachDetailResponse,
    BreachListResponse,
    DomainBreachSummaryResponse,
    EmailBreachErrorResponse,
    EmailBreachResponse,
)
from services.analytics import get_summary_and_metrics
from services.breach import get_breaches, get_exposure, get_sensitive_exposure
from services.breach_catalog import get_breach
from services.shield_cache import get_cached_shield, set_cached_shield
from services.send_email import send_exception_email
from utils.custom_limiter import custom_rate_limiter
from utils.helpers import string_to_boolean, validate_domain
from utils.token import validate_dashboard_session
from utils.validation import (
    validate_email_with_tld,
    validate_token,
    validate_url,
    validate_variables,
)

router = APIRouter()


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


def _newest_added_date(breaches: List[Dict]) -> Optional[datetime]:
    """Return the newest addedDate across breach entries, if any."""
    latest = None
    for breach in breaches:
        added = breach.get("addedDate")
        if not added:
            continue
        try:
            value = datetime.fromisoformat(added)
        except (TypeError, ValueError):
            continue
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        if latest is None or value > latest:
            latest = value
    return latest


def _not_modified(if_modified_since: Optional[str], latest: Optional[datetime]) -> bool:
    """True when the client's If-Modified-Since covers the newest breach."""
    if not if_modified_since or latest is None:
        return False
    try:
        since = parsedate_to_datetime(if_modified_since)
    except (TypeError, ValueError):
        return False
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    return latest.replace(microsecond=0) <= since


@router.get("/breaches", response_model=BreachListResponse)
@custom_rate_limiter("2 per second;50 per hour;100 per day")
async def get_xposed_breaches(
    request: Request,
    response: Response,
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
            latest = _newest_added_date(cached_result.get("exposedBreaches") or [])
            if _not_modified(if_modified_since, latest):
                return Response(
                    status_code=304,
                    headers={"Last-Modified": format_datetime(latest, usegmt=True)},
                )
            if latest is not None:
                response.headers["Last-Modified"] = format_datetime(latest, usegmt=True)
            return BreachListResponse(**cached_result)

        # Cache miss - query Datastore
        client = ds_client
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

            # Format added date (timestamp)
            added_date = entity.get("timestamp")
            if added_date:
                added_date = added_date.replace(microsecond=0).isoformat()

            breach_detail = BreachDetailResponse(
                breachID=entity.key.name or str(entity.key.id),
                breachedDate=breach_date,
                addedDate=added_date,
                domain=entity.get("domain", ""),
                industry=entity.get("industry", ""),
                logo=entity.get("logo", ""),
                passwordRisk=entity.get("password_risk", ""),
                searchable=searchable,
                sensitive=sensitive,
                verified=verified,
                breachType=entity.get("spam_collection", ""),
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

        latest = _newest_added_date(response_data["exposedBreaches"])
        if _not_modified(if_modified_since, latest):
            return Response(
                status_code=304,
                headers={"Last-Modified": format_datetime(latest, usegmt=True)},
            )
        if latest is not None:
            response.headers["Last-Modified"] = format_datetime(latest, usegmt=True)

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
        raise HTTPException(
            status_code=404, detail="An error occurred during processing"
        ) from e


def build_breach_analytics_response(
    data: Dict, token: Optional[str], shield_on: bool
) -> Union[BreachAnalyticsAuthResponse, BreachAnalyticsResponse]:
    """Build the breach-analytics response, adding shield status for valid sessions."""
    if token:
        return BreachAnalyticsAuthResponse(**data, ShieldOn=shield_on)
    return BreachAnalyticsResponse(**data)


@router.get(
    "/breach-analytics",
    response_model=Union[BreachAnalyticsAuthResponse, BreachAnalyticsResponse],
)
@custom_rate_limiter("2 per second;25 per hour;100 per day")
async def search_data_breaches(
    request: Request, email: Optional[str] = None, token: Optional[str] = None
) -> Union[BreachAnalyticsAuthResponse, BreachAnalyticsResponse]:
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
        datastore_client = ds_client

        # Always check shieldOn first (privacy - can't cache this)
        if token:
            alert_key = datastore_client.key("xon_alert", email)
            alert_record = datastore_client.get(alert_key)
        else:
            shield_on = get_cached_shield(email)
            if shield_on is None:
                alert_key = datastore_client.key("xon_alert", email)
                alert_record = datastore_client.get(alert_key)
                shield_on = bool(alert_record and alert_record.get("shieldOn", False))
                set_cached_shield(email, shield_on)
            if shield_on:
                raise HTTPException(status_code=404, detail="Not found")

        # Validate token if provided
        if token:
            if not validate_token(token):
                raise HTTPException(status_code=403, detail="Invalid token")
            token_valid = bool(alert_record and alert_record.get("token") == token)
            if not token_valid:
                token_valid = validate_dashboard_session(datastore_client, email, token)
            if not token_valid:
                raise HTTPException(status_code=403, detail="Invalid token")

        shield_on_status = bool(
            token and alert_record and alert_record.get("shieldOn", False)
        )

        # Check cache (after shieldOn/token validation)
        has_token = "with_token" if token else "no_token"
        cache_key = f"breach-analytics:{hash_email(email)}:{has_token}"
        cached_result = get_cached_breaches(cache_key)
        if cached_result:
            return build_breach_analytics_response(
                cached_result, token, shield_on_status
            )

        breach_data = await get_exposure(email)
        sensitive_data = await get_sensitive_exposure(email) if token else None

        if not breach_data and not sensitive_data:
            return build_breach_analytics_response(
                {
                    "BreachesSummary": {"domain": "", "site": "", "tmpstmp": ""},
                    "PastesSummary": {"cnt": 0, "domain": "", "tmpstmp": ""},
                    "ExposedBreaches": None,
                    "ExposedPastes": None,
                    "BreachMetrics": None,
                    "PasteMetrics": None,
                },
                token,
                shield_on_status,
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
            response_data = {
                "ExposedBreaches": exposed_breaches,
                "BreachesSummary": breach_summary
                or {"domain": "", "site": "", "tmpstmp": ""},
                "BreachMetrics": breach_metrics,
                "PastesSummary": paste_summary
                or {"cnt": 0, "domain": "", "tmpstmp": ""},
                "ExposedPastes": exposed_pastes,
                "PasteMetrics": paste_metrics,
            }
            cache_breaches(cache_key, response_data)
            return build_breach_analytics_response(
                response_data, token, shield_on_status
            )

        empty_response = {
            "BreachesSummary": {"domain": "", "site": "", "tmpstmp": ""},
            "PastesSummary": {"cnt": 0, "domain": "", "tmpstmp": ""},
            "ExposedBreaches": None,
            "ExposedPastes": None,
            "BreachMetrics": None,
            "PasteMetrics": None,
        }
        return build_breach_analytics_response(empty_response, token, shield_on_status)

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

        if not email or not validate_email_with_tld(email) or not validate_url(request):
            return EmailBreachErrorResponse(Error="Not found")

        email = email.lower()

        # Always check shieldOn first (privacy - can't cache this)
        data_store = ds_client
        xon_record = None
        xon_fetched = False
        shield_on = get_cached_shield(email)
        if shield_on is None:
            alert_key = data_store.key("xon_alert", email)
            xon_key = data_store.key("xon", email)
            alert_record = None
            for entity in data_store.get_multi([alert_key, xon_key]):
                if entity.key.kind == "xon_alert":
                    alert_record = entity
                elif entity.key.kind == "xon":
                    xon_record = entity
            xon_fetched = True
            shield_on = bool(alert_record and alert_record.get("shieldOn", False))
            set_cached_shield(email, shield_on)

        if shield_on:
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

        if xon_fetched:
            breach_data = dict(xon_record) if xon_record is not None else {}
        else:
            breach_data = await get_exposure(email)

        if not breach_data:
            return EmailBreachErrorResponse(Error="Not found")

        xon_record = breach_data

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
        ds_xon = ds_client

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
        ds_paste = ds_client
        paste_rec = ds_paste.query(kind="xon_paste")
        paste_rec.add_filter("domain", "=", domain)
        query_paste = paste_rec.fetch(limit=50)

        pastes_count = sum(1 for _ in query_paste)

        # Get latest breach date
        breach_last_seen = None
        if unique_sites:
            breach_dates = []
            for site in unique_sites:
                breach_entity = get_breach(site)
                if breach_entity is not None:
                    breach_date = breach_entity.get("breached_date")
                    if breach_date is not None:
                        breach_dates.append(breach_date)

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
