"""Analytics-related API endpoints."""

# Standard library imports
import datetime
import hashlib
import html
import json
import logging
from collections import defaultdict
from datetime import timedelta
from typing import Any, Dict, Optional, Union

# Third-party imports
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from google.api_core import exceptions as google_exceptions
from google.cloud import datastore
from redis import Redis

from config.settings import REDIS_DB, REDIS_HOST, REDIS_PORT

# Local imports
from models.responses import (
    AlertDetail,
    AlertManagement,
    AlertStatusUpdateErrorResponse,
    AlertStatusUpdateRequest,
    AlertStatusUpdateResponse,
    BreachDetails,
    BreachHierarchyResponse,
    DetailedBreachInfo,
    DetailedMetricsResponse,
    DomainAlertErrorResponse,
    DomainAlertResponse,
    DomainBreachesErrorResponse,
    DomainBreachesResponse,
    PulseNewsResponse,
    ShieldActivationErrorResponse,
    ShieldActivationResponse,
)
from services.analytics import get_detailed_metrics, get_pulse_news
from services.send_email import (
    send_dashboard_email_confirmation,
    send_exception_email,
    send_shield_email,
)
from utils.custom_limiter import custom_rate_limiter
from utils.helpers import fetch_location_by_ip, get_preferred_ip_address
from utils.request import get_client_ip, get_user_agent_info
from utils.token import confirm_token, generate_confirmation_token
from utils.validation import (
    validate_email_deliverable,
    validate_email_with_tld,
    validate_token,
    validate_url,
    validate_variables,
)
from utils.safe_encoding import (
    build_safe_url,
    escape_html_attr,
    escape_url_fragment,
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger(__name__)

# Redis client for caching
redis_client = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True
)

# Cache TTL: 24 hours
ANALYTICS_CACHE_TTL_HOURS = 24


def get_cached_analytics(cache_key: str) -> Optional[Dict]:
    """Retrieve cached analytics from Redis."""
    try:
        cached_data = redis_client.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
    except Exception:
        pass
    return None


def cache_analytics(
    cache_key: str, result: Dict, expiry_hours: int = ANALYTICS_CACHE_TTL_HOURS
) -> None:
    """Cache analytics in Redis."""
    try:
        redis_client.setex(cache_key, timedelta(hours=expiry_hours), json.dumps(result))
    except Exception:
        pass


def hash_email(email: str) -> str:
    """Hash email for privacy-safe cache keys."""
    return hashlib.sha256(email.lower().encode()).hexdigest()[:16]


class ShieldOnException(Exception):
    """Exception raised when shield is on."""

    pass


@router.get("/analytics/metrics", response_model=DetailedMetricsResponse)
@custom_rate_limiter("5 per minute;50 per hour;100 per day")
async def get_metrics(request: Request) -> DetailedMetricsResponse:
    """Returns detailed metrics about breaches."""
    try:
        # Check cache first
        cache_key = "analytics:metrics"
        cached_result = get_cached_analytics(cache_key)
        if cached_result:
            return DetailedMetricsResponse(**cached_result)

        # Cache miss - fetch from service
        metrics = await get_detailed_metrics()

        # Process top breaches (convert Entity objects to dicts)
        top_breaches = []
        for breach in metrics["top_breaches"]:
            top_breaches.append(
                {
                    "breachid": breach.key.id_or_name,
                    "logo": breach.get("logo"),
                    "description": breach.get("xposure_desc"),
                    "count": breach.get("xposed_records"),
                }
            )

        # Process recent breaches (convert Entity objects to dicts)
        recent_breaches = []
        for breach in metrics["recent_breaches"]:
            timestamp = breach.get("timestamp")
            if hasattr(timestamp, "strftime"):
                formatted_timestamp = timestamp.strftime("%a, %d %b %Y %H:%M:%S GMT")
            else:
                formatted_timestamp = datetime.datetime.utcnow().strftime(
                    "%a, %d %b %Y %H:%M:%S GMT"
                )
            recent_breaches.append(
                {
                    "breachid": breach.key.id_or_name,
                    "timestamp": formatted_timestamp,
                    "logo": breach.get("logo"),
                    "description": breach.get("xposure_desc"),
                    "count": breach.get("xposed_records"),
                }
            )

        # Transform to response format before caching
        response_data = {
            "Breaches_Count": metrics["breaches_count"],
            "Breaches_Records": metrics["breaches_total_records"],
            "Pastes_Count": str(metrics["pastes_count"]),
            "Pastes_Records": metrics["pastes_total_records"],
            "Yearly_Breaches_Count": metrics["yearly_count"],
            "Industry_Breaches_Count": metrics["industry_breaches_count"],
            "Top_Breaches": top_breaches,
            "Recent_Breaches": recent_breaches,
        }
        cache_analytics(cache_key, response_data)

        return DetailedMetricsResponse(**response_data)
    except Exception as e:
        await send_exception_email(
            api_route="GET /v1/analytics/metrics",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params="None",
        )
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/analytics/pulse", response_model=PulseNewsResponse)
@custom_rate_limiter("5 per minute;50 per hour;100 per day")
async def get_news_feed(request: Request) -> PulseNewsResponse:
    """Returns news feed for data breaches."""
    try:
        # Check cache first
        cache_key = "analytics:pulse"
        cached_result = get_cached_analytics(cache_key)
        if cached_result:
            return PulseNewsResponse(**cached_result)

        # Cache miss - fetch from service
        news_items = await get_pulse_news()
        # Handle both dict and Pydantic model items
        data_items = [
            item.model_dump() if hasattr(item, "model_dump") else item
            for item in news_items
        ]
        response_data = {
            "status": "success",
            "data": data_items,
        }
        cache_analytics(cache_key, response_data)

        return PulseNewsResponse(status="success", data=news_items)
    except Exception as e:
        await send_exception_email(
            api_route="GET /v1/analytics/pulse",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params="None",
        )
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get(
    "/domain-alert/{user_email}",
    response_model=DomainAlertResponse,
    responses={
        200: {"model": DomainAlertResponse},
        404: {"model": DomainAlertErrorResponse},
    },
)
@custom_rate_limiter("2 per second;25 per hour;50 per day")
async def domain_alert(
    request: Request, user_email: str
) -> Union[DomainAlertResponse, DomainAlertErrorResponse]:
    """
    Initiate domain breaches dashboard access and send confirmation email.

    Args:
        request: FastAPI request object
        user_email: Email address to send alert to

    Returns:
        DomainAlertResponse: Success response
        DomainAlertErrorResponse: Error response

    Raises:
        HTTPException: If email sending fails
    """
    try:
        # HTML unescape and normalize email
        user_email = html.unescape(user_email).lower().strip()

        # Validate inputs
        if not user_email:
            return DomainAlertErrorResponse(Error="Invalid email", email=user_email)

        if not validate_url(request):
            return DomainAlertErrorResponse(Error="Invalid request", email=user_email)

        # Validate email format, TLD, and domain is live
        is_deliverable, validated_email = validate_email_deliverable(user_email)
        if not is_deliverable:
            return JSONResponse(
                status_code=400,
                content={"Error": "Unable to deliver email to this address"},
            )
        user_email = validated_email

        datastore_client = datastore.Client()

        # Check if the user exists in xon_domains
        query = datastore_client.query(kind="xon_domains")
        query.add_filter("email", "=", user_email)
        domain_task = list(query.fetch())

        if not domain_task:
            # Still return success to avoid email enumeration
            return DomainAlertResponse()

        # Generate verification token and URL
        verification_token = await generate_confirmation_token(user_email)
        confirmation_url = f"{request.base_url}v1/domain-verify/{verification_token}"

        # Store session data
        try:
            alert_task_data = datastore.Entity(
                datastore_client.key("xon_domains_session", user_email)
            )
            alert_task_data.update(
                {
                    "magic_timestamp": datetime.datetime.now(),
                    "domain_magic": verification_token,
                }
            )
            datastore_client.put(alert_task_data)
        except Exception as e:
            raise

        # Get client information
        client_ip = get_client_ip(request)
        preferred_ip = get_preferred_ip_address(client_ip)
        location = fetch_location_by_ip(preferred_ip) if preferred_ip else "Unknown"
        browser_type, client_platform = get_user_agent_info(request)

        # Send confirmation email
        try:
            email_response = await send_dashboard_email_confirmation(
                user_email,
                confirmation_url,
                f"{client_ip} ({location})",
                browser_type,
                client_platform,
            )
        except Exception as e:
            raise

        return DomainAlertResponse()

    except (ValueError, HTTPException, google_exceptions.GoogleAPIError) as e:
        await send_exception_email(
            api_route=f"GET /v1/domain-alert/{user_email}",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={user_email}",
        )
        return DomainAlertErrorResponse(
            Error=f"Internal error: {str(e)}", email=user_email
        )


@router.get(
    "/domain-verify/{verification_token}",
    response_class=HTMLResponse,
    responses={
        200: {"content": {"text/html": {}}},
        404: {"content": {"text/html": {}}},
    },
)
@custom_rate_limiter("2 per second;25 per hour;50 per day")
async def domain_verify(request: Request, verification_token: str) -> HTMLResponse:
    """
    Verify domain alerts using token and return dashboard access.
    """
    try:
        # Validate inputs
        if (
            not verification_token
            or not validate_variables([verification_token])
            or not validate_url(request)
        ):
            return HTMLResponse(
                content=templates.TemplateResponse(
                    "domain_dashboard_error.html", {"request": request}
                ).body.decode(),
                status_code=404,
            )

        user_email = await confirm_token(verification_token)
        # Re-validate email from token for defense-in-depth
        if not user_email or not validate_email_with_tld(user_email):
            return HTMLResponse(
                content=templates.TemplateResponse(
                    "domain_dashboard_error.html", {"request": request}
                ).body.decode(),
                status_code=404,
            )

        # Create session data
        try:
            client = datastore.Client()
            alert_task_data = datastore.Entity(
                client.key("xon_domains_session", user_email)
            )
            alert_task_data.update(
                {
                    "magic_timestamp": datetime.datetime.now(),
                    "domain_magic": verification_token,
                }
            )
            client.put(alert_task_data)
        except Exception as e:
            raise

        # Generate dashboard link with properly encoded parameters
        dashboard_link = build_safe_url(
            "https://xposedornot.com/breach-dashboard.html",
            {"email": user_email, "token": verification_token},
        )

        return HTMLResponse(
            content=templates.TemplateResponse(
                "domain_dashboard_success.html",
                {"request": request, "link": dashboard_link},
            ).body.decode(),
            status_code=200,
        )

    except (ValueError, HTTPException, google_exceptions.GoogleAPIError) as e:
        await send_exception_email(
            api_route="GET /v1/domain-verify/{token}",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"token={verification_token}",
        )
        return HTMLResponse(
            content=templates.TemplateResponse(
                "domain_dashboard_error.html", {"request": request}
            ).body.decode(),
            status_code=404,
        )


@router.get(
    "/send_domain_breaches",
    response_model=Union[DomainBreachesResponse, DomainBreachesErrorResponse],
    responses={
        200: {"model": DomainBreachesResponse},
        400: {"model": DomainBreachesErrorResponse},
        404: {"model": DomainBreachesErrorResponse},
    },
)
@custom_rate_limiter("100 per day;50 per hour;2 per second")
async def send_domain_breaches(
    request: Request,
    email: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
    time_filter: Optional[str] = Query("all"),
) -> Union[DomainBreachesResponse, DomainBreachesErrorResponse]:
    """
    Retrieves and sends the data breaches validated by token and email.

    Args:
        request: FastAPI request object
        email: Email address for authentication
        token: Token for authentication
        time_filter: Filter breaches by time period ('all', '12m', '6m')
                    - 'all': No time filtering (default)
                    - '12m': Only breaches added in last 12 months
                    - '6m': Only breaches added in last 6 months
    """
    try:
        # Check for presence of email and token
        if email is None or token is None:
            raise HTTPException(
                status_code=400,
                detail=DomainBreachesErrorResponse(
                    Error="Missing email or token"
                ).dict(),
            )

        # Validate email and token
        if not validate_email_with_tld(email):
            raise HTTPException(
                status_code=400,
                detail=DomainBreachesErrorResponse(Error="Invalid email format").dict(),
            )

        if not validate_token(token):
            raise HTTPException(
                status_code=400,
                detail=DomainBreachesErrorResponse(Error="Invalid token format").dict(),
            )

        if not validate_url(request):
            raise HTTPException(
                status_code=400,
                detail=DomainBreachesErrorResponse(Error="Invalid request URL").dict(),
            )

        # Validate time_filter parameter
        if time_filter not in ["all", "12m", "6m"]:
            raise HTTPException(
                status_code=400,
                detail=DomainBreachesErrorResponse(
                    Error="Invalid time_filter. Must be 'all', '12m', or '6m'"
                ).dict(),
            )

        # Check for matching session in xon_domains_session
        client = datastore.Client()
        alert_key = client.key("xon_domains_session", email)
        alert_task = client.get(alert_key)

        if not alert_task:
            raise HTTPException(
                status_code=401,
                detail=DomainBreachesErrorResponse(Error="No session found").dict(),
            )

        if alert_task.get("domain_magic") != token:
            raise HTTPException(
                status_code=401,
                detail=DomainBreachesErrorResponse(Error="Invalid session").dict(),
            )

        if datetime.datetime.utcnow() - alert_task.get("magic_timestamp").replace(
            tzinfo=None
        ) > datetime.timedelta(hours=12):
            raise HTTPException(
                status_code=401,
                detail=DomainBreachesErrorResponse(Error="Session expired").dict(),
            )

        # Get verified domains
        query = client.query(kind="xon_domains")
        query.add_filter("email", "=", email)
        verified_domains = [entity["domain"] for entity in query.fetch()]

        if not verified_domains:
            return DomainBreachesErrorResponse(Error="No verified domains found")

        # Calculate time threshold for filtering
        time_threshold = None
        if time_filter == "12m":
            time_threshold = datetime.datetime.utcnow().replace(
                tzinfo=datetime.timezone.utc
            ) - datetime.timedelta(days=365)
        elif time_filter == "6m":
            time_threshold = datetime.datetime.utcnow().replace(
                tzinfo=datetime.timezone.utc
            ) - datetime.timedelta(days=183)
        # If time_filter == "all", time_threshold remains None (no filtering)

        current_year = datetime.datetime.utcnow().year
        yearly_summary = {str(year): 0 for year in range(current_year, 2006, -1)}
        yearly_breach_summary = {
            str(year): defaultdict(int) for year in range(current_year, 2006, -1)
        }
        domain_summary = defaultdict(int)
        breach_summary = defaultdict(int)
        breach_details = []
        detailed_breach_info = {}
        all_breaches_logo = {}
        seniority_summary = {"manager": 0, "c_suite": 0, "director": 0, "vp": 0}
        time_filtered_breaches = set()  # Track breaches that pass time filter

        # Process each verified domain
        for domain in verified_domains:
            domain_summary[domain] = 0
            query = client.query(kind="xon_domains_summary")
            query.add_filter("domain", "=", domain)

            for entity in query.fetch():
                if entity["breach"] == "No_Breaches":
                    continue

                breach_key = client.key("xon_breaches", entity["breach"])
                breach = client.get(breach_key)

                if breach:
                    # Apply time filtering if specified
                    if time_threshold is not None:
                        breach_timestamp = breach.get("timestamp")
                        if breach_timestamp is None:
                            continue  # Skip breaches without timestamp

                        # Ensure both timestamps have timezone info for comparison
                        if breach_timestamp.tzinfo is None:
                            breach_timestamp = breach_timestamp.replace(
                                tzinfo=datetime.timezone.utc
                            )

                        if breach_timestamp < time_threshold:
                            continue  # Skip this breach if it's outside the time filter

                    # Track this breach as passing the time filter (for filtering breach_details and seniority)
                    time_filtered_breaches.add(entity["breach"])

                    default_breach_info = {
                        "breached_date": None,
                        "logo": "",
                        "password_risk": "",
                        "searchable": "",
                        "xposed_data": "",
                        "xposed_records": "",
                        "xposure_desc": "",
                    }

                    for key, value in default_breach_info.items():
                        if key not in breach or breach[key] is None:
                            breach[key] = value

                    # Process breach data
                    all_breaches_logo[entity["breach"]] = breach["logo"]
                    breach_year = (
                        breach["breached_date"].strftime("%Y")
                        if breach["breached_date"]
                        else "Unknown Year"
                    )

                    yearly_summary[breach_year] += entity["email_count"]
                    yearly_breach_summary[breach_year][entity["breach"]] += entity[
                        "email_count"
                    ]
                    breach_summary[entity["breach"]] += entity["email_count"]
                    domain_summary[domain] += entity["email_count"]

                    # Format breached_date to RFC 822 format
                    formatted_date = None
                    if breach["breached_date"]:
                        formatted_date = breach["breached_date"].strftime(
                            "%a, %d %b %Y %H:%M:%S GMT"
                        )

                    # Keep xposed_data as semicolon-separated string
                    xposed_data = breach["xposed_data"]
                    if isinstance(xposed_data, list):
                        xposed_data = ";".join(xposed_data)

                    # Convert searchable to "Yes"/"No" string format
                    searchable = breach["searchable"]
                    if isinstance(searchable, bool):
                        searchable = "Yes" if searchable else "No"
                    elif isinstance(searchable, str):
                        searchable = (
                            "Yes"
                            if searchable.lower() in ("true", "t", "yes", "y", "1")
                            else "No"
                        )

                    # Get timestamp for added field (ISO 8601 format)
                    timestamp = breach.get("timestamp")
                    if timestamp:
                        added = timestamp.replace(microsecond=0).isoformat()
                    else:
                        added = None

                    detailed_breach_info[entity["breach"]] = DetailedBreachInfo(
                        breached_date=formatted_date,
                        logo=breach["logo"],
                        password_risk=breach["password_risk"],
                        searchable=searchable,
                        xposed_data=xposed_data,
                        xposed_records=breach["xposed_records"],
                        xposure_desc=breach["xposure_desc"],
                        added=added,
                    )

            # Get breach details (filtered by time if time_threshold is set)
            query = client.query(kind="xon_domains_details")
            query.add_filter("domain", "=", domain)
            for entity in query.fetch():
                # Only include breach details for breaches that pass the time filter
                if time_threshold is None or entity["breach"] in time_filtered_breaches:
                    breach_details.append(
                        BreachDetails(
                            email=entity["email"],
                            domain=entity["domain"],
                            breach=entity["breach"],
                        )
                    )

        # Collect emails from filtered breach_details for seniority filtering
        filtered_emails = {bd.email for bd in breach_details}

        # Get seniority information (filtered by emails in time-filtered breaches)
        query = client.query(kind="xon_domains_seniority")
        query.add_filter("domain", "IN", verified_domains)
        for entity in query.fetch():
            # Only count seniority for emails that are in the filtered breach details
            entity_email = entity.get("email", "")
            if time_threshold is None or entity_email in filtered_emails:
                seniority = entity.get("seniority", "").lower()
                if seniority in seniority_summary:
                    seniority_summary[seniority] += 1

        # Build yearly breach hierarchy
        yearly_breach_hierarchy = {"description": "Data Breaches", "children": []}

        for year, breaches in yearly_breach_summary.items():
            year_node = {"description": year, "children": []}
            for breach_name in breaches:
                breach_logo = all_breaches_logo.get(breach_name, "")
                details = (
                    f"<img src='{escape_html_attr(breach_logo)}' style='height:40px;width:65px;' />"
                    f"<a target='_blank' href='https://xposedornot.com/xposed/#{escape_url_fragment(breach_name)}'>"
                    " &nbsp;Details</a>"
                )
                breach_node = {
                    "description": details,
                    "tooltip": f"View {breach_name} details",
                    "children": [],
                }
                year_node["children"].append(breach_node)
            yearly_breach_hierarchy["children"].append(year_node)

        # Get top 10 breaches
        top10_breaches = dict(
            sorted(breach_summary.items(), key=lambda x: x[1], reverse=True)[:5]
        )

        # Query alerts for verified domains (last 6 months)
        alert_time_threshold = datetime.datetime.utcnow().replace(
            tzinfo=datetime.timezone.utc
        ) - datetime.timedelta(days=183)

        try:
            # Query only by domain_owner_email to avoid composite index requirement
            alert_query = client.query(kind="xon_alert_domains")
            alert_query.add_filter("domain_owner_email", "=", email)

            # Fetch all alerts for this user
            all_alerts = list(alert_query.fetch())

            # Filter by time threshold in memory
            filtered_alerts = []
            for alert in all_alerts:
                created_at = alert.get("created_at")
                if created_at:
                    # Ensure timezone aware for comparison
                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=datetime.timezone.utc)
                    if created_at >= alert_time_threshold:
                        filtered_alerts.append(alert)

            # Sort by created_at descending in memory
            filtered_alerts.sort(
                key=lambda x: x.get("created_at", datetime.datetime.min), reverse=True
            )

            alerts_list = []
            pending_count = 0
            acknowledged_count = 0

            for alert_entity in filtered_alerts:
                # Only include alerts for verified domains
                if alert_entity.get("affected_domain") not in verified_domains:
                    continue

                # Count by status
                status = alert_entity.get("status", "Pending")
                if status == "Pending":
                    pending_count += 1
                elif status == "Acknowledged":
                    acknowledged_count += 1

                # Parse exposed_fields
                exposed_fields = alert_entity.get("exposed_fields", [])
                if isinstance(exposed_fields, str):
                    try:
                        import json

                        exposed_fields = json.loads(exposed_fields)
                    except (json.JSONDecodeError, ValueError):
                        exposed_fields = []

                # Format timestamps
                alert_time = alert_entity.get("created_at")
                if alert_time:
                    if alert_time.tzinfo is None:
                        alert_time = alert_time.replace(tzinfo=datetime.timezone.utc)
                    alert_time_str = alert_time.isoformat()
                else:
                    alert_time_str = None

                acknowledged_at = alert_entity.get("acknowledged_at")
                if acknowledged_at:
                    if acknowledged_at.tzinfo is None:
                        acknowledged_at = acknowledged_at.replace(
                            tzinfo=datetime.timezone.utc
                        )
                    acknowledged_at_str = acknowledged_at.isoformat()
                else:
                    acknowledged_at_str = None

                alert_detail = AlertDetail(
                    alert_id=alert_entity.key.name or str(alert_entity.key.id),
                    breach_id=alert_entity.get("breach_id", ""),
                    breach_name=alert_entity.get("breach_name", ""),
                    alert_time=alert_time_str,
                    severity=alert_entity.get("severity", "Unknown"),
                    status=status,
                    description=alert_entity.get("description", ""),
                    affected_domain=alert_entity.get("affected_domain", ""),
                    affected_email_count=alert_entity.get("affected_email_count", 0),
                    exposed_fields=exposed_fields,
                    password_type=alert_entity.get("password_type", ""),
                    acknowledged_at=acknowledged_at_str,
                    acknowledged_by=alert_entity.get("acknowledged_by"),
                    last_updated_by=alert_entity.get("last_updated_by"),
                )
                alerts_list.append(alert_detail)

        except Exception as alert_error:
            # Continue without alerts instead of failing the entire request
            logger.error(f"Alert query failed: {str(alert_error)}")
            alerts_list = []
            pending_count = 0
            acknowledged_count = 0

        # Create alert management structure
        alert_management = AlertManagement(
            summary={
                "total_alerts": len(alerts_list),
                "pending_count": pending_count,
                "acknowledged_count": acknowledged_count,
                "time_range": "Last 6 months",
            },
            alerts=alerts_list,
        )

        # Prepare response
        response = DomainBreachesResponse(
            Yearly_Metrics=dict(yearly_summary),
            Domain_Summary=dict(domain_summary),
            Breach_Summary=dict(breach_summary),
            Breaches_Details=breach_details,
            Top10_Breaches=top10_breaches,
            Detailed_Breach_Info=detailed_breach_info,
            Verified_Domains=verified_domains,
            Seniority_Summary=seniority_summary,
            Yearly_Breach_Hierarchy=yearly_breach_hierarchy,
            Alert_Management=alert_management,
        )

        return response

    except HTTPException:
        raise
    except (ValueError, google_exceptions.GoogleAPIError) as e:
        await send_exception_email(
            api_route="GET /v1/send_domain_breaches",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={email}, token={'provided' if token else 'not_provided'}, time_filter={time_filter}",
        )
        error_detail = f"Error: {str(e)}"
        return DomainBreachesErrorResponse(Error=error_detail)


@router.get(
    "/shield-on/{email}",
    response_model=ShieldActivationResponse,
    responses={
        200: {"model": ShieldActivationResponse},
        404: {"model": ShieldActivationErrorResponse},
    },
)
@custom_rate_limiter("50 per day;25 per hour;2 per second")
async def activate_shield(
    request: Request, email: str
) -> Union[ShieldActivationResponse, ShieldActivationErrorResponse]:
    """
    Enable privacy shield for public searches and return status.

    """
    try:
        email = email.lower()
        if not email or not validate_email_with_tld(email) or not validate_url(request):
            return JSONResponse(
                status_code=404,
                content={"Error": "Not found"},
            )

        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", email)
        alert_task = datastore_client.get(alert_key)

        token_shield = await generate_confirmation_token(email)
        base_url = str(request.base_url)
        confirmation_url = f"{base_url}v1/verify-shield/{token_shield}"

        if alert_task is None or not alert_task.get("shieldOn", False):
            # Create or update alert entity
            alert_entity = datastore.Entity(
                datastore_client.key("xon_alert", email),
                exclude_from_indexes=[
                    "insert_timestamp",
                    "verify_timestamp",
                    "verified",
                    "unSubscribeOn",
                    "shieldOn",
                ],
            )

            if alert_task is None:
                alert_entity.update(
                    {
                        "insert_timestamp": datetime.datetime.now(),
                        "verified": False,
                        "shieldOn": False,
                        "unSubscribeOn": False,
                    }
                )
                datastore_client.put(alert_entity)

            # Get client information
            client_ip = get_client_ip(request)
            preferred_ip = get_preferred_ip_address(client_ip)
            location = fetch_location_by_ip(preferred_ip) if preferred_ip else "Unknown"
            browser_type, client_platform = get_user_agent_info(request)

            # Send shield email
            try:
                await send_shield_email(
                    email,
                    confirmation_url,
                    f"{client_ip} ({location})",
                    browser_type,
                    client_platform,
                )
            except Exception as e:
                raise

            return ShieldActivationResponse(Success="ShieldAdded")

        if alert_task.get("shieldOn", False):
            return ShieldActivationResponse(Success="AlreadyOn")

        return JSONResponse(
            status_code=404,
            content={"Error": "Unexpected state"},
        )

    except (ValueError, HTTPException, google_exceptions.GoogleAPIError) as e:
        await send_exception_email(
            api_route=f"GET /v1/shield-on/{email}",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={email}",
        )
        return JSONResponse(
            status_code=404,
            content={"Error": f"Internal error: {str(e)}"},
        )


@router.get(
    "/verify-shield/{token_shield}",
    response_class=HTMLResponse,
    responses={
        200: {"content": {"text/html": {}}},
        404: {"content": {"text/html": {}}},
    },
)
@custom_rate_limiter("50 per day;25 per hour;2 per second")
async def verify_shield(request: Request, token_shield: str) -> HTMLResponse:
    """
    Verify privacy shield for public searches and return status.

    """
    try:
        if (
            not token_shield
            or not validate_variables([token_shield])
            or not validate_url(request)
        ):
            return HTMLResponse(
                content=templates.TemplateResponse(
                    "email_shield_error.html", {"request": request}
                ).body.decode(),
                status_code=404,
            )

        email = await confirm_token(token_shield)
        if not email:
            return HTMLResponse(
                content=templates.TemplateResponse(
                    "email_shield_error.html", {"request": request}
                ).body.decode(),
                status_code=404,
            )

        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", email)
        alert_task = datastore_client.get(alert_key)

        if alert_task:
            alert_task["shield_timestamp"] = datetime.datetime.now()
            alert_task["shieldOn"] = True
            datastore_client.put(alert_task)

        else:
            alert_task = datastore.Entity(key=alert_key)
            alert_task.update(
                {
                    "insert_timestamp": datetime.datetime.now(),
                    "shield_timestamp": datetime.datetime.now(),
                    "shieldOn": True,
                }
            )
            datastore_client.put(alert_task)

        return HTMLResponse(
            content=templates.TemplateResponse(
                "email_shield_verify.html", {"request": request}
            ).body.decode(),
            status_code=200,
        )

    except (ValueError, HTTPException, google_exceptions.GoogleAPIError) as e:
        await send_exception_email(
            api_route="GET /v1/verify-shield/{token}",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"token={token_shield}",
        )
        return HTMLResponse(
            content=templates.TemplateResponse(
                "email_shield_error.html", {"request": request}
            ).body.decode(),
            status_code=404,
        )


async def get_breach_hierarchy_analytics(
    breaches: str, sensitive_breaches: str = ""
) -> Dict[str, Any]:
    """Returns the hierarchical metrics of exposed breaches organized by year"""
    try:
        ds_client = datastore.Client()
        get_details = {"children": [], "description": "Data Breaches"}

        # Create year dictionaries dynamically from 2026 down to 2007
        year_dicts = {
            str(year): {"children": [], "description": str(year)}
            for year in range(2026, 2006, -1)
        }

        # Process regular breaches
        if breaches and len(breaches) > 0:
            breach_list = breaches.split(";")
            for breach in breach_list:
                if not breach:
                    continue

                key = ds_client.key("xon_breaches", breach)
                query = ds_client.get(key)
                if not query:
                    continue

                parts_s = str(key).split(",")
                bid = parts_s[1][:-2][2:]
                logo = query.get("logo", "default_logo.jpg")

                details = (
                    f"<img src='{escape_html_attr(logo)}' style='height:40px;width:65px;' />"
                    f"<a target='_blank' href='https://xposedornot.com/xposed/#{escape_url_fragment(bid)}'>"
                    " &nbsp;Details</a>"
                )

                child = {
                    "children": [
                        {
                            "children": [],
                            "description": details,
                            "tooltip": "Click here 👇",
                        }
                    ],
                    "description": bid,
                }

                breach_year = str(query["breached_date"].year)
                if breach_year in year_dicts:
                    year_dicts[breach_year]["children"].append(child)

        # Process sensitive breaches
        if sensitive_breaches and len(sensitive_breaches) > 0:
            sensitive_breach_list = sensitive_breaches.split(";")
            for breach in sensitive_breach_list:
                if not breach:
                    continue

                key = ds_client.key("xon_breaches", breach)
                query = ds_client.get(key)
                if not query:
                    continue

                parts_s = str(key).split(",")
                bid = parts_s[1][:-2][2:]
                logo = query.get("logo", "default_logo.jpg")

                details = (
                    f"<img src='{escape_html_attr(logo)}' style='height:40px;width:65px;' />"
                    f"<a target='_blank' href='https://xposedornot.com/xposed/#{escape_url_fragment(bid)}'>"
                    " &nbsp;Details</a>"
                )

                child = {
                    "children": [
                        {
                            "children": [],
                            "description": details,
                            "tooltip": "Click here 👇",
                        }
                    ],
                    "description": bid,
                }

                breach_year = str(query["breached_date"].year)
                if breach_year in year_dicts:
                    year_dicts[breach_year]["children"].append(child)

        # Add all years to get_details in descending order
        for year in sorted(year_dicts.keys(), reverse=True):
            get_details["children"].append(year_dicts[year])

        return get_details
    except Exception as e:
        # Note: This is a helper function, not a route handler, so request object not available
        # Logging without request context
        await send_exception_email(
            api_route="HELPER /get_breach_hierarchy_analytics",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent="N/A (helper function)",
            request_params=f"breaches={breaches[:50] if breaches else 'None'}, sensitive_breaches={'provided' if sensitive_breaches else 'not_provided'}",
        )
        raise HTTPException(
            status_code=404, detail="Error processing breach data"
        ) from e


@router.get("/analytics/{user_email}", response_model=BreachHierarchyResponse)
@custom_rate_limiter("100 per day;50 per hour;2 per second")
async def get_analytics(
    request: Request, user_email: str
) -> Union[JSONResponse, BreachHierarchyResponse]:
    """Returns hierarchical analytics of data breaches for a given email"""
    try:
        user_email = user_email.lower()
        if (
            not user_email
            or not validate_email_with_tld(user_email)
            or not validate_url(request)
        ):
            return JSONResponse(content={"Error": "Not found"}, status_code=404)

        data_store = datastore.Client()
        xon_key = data_store.key("xon", user_email)
        xon_record = data_store.get(xon_key)
        alert_key = data_store.key("xon_alert", user_email)
        alert_record = data_store.get(alert_key)

        # Always check shieldOn first (privacy - can't cache this)
        if alert_record and alert_record.get("shieldOn"):
            raise ShieldOnException("Shield is on")

        # Check cache after shieldOn validation
        cache_key = f"analytics-hierarchy:{hash_email(user_email)}"
        cached_result = get_cached_analytics(cache_key)
        if cached_result:
            return BreachHierarchyResponse(**cached_result)

        if xon_record:
            site = str(xon_record["site"])
            breach_hierarchy = await get_breach_hierarchy_analytics(site, "")
            cache_analytics(cache_key, breach_hierarchy)
            return BreachHierarchyResponse(**breach_hierarchy)

        return JSONResponse(content=None)

    except ShieldOnException:
        return JSONResponse(content={"Error": "Not found"}, status_code=404)

    except (ValueError, HTTPException, google_exceptions.GoogleAPIError) as e:
        print(f"GET /v1/analytics/{user_email} error: {e}")
        await send_exception_email(
            api_route=f"GET /v1/analytics/{user_email}",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={user_email}",
        )
        return JSONResponse(
            status_code=404, content={"Error": "Failed to retrieve analytics"}
        )


@router.post(
    "/update_alert_status",
    response_model=Union[AlertStatusUpdateResponse, AlertStatusUpdateErrorResponse],
    responses={
        200: {"model": AlertStatusUpdateResponse},
        400: {"model": AlertStatusUpdateErrorResponse},
        401: {"model": AlertStatusUpdateErrorResponse},
        403: {"model": AlertStatusUpdateErrorResponse},
        404: {"model": AlertStatusUpdateErrorResponse},
    },
)
@custom_rate_limiter("2 per second;50 per hour;200 per day")
async def update_alert_status(
    request: Request,
    payload: AlertStatusUpdateRequest,
    email: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
) -> Union[AlertStatusUpdateResponse, AlertStatusUpdateErrorResponse]:
    """
    Update the status of a domain breach alert.

    Allows users to toggle alert status between 'Pending' and 'Acknowledged'.

    Args:
        request: FastAPI request object
        payload: Request body containing alert_id and status
        email: User's email for authentication
        token: Session token for validation

    Returns:
        AlertStatusUpdateResponse: Success response with status details
        AlertStatusUpdateErrorResponse: Error response
    """
    try:
        # Validate required parameters
        if not email or not token:
            raise HTTPException(
                status_code=400,
                detail=AlertStatusUpdateErrorResponse(
                    Error="Missing email or token"
                ).dict(),
            )

        if not payload.alert_id:
            raise HTTPException(
                status_code=400,
                detail=AlertStatusUpdateErrorResponse(Error="Missing alert_id").dict(),
            )

        # Validate status value
        if payload.status not in ["Pending", "Acknowledged"]:
            raise HTTPException(
                status_code=400,
                detail=AlertStatusUpdateErrorResponse(
                    Error="Invalid status. Must be 'Pending' or 'Acknowledged'"
                ).dict(),
            )

        # Validate email and token format
        if not validate_email_with_tld(email):
            raise HTTPException(
                status_code=400,
                detail=AlertStatusUpdateErrorResponse(
                    Error="Invalid email format"
                ).dict(),
            )

        if not validate_token(token):
            raise HTTPException(
                status_code=400,
                detail=AlertStatusUpdateErrorResponse(
                    Error="Invalid token format"
                ).dict(),
            )

        if not validate_url(request):
            raise HTTPException(
                status_code=400,
                detail=AlertStatusUpdateErrorResponse(
                    Error="Invalid request URL"
                ).dict(),
            )

        # Check session authentication
        client = datastore.Client()
        alert_key = client.key("xon_domains_session", email)
        alert_task = client.get(alert_key)

        if not alert_task:
            raise HTTPException(
                status_code=401,
                detail=AlertStatusUpdateErrorResponse(
                    Error="Invalid or expired session"
                ).dict(),
            )

        if alert_task.get("domain_magic") != token:
            raise HTTPException(
                status_code=401,
                detail=AlertStatusUpdateErrorResponse(
                    Error="Invalid or expired session"
                ).dict(),
            )

        # Check session expiry (12 hours)
        if datetime.datetime.utcnow() - alert_task.get("magic_timestamp").replace(
            tzinfo=None
        ) > datetime.timedelta(hours=12):
            raise HTTPException(
                status_code=401,
                detail=AlertStatusUpdateErrorResponse(Error="Session expired").dict(),
            )

        # Get user's verified domains
        query = client.query(kind="xon_domains")
        query.add_filter("email", "=", email)
        verified_domains = [entity["domain"] for entity in query.fetch()]

        # Fetch the alert
        alert_entity_key = client.key("xon_alert_domains", payload.alert_id)
        alert_entity = client.get(alert_entity_key)

        if not alert_entity:
            raise HTTPException(
                status_code=404,
                detail=AlertStatusUpdateErrorResponse(Error="Alert not found").dict(),
            )

        # Authorization: Check if alert belongs to user
        if alert_entity.get("domain_owner_email") != email:
            raise HTTPException(
                status_code=403,
                detail=AlertStatusUpdateErrorResponse(
                    Error="You do not have permission to modify this alert"
                ).dict(),
            )

        # Additional check: Alert's affected_domain must be in verified domains
        if alert_entity.get("affected_domain") not in verified_domains:
            raise HTTPException(
                status_code=403,
                detail=AlertStatusUpdateErrorResponse(
                    Error="You do not have permission to modify this alert"
                ).dict(),
            )

        # Get current status
        previous_status = alert_entity.get("status", "Pending")

        # Idempotency check
        if previous_status == payload.status:
            # Format acknowledged_at if exists
            acknowledged_at = alert_entity.get("acknowledged_at")
            if acknowledged_at:
                if acknowledged_at.tzinfo is None:
                    acknowledged_at = acknowledged_at.replace(
                        tzinfo=datetime.timezone.utc
                    )
                acknowledged_at_str = acknowledged_at.isoformat()
            else:
                acknowledged_at_str = None

            return AlertStatusUpdateResponse(
                status="success",
                message="Alert already in requested status",
                alert_id=payload.alert_id,
                previous_status=previous_status,
                current_status=payload.status,
                acknowledged_at=acknowledged_at_str,
                acknowledged_by=alert_entity.get("acknowledged_by"),
                last_updated_by=alert_entity.get("last_updated_by", email),
            )

        # Update status
        current_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

        alert_entity["status"] = payload.status
        alert_entity["updated_at"] = current_time
        alert_entity["last_updated_by"] = email  # Always track who made the change

        if payload.status == "Acknowledged":
            # Update acknowledgment fields when acknowledging
            alert_entity["acknowledged_at"] = current_time
            alert_entity["acknowledged_by"] = email
            acknowledged_at_str = current_time.isoformat()
            acknowledged_by_str = email
        else:  # Pending
            # Preserve acknowledgment history when un-acknowledging
            # Don't clear acknowledged_at and acknowledged_by
            existing_acknowledged_at = alert_entity.get("acknowledged_at")
            if existing_acknowledged_at:
                if existing_acknowledged_at.tzinfo is None:
                    existing_acknowledged_at = existing_acknowledged_at.replace(
                        tzinfo=datetime.timezone.utc
                    )
                acknowledged_at_str = existing_acknowledged_at.isoformat()
            else:
                acknowledged_at_str = None
            acknowledged_by_str = alert_entity.get("acknowledged_by")

        # Save to datastore
        client.put(alert_entity)

        return AlertStatusUpdateResponse(
            status="success",
            message="Alert status updated successfully",
            alert_id=payload.alert_id,
            previous_status=previous_status,
            current_status=payload.status,
            acknowledged_at=acknowledged_at_str,
            acknowledged_by=acknowledged_by_str,
            last_updated_by=email,
        )

    except HTTPException:
        raise
    except Exception as e:
        await send_exception_email(
            api_route="POST /v1/update_alert_status",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={email}, token={'provided' if token else 'not_provided'}, alert_id={payload.alert_id if payload else 'missing'}, status={payload.status if payload else 'missing'}",
        )
        return AlertStatusUpdateErrorResponse(Error=f"Internal error: {str(e)}")
