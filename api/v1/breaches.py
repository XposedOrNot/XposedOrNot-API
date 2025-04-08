"""Breach-related API endpoints."""

# Standard library imports
import json
import logging
import sys
from datetime import datetime
from typing import Optional, Union

# Third-party imports
from fastapi import APIRouter, HTTPException, Request, Header, Query, Path
from fastapi.responses import JSONResponse, Response
from google.cloud import datastore
from slowapi import Limiter
from slowapi.util import get_remote_address

# Local imports
from config.settings import MAX_EMAIL_LENGTH
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
from services.breach import get_exposure, get_sensitive_exposure
from utils.helpers import (
    string_to_boolean,
    validate_domain,
    validate_email_with_tld,
    validate_url,
)
from utils.validation import validate_variables

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.get("/breaches", response_model=BreachListResponse)
@limiter.limit("2 per second;50 per hour;1000 per day")
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
        client = datastore.Client()
        query = client.query(kind="xon_breaches")

        if breach_id:
            if not validate_variables([breach_id]):
                raise HTTPException(status_code=400, detail="Invalid Breach ID")
            query.key_filter(client.key("xon_breaches", breach_id), "=")
        elif domain:
            if not validate_domain(domain):
                raise HTTPException(status_code=400, detail="Invalid Domain")
            query.add_filter("domain", "=", domain)
        else:
            query.order = ["-timestamp"]

        # Check if-modified-since header
        latest_entity = list(query.fetch(limit=1))
        if latest_entity and if_modified_since:
            latest_timestamp = latest_entity[0]["timestamp"]
            try:
                if_modified_dt = datetime.strptime(
                    if_modified_since, "%a, %d %b %Y %H:%M:%S GMT"
                )
                if latest_timestamp.replace(tzinfo=None) <= if_modified_dt:
                    return Response(status_code=304)
            except ValueError:
                pass

        entities = list(query.fetch())
        if not entities:
            return BreachListResponse(
                status="Not Found",
                message="No breaches found for the provided criteria",
            )

        breach_details = []
        for entity in entities:
            # Convert exposed data string to list
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

        return BreachListResponse(status="success", exposedBreaches=breach_details)

    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.get("/v2/breach-analytics", response_model=BreachAnalyticsV2Response)
@limiter.limit("2 per second;50 per hour;100 per day")
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
            logger.debug("[BREACH-ANALYTICS] Processing sensitive data")
            # Get existing sites from breach record
            existing_sites = (
                set(breach_data["site"].split(";"))
                if "site" in breach_data and breach_data["site"]
                else set()
            )
            # Get sites from sensitive data
            sensitive_sites = (
                set(sensitive_data["site"].split(";"))
                if "site" in sensitive_data and sensitive_data["site"]
                else set()
            )
            # Combine sites
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

    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.get("/breach-analytics", response_model=BreachAnalyticsResponse)
@limiter.limit("2 per second;50 per hour;100 per day")
async def search_data_breaches(
    request: Request, email: Optional[str] = None, token: Optional[str] = None
) -> BreachAnalyticsResponse:
    """Returns summary and details of data breaches for a given email."""
    logger.debug("[BREACH-ANALYTICS] Starting breach search for email: %s", email)

    if (
        not email
        or not validate_email_with_tld(email)
        or not validate_url(request)
        or len(email) > MAX_EMAIL_LENGTH
    ):
        logger.debug("[BREACH-ANALYTICS] Input validation failed")
        logger.debug(
            "[BREACH-ANALYTICS] Email valid: %s",
            bool(email and validate_email_with_tld(email)),
        )
        logger.debug("[BREACH-ANALYTICS] URL valid: %s", bool(validate_url(request)))
        logger.debug(
            "[BREACH-ANALYTICS] Length valid: %s",
            bool(email and len(email) <= MAX_EMAIL_LENGTH),
        )
        raise HTTPException(status_code=404, detail="Not found")

    try:
        email = email.lower()
        logger.debug("\n" + "=" * 50)
        logger.debug("[BREACH-ANALYTICS][1] Starting breach search")
        logger.debug("-" * 50)
        logger.debug(
            "[BREACH-ANALYTICS][1.1] Email: %s, Token provided: %s", email, bool(token)
        )

        # Check shield status first
        logger.debug("\n[BREACH-ANALYTICS][2] Checking shield status")
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", email)
        alert_record = datastore_client.get(alert_key)
        logger.debug(
            "[BREACH-ANALYTICS][2.1] Alert record found: %s, Shield status: %s",
            bool(alert_record),
            alert_record.get("shieldOn", False) if alert_record else False,
        )

        if alert_record and alert_record.get("shieldOn", False):
            logger.debug("[BREACH-ANALYTICS][2.2] Shield is on for this email")
            raise HTTPException(status_code=404, detail="Not found")

        # Validate token if provided
        if token:
            logger.debug("\n[BREACH-ANALYTICS][3] Validating token")
            stored_token = alert_record.get("token") if alert_record else None
            token_valid = bool(alert_record and alert_record.get("token") == token)
            logger.debug(
                "[BREACH-ANALYTICS][3.1] Token validation - Stored: %s, Provided: %s, Valid: %s",
                stored_token,
                token,
                token_valid,
            )

            if not token_valid:
                logger.debug("[BREACH-ANALYTICS][3.2] Invalid token provided")
                raise HTTPException(status_code=403, detail="Invalid token")
            logger.debug("[BREACH-ANALYTICS][3.3] Token validation successful")

        # Get breach and sensitive data
        logger.debug("\n[BREACH-ANALYTICS][4] Fetching data")
        breach_data = await get_exposure(email)
        logger.debug(
            "[BREACH-ANALYTICS][4.1] Breach data: %s",
            _format_log_data(breach_data) if breach_data else "No breach data",
        )

        sensitive_data = None
        if token:
            logger.debug("[BREACH-ANALYTICS][4.2] Fetching sensitive data...")
            sensitive_data = await get_sensitive_exposure(email)
            logger.debug(
                "[BREACH-ANALYTICS][4.3] Sensitive data: %s",
                (
                    _format_log_data(sensitive_data)
                    if sensitive_data
                    else "No sensitive data"
                ),
            )
        else:
            logger.debug(
                "[BREACH-ANALYTICS][4.4] No token, skipping sensitive data fetch"
            )

        # Return empty response if no data found
        if not breach_data and not sensitive_data:
            logger.debug("\n[BREACH-ANALYTICS][5] No data found")
            return BreachAnalyticsResponse(
                BreachesSummary={"domain": "", "site": "", "tmpstmp": ""},
                PastesSummary={"cnt": 0, "domain": "", "tmpstmp": ""},
                ExposedBreaches=None,
                ExposedPastes=None,
                BreachMetrics=None,
                PasteMetrics=None,
            )

        # Combine breach and sensitive data sites if token is valid
        if breach_data and sensitive_data and token:
            logger.debug("\n[BREACH-ANALYTICS][6] Processing sensitive data")
            # Get existing sites from breach record
            existing_sites = (
                set(breach_data["site"].split(";"))
                if "site" in breach_data and breach_data["site"]
                else set()
            )
            # Get sites from sensitive data
            sensitive_sites = (
                set(sensitive_data["site"].split(";"))
                if "site" in sensitive_data and sensitive_data["site"]
                else set()
            )
            logger.debug(
                "[BREACH-ANALYTICS][6.1] Sites - Existing: %s, Sensitive: %s",
                list(existing_sites),
                list(sensitive_sites),
            )

            # Combine sites
            unique_sites = existing_sites.union(sensitive_sites)
            breach_data["site"] = ";".join(unique_sites)
            logger.debug(
                "[BREACH-ANALYTICS][6.2] Combined sites: %s", list(unique_sites)
            )

        # Get summary and metrics
        logger.debug("\n[BREACH-ANALYTICS][7] Getting summary and metrics")
        logger.debug(
            "[BREACH-ANALYTICS][7.1] Input - Breach data: %s",
            _format_log_data(breach_data),
        )
        logger.debug(
            "[BREACH-ANALYTICS][7.2] Input - Sensitive data: %s",
            _format_log_data(sensitive_data),
        )

        summary_result = await get_summary_and_metrics(breach_data, sensitive_data)
        (
            breach_summary,
            paste_summary,
            exposed_breaches,
            exposed_pastes,
            breach_metrics,
            paste_metrics,
        ) = summary_result

        logger.debug("\n[BREACH-ANALYTICS][8] Summary results:")
        logger.debug(
            "[BREACH-ANALYTICS][8.1] Breach summary: %s",
            _format_log_data(breach_summary),
        )
        logger.debug(
            "[BREACH-ANALYTICS][8.2] Paste summary: %s", _format_log_data(paste_summary)
        )
        logger.debug(
            "[BREACH-ANALYTICS][8.3] Exposed breaches: %s",
            _format_log_data(exposed_breaches),
        )
        logger.debug(
            "[BREACH-ANALYTICS][8.4] Exposed pastes: %s",
            _format_log_data(exposed_pastes),
        )
        logger.debug(
            "[BREACH-ANALYTICS][8.5] Breach metrics: %s",
            _format_log_data(breach_metrics),
        )
        logger.debug(
            "[BREACH-ANALYTICS][8.6] Paste metrics: %s", _format_log_data(paste_metrics)
        )

        # Return appropriate response based on data availability
        if breach_summary or paste_summary:
            logger.debug("\n[BREACH-ANALYTICS][9] Returning full response")
            return BreachAnalyticsResponse(
                ExposedBreaches=exposed_breaches,
                BreachesSummary=breach_summary
                or {"domain": "", "site": "", "tmpstmp": ""},
                BreachMetrics=breach_metrics,
                PastesSummary=paste_summary or {"cnt": 0, "domain": "", "tmpstmp": ""},
                ExposedPastes=exposed_pastes,
                PasteMetrics=paste_metrics,
            )

        logger.debug("\n[BREACH-ANALYTICS][9] No summary data found")
        return BreachAnalyticsResponse(
            BreachesSummary={"domain": "", "site": "", "tmpstmp": ""},
            PastesSummary={"cnt": 0, "domain": "", "tmpstmp": ""},
            ExposedBreaches=None,
            ExposedPastes=None,
            BreachMetrics=None,
            PasteMetrics=None,
        )

    except Exception as e:
        logger.error(
            "[BREACH-ANALYTICS] Error processing request: %s", str(e), exc_info=True
        )
        raise HTTPException(status_code=404, detail="Not found") from e


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
    
    Rate Limit: 2 requests/second, 50/hour, 100/day
    """,
    tags=["breaches"],
)
async def search_email(
    request: Request,
    email: str = Path(
        ...,
        description="Email address to check for breaches",
        example="user@example.com",
        max_length=MAX_EMAIL_LENGTH,
    ),
    # Keeping parameter but not using it to maintain API compatibility
    include_details: bool = Query(
        False,
        description="Include detailed breach information in the response",
        example=False,
    ),
) -> Union[EmailBreachResponse, EmailBreachErrorResponse]:
    """Check if an email address appears in any known data breaches."""
    try:
        if not email or not validate_email_with_tld(email) or not validate_url(request):
            return EmailBreachErrorResponse(Error="Not found")

        email = email.lower()
        breach_data = await get_exposure(email)

        if not breach_data:
            return EmailBreachErrorResponse(Error="Not found")

        # Initialize datastore client
        data_store = datastore.Client()

        # Check if email is protected by shield
        alert_key = data_store.key("xon_alert", email)
        alert_record = data_store.get(alert_key)
        if alert_record and alert_record.get("shieldOn", False):
            return JSONResponse(
                status_code=404, content={"Error": "Email is protected", "email": email}
            )

        # Get breach data
        xon_key = data_store.key("xon", email)
        xon_record = data_store.get(xon_key)

        if xon_record and "site" in xon_record:
            domains = xon_record["site"].split(";")
            filtered_domains = [domain.strip() for domain in domains if domain.strip()]

            if filtered_domains:
                return JSONResponse(
                    status_code=200,
                    content={"breaches": [filtered_domains], "email": email},
                )

        return JSONResponse(
            status_code=404, content={"Error": "No breaches found", "email": email}
        )

    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.get("/domain-breach-summary", response_model=DomainBreachSummaryResponse)
@limiter.limit("2 per second;10 per hour;50 per day")
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
    logger.debug(
        "[DOMAIN-BREACH-SUMMARY] Starting domain breach search for domain: %s", d
    )

    try:
        if not d or not validate_domain(d) or not validate_url(request):
            logger.debug("[DOMAIN-BREACH-SUMMARY] Input validation failed")
            logger.debug(
                "[DOMAIN-BREACH-SUMMARY] Domain valid: %s",
                bool(d and validate_domain(d)),
            )
            logger.debug(
                "[DOMAIN-BREACH-SUMMARY] URL valid: %s", bool(validate_url(request))
            )
            raise HTTPException(status_code=404, detail="Not found")

        domain = d.lower().strip()

        # Initialize datastores
        ds_xon = datastore.Client()

        # Query xon records for domain
        logger.debug(
            "[DOMAIN-BREACH-SUMMARY] Querying xon records for domain: %s", domain
        )
        xon_rec = ds_xon.query(kind="xon")
        xon_rec.add_filter("domain", "=", domain)
        query_xon = xon_rec.fetch(limit=1000)

        unique_emails = set()
        unique_sites = set()
        total_records = 0

        # Process xon records
        for entity_xon in query_xon:
            email = entity_xon.key.name
            if len(unique_emails) <= 1000:
                unique_emails.add(email)
            if "site" in entity_xon:
                sites = entity_xon["site"].split(";")
                unique_sites.update(sites)
                total_records += len(sites)

        unique_sites.discard("")

        breach_count = len(unique_sites)
        emails_count = len(unique_emails)

        logger.debug(
            "[DOMAIN-BREACH-SUMMARY] Found %s unique emails and %s unique breaches",
            emails_count,
            breach_count,
        )

        # Query paste records
        logger.debug(
            "[DOMAIN-BREACH-SUMMARY] Querying paste records for domain: %s", domain
        )
        ds_paste = datastore.Client()
        paste_rec = ds_paste.query(kind="xon_paste")
        paste_rec.add_filter("domain", "=", domain)
        query_paste = paste_rec.fetch(limit=50)

        pastes_count = sum(1 for _ in query_paste)
        logger.debug("[DOMAIN-BREACH-SUMMARY] Found %s pastes", pastes_count)

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
                logger.debug(
                    "[DOMAIN-BREACH-SUMMARY] Latest breach date: %s", breach_last_seen
                )

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

        return DomainBreachSummaryResponse(
            sendDomains=breaches_dict, SearchStatus="Success"
        )

    except Exception as e:
        logger.error(
            "[DOMAIN-BREACH-SUMMARY] Error processing request: %s",
            str(e),
            exc_info=True,
        )
        raise HTTPException(status_code=404, detail=str(e)) from e


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
        # Convert data to be JSON serializable
        prepared_data = _prepare_for_logging(data)
        # Format with compact separators and no extra whitespace
        return json.dumps(prepared_data, separators=(",", ":"))

    except (ValueError, TypeError, KeyError) as e:
        return f"Error formatting data: {str(e)}"
