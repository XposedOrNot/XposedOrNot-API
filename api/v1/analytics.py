"""Analytics-related API endpoints."""

# Standard library imports
import datetime
import html
import logging
from collections import defaultdict
from typing import Optional, Union, Dict, Any, List

# Third-party imports
from fastapi import APIRouter, HTTPException, Request, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from google.cloud import datastore
from slowapi import Limiter
from slowapi.util import get_remote_address
from user_agents import parse

# Local imports
from models.responses import (
    DetailedMetricsResponse,
    PulseNewsResponse,
    DomainAlertResponse,
    DomainAlertErrorResponse,
    DomainVerifyResponse,
    DomainVerifyErrorResponse,
    DomainBreachesResponse,
    DomainBreachesErrorResponse,
    BreachDetails,
    DetailedBreachInfo,
    ShieldActivationResponse,
    ShieldActivationErrorResponse,
    ShieldVerificationResponse,
    ShieldVerificationErrorResponse,
    BreachHierarchyResponse,
)
from services.analytics import (
    get_detailed_metrics,
    get_pulse_news,
    get_breaches_analytics,
)
from services.send_email import send_dashboard_email_confirmation, send_shield_email
from utils.validation import validate_email_with_tld, validate_url, validate_variables
from utils.token import generate_confirmation_token, confirm_token
from utils.helpers import get_preferred_ip_address, fetch_location_by_ip
from utils.request import get_client_ip, get_user_agent_info

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
templates = Jinja2Templates(directory="templates")


class ShieldOnException(Exception):
    """Exception raised when shield is on."""

    pass


@router.get("/analytics/metrics", response_model=DetailedMetricsResponse)
@limiter.limit("5 per minute;100 per hour;500 per day")
async def get_metrics(request: Request) -> DetailedMetricsResponse:
    """Returns detailed metrics about breaches."""
    try:
        metrics = await get_detailed_metrics()
        return DetailedMetricsResponse(**metrics)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/analytics/pulse", response_model=PulseNewsResponse)
@limiter.limit("5 per minute;100 per hour;500 per day")
async def get_news_feed(request: Request) -> PulseNewsResponse:
    """Returns news feed for data breaches."""
    try:
        news_items = await get_pulse_news()
        return PulseNewsResponse(status="success", data=news_items)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get(
    "/domain-alert/{user_email}",
    response_model=DomainAlertResponse,
    responses={
        200: {"model": DomainAlertResponse},
        404: {"model": DomainAlertErrorResponse},
    },
)
@limiter.limit("2 per second;10 per hour;50 per day")
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
    logging.info(
        "[DOMAIN-ALERT] Starting domain alert process for email: %s", user_email
    )
    try:
        # HTML unescape and normalize email
        user_email = html.unescape(user_email).lower().strip()
        logging.debug("[DOMAIN-ALERT] Normalized email: %s", user_email)

        # Validate inputs
        if not user_email:
            logging.error("[DOMAIN-ALERT] Empty email provided")
            return DomainAlertErrorResponse(Error="Invalid email", email=user_email)

        if not validate_email_with_tld(user_email):
            logging.error("[DOMAIN-ALERT] Invalid email format: %s", user_email)
            return DomainAlertErrorResponse(
                Error="Invalid email format", email=user_email
            )

        if not validate_url(request):
            logging.error("[DOMAIN-ALERT] Invalid request URL: %s", request.url)
            return DomainAlertErrorResponse(Error="Invalid request", email=user_email)

        logging.info("[DOMAIN-ALERT] Input validation passed for email: %s", user_email)
        datastore_client = datastore.Client()

        # Check if the user exists in xon_domains
        query = datastore_client.query(kind="xon_domains")
        query.add_filter("email", "=", user_email)
        domain_task = list(query.fetch())

        if not domain_task:
            logging.warning(
                "[DOMAIN-ALERT] No domain task found for email: %s", user_email
            )
            # Still return success to avoid email enumeration
            return DomainAlertResponse()

        logging.info("[DOMAIN-ALERT] Found domain task for email: %s", user_email)

        # Generate verification token and URL
        verification_token = await generate_confirmation_token(user_email)
        confirmation_url = f"{request.base_url}v1/domain-verify/{verification_token}"
        logging.debug("[DOMAIN-ALERT] Generated confirmation URL: %s", confirmation_url)

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
            logging.info("[DOMAIN-ALERT] Stored session data for email: %s", user_email)
        except Exception as e:
            logging.error("[DOMAIN-ALERT] Failed to store session data: %s", str(e))
            raise

        # Get client information
        client_ip = get_client_ip(request)
        preferred_ip = get_preferred_ip_address(client_ip)
        location = fetch_location_by_ip(preferred_ip) if preferred_ip else "Unknown"
        browser_type, client_platform = get_user_agent_info(request)

        logging.debug(
            "[DOMAIN-ALERT] Client info - IP: %s, Location: %s, Browser: %s, Platform: %s",
            client_ip,
            location,
            browser_type,
            client_platform,
        )

        # Send confirmation email
        try:
            email_response = await send_dashboard_email_confirmation(
                user_email,
                confirmation_url,
                f"{client_ip} ({location})",
                browser_type,
                client_platform,
            )
            logging.info(
                "[DOMAIN-ALERT] Email sent successfully to %s. Response: %s",
                user_email,
                email_response,
            )
        except Exception as e:
            logging.error("[DOMAIN-ALERT] Failed to send email: %s", str(e))
            raise

        return DomainAlertResponse()

    except Exception as e:
        logging.error("[DOMAIN-ALERT] Unexpected error: %s", str(e), exc_info=True)
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
@limiter.limit("2 per second;10 per hour;50 per day")
async def domain_verify(request: Request, verification_token: str) -> HTMLResponse:
    """
    Verify domain alerts using token and return dashboard access.
    """
    logging.info(
        "[DOMAIN-VERIFY] Starting verification process for token: %s...",
        verification_token[:10],
    )
    try:
        # Validate inputs
        if (
            not verification_token
            or not validate_variables([verification_token])
            or not validate_url(request)
        ):
            logging.error(
                "[DOMAIN-VERIFY] Invalid token or URL: %s...", verification_token[:10]
            )
            return HTMLResponse(
                content=templates.TemplateResponse(
                    "domain_dashboard_error.html", {"request": request}
                ).body.decode(),
                status_code=404,
            )

        user_email = await confirm_token(verification_token)
        if not user_email:
            logging.error("[DOMAIN-VERIFY] Token confirmation failed")
            return HTMLResponse(
                content=templates.TemplateResponse(
                    "domain_dashboard_error.html", {"request": request}
                ).body.decode(),
                status_code=404,
            )

        logging.info("[DOMAIN-VERIFY] Token confirmed for email: %s", user_email)

        # Generate dashboard link
        base_url = "https://xposedornot.com/"
        email_param = f"email={user_email}"
        token_param = f"token={verification_token}"
        dashboard_link = f"{base_url}breach-dashboard.html?{email_param}&{token_param}"

        return HTMLResponse(
            content=templates.TemplateResponse(
                "domain_dashboard_success.html",
                {"request": request, "link": dashboard_link},
            ).body.decode(),
            status_code=200,
        )

    except Exception as e:
        logging.error(
            "[DOMAIN-VERIFY] Error processing request: %s", str(e), exc_info=True
        )
        return HTMLResponse(
            content=templates.TemplateResponse(
                "domain_dashboard_error.html", {"request": request}
            ).body.decode(),
            status_code=500,
        )


@router.get(
    "/send_domain_breaches",
    response_model=DomainBreachesResponse,
    responses={
        200: {"model": DomainBreachesResponse},
        400: {"model": DomainBreachesErrorResponse},
        404: {"model": DomainBreachesErrorResponse},
    },
)
@limiter.limit("500 per day;100 per hour;2 per second")
async def send_domain_breaches(
    request: Request,
    email: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
) -> Union[DomainBreachesResponse, DomainBreachesErrorResponse]:
    """
    Retrieves and sends the data breaches validated by token and email.

    """
    logging.info(
        "[DOMAIN-BREACHES] Starting domain breaches check for email: %s", email
    )
    try:
        # Check for presence of email and token
        if email is None or token is None:
            logging.error("[DOMAIN-BREACHES] Missing email or token")
            return DomainBreachesErrorResponse(Error="Missing email or token")

        # Validate email and token
        if (
            not validate_email_with_tld(email)
            or not validate_variables([token])
            or not validate_url(request)
        ):
            logging.error(
                "[DOMAIN-BREACHES] Invalid email or token for email: %s", email
            )
            return DomainBreachesErrorResponse(Error="Invalid email or token")

        # Check for matching session in xon_domains_session
        client = datastore.Client()
        alert_key = client.key("xon_domains_session", email)
        alert_task = client.get(alert_key)

        if not alert_task or alert_task.get("domain_magic") != token:
            logging.error("[DOMAIN-BREACHES] Invalid session for email: %s", email)
            return DomainBreachesErrorResponse(Error="Invalid session")

        if datetime.datetime.utcnow() - alert_task.get("magic_timestamp").replace(
            tzinfo=None
        ) > datetime.timedelta(hours=24):
            logging.error(f"[DOMAIN-BREACHES] Session expired for email: {email}")
            return DomainBreachesErrorResponse(Error="Session expired")

        # Get verified domains
        query = client.query(kind="xon_domains")
        query.add_filter("email", "=", email)
        verified_domains = [entity["domain"] for entity in query.fetch()]

        if not verified_domains:
            logging.warning(
                "[DOMAIN-BREACHES] No verified domains found for email: %s", email
            )
            return DomainBreachesErrorResponse(Error="No verified domains found")

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

                    detailed_breach_info[entity["breach"]] = DetailedBreachInfo(
                        breached_date=formatted_date,
                        logo=breach["logo"],
                        password_risk=breach["password_risk"],
                        searchable=searchable,
                        xposed_data=xposed_data,
                        xposed_records=breach["xposed_records"],
                        xposure_desc=breach["xposure_desc"],
                    )

            # Get breach details
            query = client.query(kind="xon_domains_details")
            query.add_filter("domain", "=", domain)
            for entity in query.fetch():
                breach_details.append(
                    BreachDetails(
                        email=entity["email"],
                        domain=entity["domain"],
                        breach=entity["breach"],
                    )
                )

        # Get seniority information
        query = client.query(kind="xon_domains_seniority")
        query.add_filter("domain", "IN", verified_domains)
        for entity in query.fetch():
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
                    f"<img src='{breach_logo}' style='height:40px;width:65px;' />"
                    f"<a target='_blank' href='https://xposedornot.com/xposed/#{breach_name}'>"
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
        )

        logging.info(
            "[DOMAIN-BREACHES] Successfully retrieved breach data for email: %s", email
        )
        return response

    except Exception as e:
        logging.error(
            "[DOMAIN-BREACHES] Error processing request: %s", str(e), exc_info=True
        )
        return DomainBreachesErrorResponse(Error=str(e))


@router.get(
    "/shield-on/{email}",
    response_model=ShieldActivationResponse,
    responses={
        200: {"model": ShieldActivationResponse},
        404: {"model": ShieldActivationErrorResponse},
    },
)
@limiter.limit("50 per day;10 per hour;2 per second")
async def activate_shield(
    request: Request, email: str
) -> Union[ShieldActivationResponse, ShieldActivationErrorResponse]:
    """
    Enable privacy shield for public searches and return status.

    """
    logging.info("[SHIELD-ON] Starting shield activation for email: %s", email)
    try:
        email = email.lower()
        if not email or not validate_email_with_tld(email) or not validate_url(request):
            logging.error("[SHIELD-ON] Invalid email or URL: %s", email)
            return ShieldActivationErrorResponse(Error="Not found")

        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", email)
        alert_task = datastore_client.get(alert_key)

        token_shield = await generate_confirmation_token(email)
        base_url = str(request.base_url)
        confirmation_url = f"{base_url}v1/verify-shield/{token_shield}"

        logging.debug("[SHIELD-ON] Generated confirmation URL: %s", confirmation_url)

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
                logging.info(
                    "[SHIELD-ON] Created new alert entity for email: %s", email
                )

            # Get client information
            client_ip = get_client_ip(request)
            preferred_ip = get_preferred_ip_address(client_ip)
            location = fetch_location_by_ip(preferred_ip) if preferred_ip else "Unknown"
            browser_type, client_platform = get_user_agent_info(request)

            logging.debug(
                "[DOMAIN-ALERT] Client info - IP: %s, Location: %s, Browser: %s, Platform: %s",
                client_ip,
                location,
                browser_type,
                client_platform,
            )

            # Send shield email
            try:
                await send_shield_email(
                    email,
                    confirmation_url,
                    f"{client_ip} ({location})",
                    browser_type,
                    client_platform,
                )
                logging.info("[SHIELD-ON] Shield email sent successfully to: %s", email)
            except Exception as e:
                logging.error("[SHIELD-ON] Failed to send shield email: %s", str(e))
                raise

            return ShieldActivationResponse(Success="ShieldAdded")

        if alert_task.get("shieldOn", False):
            logging.info("[SHIELD-ON] Shield already active for email: %s", email)
            return ShieldActivationResponse(Success="AlreadyOn")

        logging.error("[SHIELD-ON] Unexpected state for email: %s", email)
        return ShieldActivationErrorResponse(Error="Unexpected state")

    except Exception as e:
        logging.error("[SHIELD-ON] Error processing request: %s", str(e), exc_info=True)
        return ShieldActivationErrorResponse(Error=str(e))


@router.get(
    "/verify-shield/{token_shield}",
    response_class=HTMLResponse,
    responses={
        200: {"content": {"text/html": {}}},
        404: {"content": {"text/html": {}}},
    },
)
@limiter.limit("50 per day;10 per hour;2 per second")
async def verify_shield(request: Request, token_shield: str) -> HTMLResponse:
    """
    Verify privacy shield for public searches and return status.

    """
    logging.info(
        "[SHIELD-VERIFY] Starting shield verification for token: %s...",
        token_shield[:10],
    )
    try:
        if (
            not token_shield
            or not validate_variables([token_shield])
            or not validate_url(request)
        ):
            logging.error(
                "[SHIELD-VERIFY] Invalid token or URL: %s...", token_shield[:10]
            )
            return HTMLResponse(
                content=templates.TemplateResponse(
                    "email_shield_error.html", {"request": request}
                ).body.decode(),
                status_code=404,
            )

        email = await confirm_token(token_shield)
        if not email:
            logging.error("[SHIELD-VERIFY] Token confirmation failed")
            return HTMLResponse(
                content=templates.TemplateResponse(
                    "email_shield_error.html", {"request": request}
                ).body.decode(),
                status_code=404,
            )

        logging.info("[SHIELD-VERIFY] Token confirmed for email: %s", email)

        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", email)
        alert_task = datastore_client.get(alert_key)

        if alert_task:
            alert_task["shield_timestamp"] = datetime.datetime.now()
            alert_task["shieldOn"] = True
            datastore_client.put(alert_task)
            logging.info("[SHIELD-VERIFY] Updated existing alert for email: %s", email)
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
            logging.info("[SHIELD-VERIFY] Created new alert for email: %s", email)

        return HTMLResponse(
            content=templates.TemplateResponse(
                "email_shield_verify.html", {"request": request}
            ).body.decode(),
            status_code=200,
        )

    except Exception as e:
        logging.error(
            "[SHIELD-VERIFY] Error processing request: %s", str(e), exc_info=True
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

        # Create year dictionaries dynamically from 2025 down to 2007
        year_dicts = {
            str(year): {"children": [], "description": str(year)}
            for year in range(2025, 2006, -1)
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
                    f"<img src='{logo}' style='height:40px;width:65px;' />"
                    f"<a target='_blank' href='https://xposedornot.com/xposed/#{bid}'>"
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
                    f"<img src='{logo}' style='height:40px;width:65px;' />"
                    f"<a target='_blank' href='https://xposedornot.com/xposed/#{bid}'>"
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
        logging.error(
            "[BREACH-HIERARCHY] Error processing breaches: %s", str(e), exc_info=True
        )
        raise HTTPException(
            status_code=404, detail="Error processing breach data"
        ) from e


@router.get("/analytics/{user_email}", response_model=BreachHierarchyResponse)
@limiter.limit("500 per day;100 per hour;2 per second")
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

        if alert_record and alert_record.get("shieldOn"):
            raise ShieldOnException("Shield is on")

        if xon_record:
            site = str(xon_record["site"])
            breach_hierarchy = await get_breach_hierarchy_analytics(site, "")
            return BreachHierarchyResponse(**breach_hierarchy)

        return JSONResponse(content=None)

    except ShieldOnException:
        return JSONResponse(content={"Error": "Not found"}, status_code=404)

    except Exception as e:
        logging.error("[ANALYTICS] Error processing request: %s", str(e), exc_info=True)
        return JSONResponse(content={"Error": "Not found"}, status_code=404)
