"""Alert-related API endpoints."""

# Standard library imports
from datetime import datetime
import time

# Third-party imports
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from google.cloud import datastore
from google.api_core import exceptions as google_exceptions
from user_agents import parse

# Local imports
from models.responses import (
    AlertResponse,
    UnsubscribeResponse,
    VerificationResponse,
)
from services.analytics import get_breaches_analytics
from services.breach import get_breaches, get_exposure, get_sensitive_exposure
from services.send_email import send_alert_confirmation, send_exception_email, send_unsub_email
from utils.custom_limiter import custom_rate_limiter
from utils.helpers import fetch_location_by_ip, get_preferred_ip_address
from utils.token import confirm_token, generate_confirmation_token
from utils.validation import validate_email_with_tld, validate_url, validate_variables

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/alertme/{user_email}", response_model=AlertResponse)
@custom_rate_limiter("50 per day;5 per hour;2 per second")
async def subscribe_to_alert_me(
    user_email: str,
    request: Request,
):
    """Subscribe to alert-me notifications and send confirmation email."""
    try:
        user_email = user_email.lower()

        # Validation checks
        email_valid = validate_email_with_tld(user_email)
        url_valid = validate_url(request)

        if not user_email or not email_valid or not url_valid:
            return JSONResponse(
                status_code=400,
                content={"status": "Error", "message": "Invalid request"},
            )

        # Datastore operations
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)

        # Token generation
        verification_token = await generate_confirmation_token(user_email)
        base_url = str(request.base_url)
        confirmation_url = f"{base_url}v1/verifyme/{verification_token}"

        # Create/Update alert task
        if alert_task is None or not alert_task.get("verified", False):
            alert_task_data = datastore.Entity(
                datastore_client.key("xon_alert", user_email),
                exclude_from_indexes=[
                    "insert_timestamp",
                    "verify_timestamp",
                    "verified",
                    "unSubscribeOn",
                    "shieldOn",
                ],
            )
            if alert_task is None:
                alert_task_data.update(
                    {
                        "insert_timestamp": datetime.now(),
                        "verified": False,
                        "unSubscribeOn": False,
                        "shieldOn": False,
                    }
                )
                datastore_client.put(alert_task_data)

        # IP Address detection
        client_ip_address = None
        if "X-Forwarded-For" in request.headers:
            client_ip_address = request.headers["X-Forwarded-For"].split(",")[0].strip()
        elif "X-Real-IP" in request.headers:
            client_ip_address = request.headers["X-Real-IP"].strip()
        else:
            client_ip_address = request.client.host

        preferred_ip = get_preferred_ip_address(client_ip_address)
        location = fetch_location_by_ip(preferred_ip) if preferred_ip else "Unknown"

        # User agent parsing
        user_agent_string = request.headers.get("User-Agent")
        user_agent = parse(user_agent_string)
        browser_type = (
            f"{user_agent.browser.family} {user_agent.browser.version_string}"
        )
        client_platform = user_agent.os.family

        # Send confirmation email
        await send_alert_confirmation(
            user_email,
            confirmation_url,
            f"{preferred_ip} ({location})",
            browser_type,
            client_platform,
        )

        return AlertResponse(status="Success", message="Subscription Successful")

    except (
        ValueError,
        HTTPException,
        google_exceptions.GoogleAPIError,
    ) as exception_details:
        await send_exception_email(
            api_route=f"GET /v1/alertme/{user_email}",
            error_message=str(exception_details),
            exception_type=type(exception_details).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={user_email}",
        )
        raise HTTPException(status_code=404) from exception_details


@router.get("/verifyme/{verification_token}")
@custom_rate_limiter("50 per day;5 per hour;2 per second")
async def alert_me_verification(verification_token: str, request: Request):
    """Verify alert-me subscription and send initial leaks if any."""
    try:
        token_valid = validate_variables([verification_token])
        url_valid = validate_url(request)

        if not verification_token or not token_valid or not url_valid:
            raise HTTPException(status_code=404, detail="Not found")

        # Token confirmation
        user_email = await confirm_token(verification_token)
        if not user_email:
            raise HTTPException(status_code=404, detail="Not found")

        # Datastore operations
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)

        # Update alert task
        if alert_task["verified"]:
            max_retries = 5
            retry_count = 0
            while retry_count < max_retries:
                try:
                    with datastore_client.transaction():
                        alert_task["recent_timestamp"] = datetime.now()
                        alert_task["token"] = verification_token
                        datastore_client.put(alert_task)
                    break
                except (
                    google_exceptions.GoogleAPIError,
                    ValueError,
                    RuntimeError,
                ) as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        raise
                    wait_time = 2**retry_count * 0.1  # Exponential backoff
                    time.sleep(wait_time)
        else:
            max_retries = 5
            retry_count = 0
            while retry_count < max_retries:
                try:
                    with datastore_client.transaction():
                        alert_task["verify_timestamp"] = datetime.now()
                        alert_task["verified"] = True
                        alert_task["token"] = verification_token
                        datastore_client.put(alert_task)
                    break
                except (
                    google_exceptions.GoogleAPIError,
                    ValueError,
                    RuntimeError,
                ) as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        raise
                    wait_time = 2**retry_count * 0.1  # Exponential backoff
                    time.sleep(wait_time)

        exposure_info = await get_exposure(user_email)
        sensitive_exposure_info = await get_sensitive_exposure(user_email)

        has_exposure = bool(exposure_info.get("site", ""))
        has_sensitive_exposure = bool(sensitive_exposure_info.get("site", ""))

        if not has_exposure and not has_sensitive_exposure:
            return templates.TemplateResponse("email_verify.html", {"request": request})

        # If exposures are found
        base_url = "https://xposedornot.com/"
        email_param = f"email={user_email}"
        token_param = f"&token={verification_token}"
        breaches_link = f"{base_url}data-breaches-risks.html?{email_param}{token_param}"
        return templates.TemplateResponse(
            "email_success.html",
            {"request": request, "breaches_link": breaches_link},
        )

    except (google_exceptions.GoogleAPIError, ValueError, RuntimeError) as e:
        await send_exception_email(
            api_route="GET /v1/verifyme/{token}",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"token={verification_token}",
        )
        return templates.TemplateResponse("email_error.html", {"request": request})


@router.get("/send_verification", response_model=VerificationResponse)
@custom_rate_limiter("50 per day;10 per hour;2 per second")
async def send_verification(
    token: str = "None", email: str = None, request: Request = None
):
    """Verify and send confirmation for report access."""
    try:
        user_email = email.lower() if email else ""

        if (
            not validate_url(request)
            or not user_email
            or not validate_email_with_tld(user_email)
            or (token != "None" and not validate_variables([token]))
        ):
            return VerificationResponse(status="Failed")

        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)

        if alert_task["verified"] and alert_task["token"] == token:
            now = datetime.now()
            verification_timestamp = alert_task["verify_timestamp"]

            time_diff_hours = (now - verification_timestamp).total_seconds() / 3600

            if time_diff_hours < 24:
                ds_xon = datastore.Client()
                xon_key = ds_xon.key("xon", user_email)
                xon_record = ds_xon.get(xon_key)
                sensitive_site_breaches = ""
                breach_metrics = {}

                if xon_record is not None:
                    site = str(xon_record.get("site", ""))
                    sensitive_site = str(xon_record.get("sensitive_site", ""))

                    if site or sensitive_site:
                        sensitive_site_breaches = (
                            get_breaches(sensitive_site) if sensitive_site else ""
                        )
                        breach_metrics = (
                            await get_breaches_analytics(site, sensitive_site)
                            if site or sensitive_site
                            else {}
                        )

                    return VerificationResponse(
                        status="Success",
                        breaches=site,
                        breaches_details=sensitive_site_breaches,
                        breach_metrics=breach_metrics,
                    )

            return VerificationResponse(status="Failed")
        return VerificationResponse(status="Failed")

    except (
        ValueError,
        HTTPException,
        google_exceptions.GoogleAPIError,
    ) as exception_details:
        await send_exception_email(
            api_route="GET /v1/send_verification",
            error_message=str(exception_details),
            exception_type=type(exception_details).__name__,
            user_agent=request.headers.get("User-Agent") if request else "Unknown",
            request_params=f"email={email}, token={'provided' if token != 'None' else 'not_provided'}",
        )
        return VerificationResponse(status="Failed")


@router.get("/unsubscribe-on/{user_email}", response_model=UnsubscribeResponse)
@custom_rate_limiter("20 per day;5 per hour;2 per second")
async def unsubscribe(user_email: str, request: Request):
    """Initiates the unsubscription process for a user."""
    try:
        user_email = user_email.lower()
        # Validation checks
        if (
            not user_email
            or not validate_email_with_tld(user_email)
            or not validate_url(request)
        ):
            raise HTTPException(status_code=404, detail="Not found")

        # Datastore operations
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)

        if alert_task and alert_task.get("verified", True):
            # Generate unsubscribe token
            unsubscribe_token = await generate_confirmation_token(user_email)
            base_url = str(request.base_url)
            unsub_url = f"{base_url}v1/verify_unsub/{unsubscribe_token}"

            alert_task["unSubscribeOn"] = True
            alert_task["unsub_token"] = unsubscribe_token
            datastore_client.put(alert_task)

            # Send unsubscribe email
            await send_unsub_email(user_email, unsub_url)

        return UnsubscribeResponse(status="Success")

    except (
        ValueError,
        HTTPException,
        google_exceptions.GoogleAPIError,
    ) as exception_details:
        await send_exception_email(
            api_route=f"GET /v1/unsubscribe-on/{user_email}",
            error_message=str(exception_details),
            exception_type=type(exception_details).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={user_email}",
        )
        raise HTTPException(status_code=404, detail="Not found") from exception_details


@router.get("/verify_unsub/{unsubscribe_token}")
@custom_rate_limiter("20 per day;5 per hour;2 per second")
async def verify_unsubscribe(unsubscribe_token: str, request: Request):
    """Verify user's request to unsubscribe."""
    try:
        if (
            not unsubscribe_token
            or not validate_variables([unsubscribe_token])
            or not validate_url(request)
        ):
            raise HTTPException(status_code=404, detail="Not found")

        # Confirm token
        user_email = await confirm_token(unsubscribe_token)
        if not user_email:
            raise HTTPException(status_code=404, detail="Not found")

        # Datastore operations
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)

        if (
            alert_task
            and alert_task.get("unSubscribeOn", False)
            and alert_task.get("unsub_token") == unsubscribe_token
        ):
            # Delete user record from datastore
            datastore_client.delete(alert_key)

            return templates.TemplateResponse(
                "unsubscribe_success.html", {"request": request}
            )

        raise HTTPException(status_code=404, detail="Not found")

    except (
        ValueError,
        HTTPException,
        google_exceptions.GoogleAPIError,
    ) as exception_details:
        await send_exception_email(
            api_route="GET /v1/verify_unsub/{token}",
            error_message=str(exception_details),
            exception_type=type(exception_details).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"token={unsubscribe_token}",
        )
        raise HTTPException(status_code=404, detail="Not found") from exception_details
