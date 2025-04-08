"""Alert-related API endpoints."""

# Standard library imports
from datetime import datetime
import logging
import sys
import time

# Third-party imports
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from google.cloud import datastore
from slowapi import Limiter
from slowapi.util import get_remote_address
from user_agents import parse

# Local imports
from models.responses import (
    AlertResponse,
    UnsubscribeResponse,
    VerificationResponse,
)
from services.analytics import get_breaches_analytics
from services.breach import get_breaches, get_exposure, get_sensitive_exposure
from services.send_email import send_alert_confirmation, send_unsub_email
from utils.helpers import fetch_location_by_ip, get_preferred_ip_address
from utils.token import confirm_token, generate_confirmation_token
from utils.validation import validate_email_with_tld, validate_url, validate_variables

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
templates = Jinja2Templates(directory="templates")


@router.get("/alertme/{user_email}", response_model=AlertResponse)
@limiter.limit("50 per day;5 per hour;2 per second")
async def subscribe_to_alert_me(
    user_email: str,
    request: Request,
):
    """Subscribe to alert-me notifications and send confirmation email."""
    try:
        logger.debug(
            "[ALERT] Starting alert-me subscription process for email: %s", user_email
        )
        user_email = user_email.lower()

        # Validation checks
        logger.debug("[ALERT] Performing validation checks for email: %s", user_email)
        email_valid = validate_email_with_tld(user_email)
        url_valid = validate_url(request)
        logger.debug(
            "[ALERT] Validation results - Email valid: %s, URL valid: %s",
            email_valid,
            url_valid,
        )

        if not user_email or not email_valid or not url_valid:
            logger.warning("[ALERT] Validation failed for email: %s", user_email)
            return JSONResponse(
                status_code=400,
                content={"status": "Error", "message": "Invalid request"},
            )

        # Datastore operations
        logger.debug("[ALERT] Accessing datastore for email: %s", user_email)
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)
        logger.debug("[ALERT] Existing alert task found: %s", alert_task is not None)

        # Token generation
        logger.debug("[ALERT] Generating confirmation token for email: %s", user_email)
        verification_token = await generate_confirmation_token(user_email)
        base_url = str(request.base_url)
        confirmation_url = f"{base_url}v1/verifyme/{verification_token}"
        logger.debug("[ALERT] Generated confirmation URL: %s", confirmation_url)

        # Create/Update alert task
        if alert_task is None or not alert_task.get("verified", False):
            logger.debug("[ALERT] Creating new alert task for email: %s", user_email)
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
                logger.debug(
                    "[ALERT] Initializing new alert task data for email: %s", user_email
                )
                alert_task_data.update(
                    {
                        "insert_timestamp": datetime.now(),
                        "verified": False,
                        "unSubscribeOn": False,
                        "shieldOn": False,
                    }
                )
                datastore_client.put(alert_task_data)
                logger.debug(
                    "[ALERT] New alert task created and stored for email: %s",
                    user_email,
                )

        # IP Address detection
        logger.debug("[ALERT] Detecting client IP address for email: %s", user_email)
        client_ip_address = None
        if "X-Forwarded-For" in request.headers:
            client_ip_address = request.headers["X-Forwarded-For"].split(",")[0].strip()
            logger.debug("[ALERT] IP from X-Forwarded-For: %s", client_ip_address)
        elif "X-Real-IP" in request.headers:
            client_ip_address = request.headers["X-Real-IP"].strip()
            logger.debug("[ALERT] IP from X-Real-IP: %s", client_ip_address)
        else:
            client_ip_address = request.client.host
            logger.debug("[ALERT] IP from request.client.host: %s", client_ip_address)

        preferred_ip = get_preferred_ip_address(client_ip_address)
        location = fetch_location_by_ip(preferred_ip) if preferred_ip else "Unknown"
        logger.debug("[ALERT] Resolved location for IP %s: %s", preferred_ip, location)

        # User agent parsing
        logger.debug("[ALERT] Parsing user agent for email: %s", user_email)
        user_agent_string = request.headers.get("User-Agent")
        user_agent = parse(user_agent_string)
        browser_type = (
            f"{user_agent.browser.family} {user_agent.browser.version_string}"
        )
        client_platform = user_agent.os.family
        logger.debug(
            "[ALERT] User agent details - Browser: %s, Platform: %s",
            browser_type,
            client_platform,
        )

        # Send confirmation email
        logger.debug("[ALERT] Sending confirmation email to: %s", user_email)
        await send_alert_confirmation(
            user_email,
            confirmation_url,
            f"{preferred_ip} ({location})",
            browser_type,
            client_platform,
        )
        logger.debug("[ALERT] Confirmation email sent successfully to: %s", user_email)

        return AlertResponse(status="Success", message="Subscription Successful")

    except (ValueError, HTTPException, datastore.exceptions.GoogleAPIError) as exception_details:
        logger.error(
            "[ALERT] Error processing request: %s",
            str(exception_details),
            exc_info=True,
        )
        raise HTTPException(status_code=404) from exception_details


@router.get("/verifyme/{verification_token}")
@limiter.limit("50 per day;5 per hour;2 per second")
async def alert_me_verification(verification_token: str, request: Request):
    """Verify alert-me subscription and send initial leaks if any."""
    try:
        logger.debug(
            "[VERIFY] Starting verification process for token: %s", verification_token
        )

        logger.debug("[VERIFY] Performing validation checks")
        token_valid = validate_variables([verification_token])
        url_valid = validate_url(request)
        logger.debug(
            "[VERIFY] Validation results - Token valid: %s, URL valid: %s",
            token_valid,
            url_valid,
        )

        if not verification_token or not token_valid or not url_valid:
            logger.warning(
                "[VERIFY] Validation failed for token: %s", verification_token
            )
            raise HTTPException(status_code=404, detail="Not found")

        # Token confirmation
        logger.debug("[VERIFY] Confirming token: %s", verification_token)
        user_email = await confirm_token(verification_token)
        if not user_email:
            logger.warning("[VERIFY] Invalid token: %s", verification_token)
            raise HTTPException(status_code=404, detail="Not found")
        logger.debug("[VERIFY] Token confirmed for email: %s", user_email)

        # Datastore operations
        logger.debug("[VERIFY] Accessing datastore for email: %s", user_email)
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)
        logger.debug("[VERIFY] Alert task found: %s", alert_task is not None)

        # Update alert task
        if alert_task["verified"]:
            logger.debug(
                "[VERIFY] Updating existing verified alert for email: %s", user_email
            )
            max_retries = 5
            retry_count = 0
            while retry_count < max_retries:
                try:
                    with datastore_client.transaction():
                        alert_task["recent_timestamp"] = datetime.now()
                        alert_task["token"] = verification_token
                        datastore_client.put(alert_task)
                    break
                except (datastore.exceptions.GoogleAPIError, ValueError, RuntimeError) as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        logger.error("[VERIFY] Max retries reached: %s", str(e))
                        raise
                    wait_time = 2**retry_count * 0.1  # Exponential backoff
                    logger.warning(
                        "[VERIFY] Retrying transaction (attempt %s): %s",
                        retry_count,
                        str(e),
                    )
                    time.sleep(wait_time)
        else:
            logger.debug("[VERIFY] Marking alert as verified for email: %s", user_email)
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
                except (datastore.exceptions.GoogleAPIError, ValueError, RuntimeError) as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        logger.error("[VERIFY] Max retries reached: %s", str(e))
                        raise
                    wait_time = 2**retry_count * 0.1  # Exponential backoff
                    logger.warning(
                        "[VERIFY] Retrying transaction (attempt %s): %s",
                        retry_count,
                        str(e),
                    )
                    time.sleep(wait_time)

        logger.debug("[VERIFY] Checking exposures for email: %s", user_email)
        exposure_info = await get_exposure(user_email)
        sensitive_exposure_info = await get_sensitive_exposure(user_email)

        has_exposure = bool(exposure_info.get("site", ""))
        has_sensitive_exposure = bool(sensitive_exposure_info.get("site", ""))
        logger.debug(
            "[VERIFY] Exposure check results - Regular: %s, Sensitive: %s",
            has_exposure,
            has_sensitive_exposure,
        )

        if not has_exposure and not has_sensitive_exposure:
            logger.debug("[VERIFY] No exposures found for email: %s", user_email)
            return templates.TemplateResponse("email_verify.html", {"request": request})

        # If exposures are found
        logger.debug(
            "[VERIFY] Exposures found for email: %s, generating breach report link",
            user_email,
        )
        base_url = "https://xposedornot.com/"
        email_param = f"email={user_email}"
        token_param = f"&token={verification_token}"
        breaches_link = f"{base_url}data-breaches-risks.html?{email_param}{token_param}"
        logger.debug("[VERIFY] Generated breach report link: %s", breaches_link)
        return templates.TemplateResponse(
            "email_success.html",
            {"request": request, "breaches_link": breaches_link},
        )

    except (ValueError, HTTPException, datastore.exceptions.GoogleAPIError) as exception_details:
        logger.error(
            "[VERIFY] Error processing request: %s",
            str(exception_details),
            exc_info=True,
        )
        return templates.TemplateResponse("email_error.html", {"request": request})


@router.get("/send_verification", response_model=VerificationResponse)
@limiter.limit("50 per day;10 per hour;2 per second")
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
                        sensitive_breach_details=sensitive_site_breaches,
                        BreachMetrics=breach_metrics,
                    )

            return VerificationResponse(status="Failed")
        return VerificationResponse(status="Failed")

    except (ValueError, HTTPException, datastore.exceptions.GoogleAPIError) as exception_details:
        logger.error(
            "[ALERT] Error processing request: %s",
            str(exception_details),
            exc_info=True,
        )
        return VerificationResponse(status="Failed")


@router.get("/unsubscribe-on/{user_email}", response_model=UnsubscribeResponse)
@limiter.limit("20 per day;5 per hour;2 per second")
async def unsubscribe(user_email: str, request: Request):
    """Unsubscribe from alerts and return status."""
    try:
        logger.debug("[UNSUB] Starting unsubscribe process for email: %s", user_email)
        user_email = user_email.lower()

        # Validation checks
        logger.debug("[UNSUB] Performing validation checks for email: %s", user_email)
        email_valid = validate_email_with_tld(user_email)
        url_valid = validate_url(request)
        logger.debug(
            "[UNSUB] Validation results - Email valid: %s, URL valid: %s",
            email_valid,
            url_valid,
        )

        if not user_email or not email_valid or not url_valid:
            logger.warning("[UNSUB] Validation failed for email: %s", user_email)
            return UnsubscribeResponse(status="Error", message="Not found")

        # Datastore operations
        logger.debug("[UNSUB] Accessing datastore for email: %s", user_email)
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)
        logger.debug("[UNSUB] Alert task found: %s", alert_task is not None)

        if alert_task is None or not alert_task.get("unSubscribeOn", False):
            logger.debug(
                "[UNSUB] Creating/updating unsubscribe task for email: %s", user_email
            )
            task_entity = datastore.Entity(
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
                task_entity.update({"unSubscribeOn": False})
                datastore_client.put(task_entity)

            # Generate unsubscribe token and URL
            logger.debug(
                "[UNSUB] Generating unsubscribe token for email: %s", user_email
            )
            unsubscribe_token = await generate_confirmation_token(user_email)
            base_url = str(request.base_url)
            confirm_url = f"{base_url}v1/verify_unsub/{unsubscribe_token}"
            logger.debug("[UNSUB] Generated confirmation URL: %s", confirm_url)

            # Send unsubscribe email
            logger.debug("[UNSUB] Sending unsubscribe email to: %s", user_email)
            await send_unsub_email(user_email, confirm_url)
            logger.debug("[UNSUB] Unsubscribe email sent successfully")

            return UnsubscribeResponse(status="Success", message="UnSubscribed")

        if alert_task.get("unSubscribeOn", False):
            logger.debug("[UNSUB] Email already unsubscribed: %s", user_email)
            return UnsubscribeResponse(status="Success", message="AlreadyUnSubscribed")

        logger.warning("[UNSUB] Invalid state for email: %s", user_email)
        return UnsubscribeResponse(status="Error", message="Not found")

    except (ValueError, HTTPException, datastore.exceptions.GoogleAPIError) as exception_details:
        logger.error(
            "[UNSUB] Error processing request: %s",
            str(exception_details),
            exc_info=True,
        )
        return UnsubscribeResponse(status="Error", message="Not found")


@router.get("/verify_unsub/{unsubscribe_token}")
@limiter.limit("20 per day;5 per hour;2 per second")
async def verify_unsubscribe(unsubscribe_token: str, request: Request):
    """Returns response based on verification for unsubscribe token."""
    try:
        logger.debug(
            "[VERIFY_UNSUB] Starting verification for token: %s", unsubscribe_token
        )

        # Validation checks
        logger.debug("[VERIFY_UNSUB] Performing validation checks")
        token_valid = validate_variables([unsubscribe_token])
        url_valid = validate_url(request)
        logger.debug(
            "[VERIFY_UNSUB] Validation results - Token valid: %s, URL valid: %s",
            token_valid,
            url_valid,
        )

        if not unsubscribe_token or not token_valid or not url_valid:
            logger.warning(
                "[VERIFY_UNSUB] Validation failed for token: %s", unsubscribe_token
            )
            return templates.TemplateResponse(
                "email_unsub_error.html", {"request": request}
            )

        # Token confirmation and datastore update
        logger.debug("[VERIFY_UNSUB] Confirming token: %s", unsubscribe_token)
        user_email = await confirm_token(unsubscribe_token)
        if not user_email:
            logger.warning("[VERIFY_UNSUB] Invalid token: %s", unsubscribe_token)
            return templates.TemplateResponse(
                "email_unsub_error.html", {"request": request}
            )

        logger.debug("[VERIFY_UNSUB] Accessing datastore for email: %s", user_email)
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)

        if alert_task and alert_task.get("unSubscribeOn", False):
            logger.debug("[VERIFY_UNSUB] Email already unsubscribed: %s", user_email)
            return templates.TemplateResponse(
                "email_unsub_error.html", {"request": request}
            )

        logger.debug(
            "[VERIFY_UNSUB] Updating unsubscribe status for email: %s", user_email
        )
        max_retries = 5
        retry_count = 0
        while retry_count < max_retries:
            try:
                with datastore_client.transaction():
                    alert_task["unSubscribe_timestamp"] = datetime.now()
                    alert_task["unSubscribeOn"] = True
                    datastore_client.put(alert_task)
                logger.debug("[VERIFY_UNSUB] Successfully updated unsubscribe status")
                break  # Break the loop if successful
            except (datastore.exceptions.GoogleAPIError, ValueError, RuntimeError) as e:
                retry_count += 1
                if retry_count >= max_retries:
                    logger.error("[VERIFY_UNSUB] Max retries reached: %s", str(e))
                    raise
                wait_time = 2**retry_count * 0.1  # Exponential backoff
                logger.warning(
                    "[VERIFY_UNSUB] Retrying transaction (attempt %s): %s",
                    retry_count,
                    str(e),
                )
                time.sleep(wait_time)

        return templates.TemplateResponse(
            "email_unsub_verify.html", {"request": request}
        )

    except (ValueError, HTTPException, datastore.exceptions.GoogleAPIError) as exception_details:
        logger.error(
            "[VERIFY_UNSUB] Error processing request: %s",
            str(exception_details),
            exc_info=True,
        )
        return templates.TemplateResponse(
            "email_unsub_error.html", {"request": request}
        )
