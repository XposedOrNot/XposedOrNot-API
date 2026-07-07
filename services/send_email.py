#!/usr/bin/python
# -*- coding: utf-8 -*-

"""XposedOrNot Mailer Sub-module API module using Mailjet"""

# Standard library imports
import asyncio
import json
import logging
import os
import time
import socket
from typing import Dict, Any, Optional, List

# Third-party imports
import httpx
from fastapi import HTTPException

# Local imports
from utils.redaction import sanitize_log_text

logger = logging.getLogger(__name__)

# Mailjet configuration
MAILJET_API_KEY = os.environ.get("MAILJET_API_KEY")
MAILJET_API_SECRET = os.environ.get("MAILJET_API_SECRET")
MAILJET_SENDER_EMAIL = os.environ.get("MAILJET_SENDER_EMAIL")
MAILJET_SENDER_NAME = os.environ.get("MAILJET_SENDER_NAME")

API_KEY = os.environ["MJ_API_KEY"]
API_SECRET = os.environ["MJ_API_SECRET"]
FROM_EMAIL = "notifications@xposedornot.com"
FROM_NAME = "XposedOrNot Notifications"
MAILJET_API_URL = "https://api.mailjet.com/v3.1/send"


async def send_shield_email(
    email: str, confirm_url: str, ip_address: str, browser: str, platform: str
) -> Dict[str, Any]:
    """
    Sends initial XposedOrNot Shield Email

    """
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": email}],
                    "TemplateID": 320580,
                    "TemplateLanguage": True,
                    "Subject": "XposedOrNo: Privacy Shield Confirmation",
                    "Variables": {
                        "confirm_url": confirm_url,
                        "ip": ip_address,
                        "browser": browser,
                        "platform": platform,
                    },
                }
            ]
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=500, detail="Failed to send shield email"
                )
            return response.json()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Failed to send shield email"
        ) from e


async def send_alert_confirmation(
    email: str, confirm_url: str, ip_address: str, browser: str, platform: str
) -> Dict[str, Any]:
    """
    Sends XposedOrNot Alert Me Confirmation Email

    """
    try:
        # Check if API credentials are set
        if not API_KEY or not API_SECRET:
            raise HTTPException(
                status_code=500,
                detail="Email service configuration error: API credentials not set",
            )

        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": email}],
                    "TemplateID": 8115033,
                    "TemplateLanguage": True,
                    "Subject": "XposedOrNot: DataBreach Alert Me Confirmation",
                    "Variables": {
                        "confirm_url": confirm_url,
                        "ip": ip_address,
                        "browser": browser,
                        "platform": platform,
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            try:
                # Check connectivity
                try:
                    ip_address = socket.gethostbyname("api.mailjet.com")

                except socket.gaierror as e:
                    logging.error("Could not resolve api.mailjet.com: %s", str(e))

                response = await client.post(
                    MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
                )

                if response.status_code != 200:
                    raise HTTPException(
                        status_code=500, detail="Failed to send alert confirmation"
                    )
                return response.json()
            except httpx.ConnectError as e:
                error_msg = "Unable to connect to email service. "
                error_msg += "Check network connection and firewall settings."
                raise HTTPException(status_code=500, detail=error_msg) from e
            except httpx.TimeoutException as e:
                raise HTTPException(
                    status_code=500, detail="Email service timeout"
                ) from e
    except HTTPException:
        raise
    except Exception as e:
        logging.error("send_alert_confirmation failed: %s", sanitize_log_text(str(e)))
        raise HTTPException(
            status_code=500, detail="Failed to send alert confirmation"
        ) from e


async def send_alert_reminder(email: str, confirm_url: str) -> Dict[str, Any]:
    """
    Sends XposedOrNot Alert Me Confirmation Reminder Email

    """
    try:
        if not API_KEY or not API_SECRET:
            raise HTTPException(
                status_code=500,
                detail="Email service configuration error: API credentials not set",
            )

        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": email}],
                    "TemplateID": 8115137,
                    "TemplateLanguage": True,
                    "Subject": "XposedOrNot: Reminder - confirm your breach alerts",
                    "Variables": {
                        "confirm_url": confirm_url,
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            try:
                try:
                    socket.gethostbyname("api.mailjet.com")

                except socket.gaierror as e:
                    logging.error("Could not resolve api.mailjet.com: %s", str(e))

                response = await client.post(
                    MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
                )

                if response.status_code != 200:
                    raise HTTPException(
                        status_code=500, detail="Failed to send alert reminder"
                    )
                return response.json()
            except httpx.ConnectError as e:
                error_msg = "Unable to connect to email service. "
                error_msg += "Check network connection and firewall settings."
                raise HTTPException(status_code=500, detail=error_msg) from e
            except httpx.TimeoutException as e:
                raise HTTPException(
                    status_code=500, detail="Email service timeout"
                ) from e
    except HTTPException:
        raise
    except Exception as e:
        logging.error("send_alert_reminder failed: %s", sanitize_log_text(str(e)))
        raise HTTPException(
            status_code=500, detail="Failed to send alert reminder"
        ) from e


async def send_dashboard_email_confirmation(
    email: str, confirm_url: str, ip_address: str, browser: str, platform: str
) -> Dict[str, Any]:
    """
    Sends XposedOrNot dashboard-email Confirmation Email

    """
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [
                        {
                            "Email": email,
                        }
                    ],
                    "TemplateID": 4897532,
                    "TemplateLanguage": True,
                    "Subject": "XposedOrNot: Passwordless Databreach Dashboard",
                    "Variables": {
                        "confirm_url": confirm_url,
                        "ip": ip_address,
                        "browser": browser,
                        "platform": platform,
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=500, detail="Failed to send confirmation email"
                )
            return response.json()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Failed to send confirmation email"
        ) from e


# Module-level rate limiting state for the admin email alert
_error_count = 0
_last_error_time = 0.0
_RATE_LIMIT = 5
_ERROR_WINDOW = 60

# Fire-and-forget admin alert tasks (kept referenced so they are not GC'd)
_exception_alert_tasks: "set[asyncio.Task]" = set()


def log_exception(
    api_route: str,
    error_message: str,
    exception_type: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_params: Optional[str] = None,
) -> None:
    """
    Emit a structured error log for the exception.

    Cloud Logging ingests stdout, so this record feeds log-based metrics and
    Cloud Monitoring alert policies. PII/secrets are scrubbed before logging.
    """
    try:
        logger.error(
            "api_exception %s",
            json.dumps(
                {
                    "api_route": api_route,
                    "exception_type": exception_type or "Exception",
                    "error": sanitize_log_text(error_message)
                    or "No error message provided",
                    "user_agent": user_agent or "Unknown",
                    "request_params": sanitize_log_text(request_params) or "None",
                },
                default=str,
            ),
        )
    except Exception:
        pass


async def _send_exception_alert_email(
    api_route: str,
    error_message: Optional[str],
    exception_type: Optional[str],
    user_agent: Optional[str],
    request_params: Optional[str],
) -> None:
    """Send the admin exception alert email (best-effort, off the request path)."""
    # TODO: migrate this admin alert from Mailjet email to a Slack webhook.
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": "deva@xposedornot.com"}],
                    "TemplateID": 4318335,
                    "TemplateLanguage": True,
                    "Subject": "Xonnie API exception",
                    "Variables": {
                        "api": api_route,
                        "error_message": sanitize_log_text(error_message)
                        or "No error message provided",
                        "exception_type": exception_type or "Exception",
                        "user_agent": user_agent or "Unknown",
                        "request_params": sanitize_log_text(request_params) or "None",
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )
    except Exception:
        pass


async def send_exception_email(
    api_route: str,
    error_message: Optional[str] = None,
    exception_type: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_params: Optional[str] = None,
) -> None:
    """
    Record an API exception via structured logging and a rate-limited admin alert.

    The structured log is emitted synchronously (cheap, non-blocking) for Cloud
    Logging; the admin email alert is rate-limited and dispatched as a
    background task so it never holds up the request's error response.

    Args:
        api_route: The API route where the exception occurred (e.g., "GET /v1/check-email/{email}")
        error_message: The exception error message (optional)
        exception_type: The type of exception (e.g., "ValueError", "HTTPException") (optional)
        user_agent: The User-Agent header from the request (optional)
        request_params: Additional request parameters as a string (optional)
    """
    global _error_count, _last_error_time

    log_exception(
        api_route=api_route,
        error_message=error_message or "No error message provided",
        exception_type=exception_type,
        user_agent=user_agent,
        request_params=request_params,
    )

    current_time = time.time()

    if current_time - _last_error_time > _ERROR_WINDOW:
        _error_count = 0

    if _error_count >= _RATE_LIMIT:
        return

    _error_count += 1
    _last_error_time = current_time

    task = asyncio.create_task(
        _send_exception_alert_email(
            api_route, error_message, exception_type, user_agent, request_params
        )
    )
    _exception_alert_tasks.add(task)
    task.add_done_callback(_exception_alert_tasks.discard)


async def send_domain_confirmation(
    email: str, confirm_url: str, ip_address: str, browser: str, platform: str
) -> Dict[str, Any]:
    """
    Sends XposedOrNot domain Confirmation Email
    """
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": email}],
                    "TemplateID": 1625322,
                    "TemplateLanguage": True,
                    "Subject": "XposedOrNot: Domain Verification Confirmation",
                    "Variables": {
                        "confirm_url": confirm_url,
                        "ip": ip_address,
                        "browser": browser,
                        "platform": platform,
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=500, detail="Failed to send domain confirmation"
                )
            return response.json()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Failed to send domain confirmation"
        ) from e


async def send_unsub_email(email: str, confirm_url: str) -> Dict[str, Any]:
    """
    Sends XposedOrNot Unsubscribe Confirmation Email
    """
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": email}],
                    "TemplateID": 320586,
                    "TemplateLanguage": True,
                    "Subject": "XposedOrNot: Unsubscribe Confirmation",
                    "Variables": {
                        "confirm_url": confirm_url,
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=500, detail="Failed to send unsubscribe email"
                )
            return response.json()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Failed to send unsubscribe email"
        ) from e


async def send_domain_email(email: str, confirm_url: str) -> Dict[str, Any]:
    """
    Sends XposedOrNot Domain Email
    """
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": email}],
                    "TemplateID": 357300,
                    "TemplateLanguage": True,
                    "Subject": "XposedOrNot: Domain Verification",
                    "Variables": {
                        "confirm_url": confirm_url,
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=500, detail="Failed to send domain email"
                )
            return response.json()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Failed to send domain email"
        ) from e


async def send_alert_email(email: str, confirm_url: str) -> Dict[str, Any]:
    """
    Sends XposedOrNot Alert Email
    """
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": email}],
                    "TemplateID": 324635,
                    "TemplateLanguage": True,
                    "Subject": "XposedOrNot: DataBreach Alert",
                    "Variables": {
                        "confirm_url": confirm_url,
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=500, detail="Failed to send alert email"
                )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to send alert email") from e


async def send_subscribe_leaks_initial(email: str, confirm_url: str) -> Dict[str, Any]:
    """
    Sends XposedOrNot Subscribe Leaks Initial Email
    """
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": email}],
                    "TemplateID": 10886213,
                    "TemplateLanguage": True,
                    "Subject": "XposedOrNot: Subscribe to Leaks",
                    "Variables": {
                        "confirm_url": confirm_url,
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=500, detail="Failed to send initial leak email"
                )
            return response.json()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Failed to send initial leak email"
        ) from e


async def send_databreach_alertme(
    email: str,
    breach: str,
    date: str,
    description: str,
    confirm_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Sends XposedOrNot DataBreach Alert Me Email
    """
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": email}],
                    "TemplateID": 11789921,
                    "TemplateLanguage": True,
                    "Subject": "XposedOrNot: DataBreach Alert",
                    "Variables": {
                        "breach": breach,
                        "date": date,
                        "description": description,
                        "confirm_url": confirm_url if confirm_url else "",
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=500, detail="Failed to send databreach alert"
                )
            return response.json()
    except httpx.ConnectError as e:
        raise HTTPException(
            status_code=500, detail="Unable to connect to email service"
        ) from e
    except httpx.TimeoutException as e:
        raise HTTPException(status_code=500, detail="Email service timeout") from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Failed to send databreach alert"
        ) from e


async def send_domain_verified_success(
    email: str, ip_address: str, browser: str, platform: str
) -> Dict[str, Any]:
    """
    Sends XposedOrNot Domain Verified Success Email
    """
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": email}],
                    "TemplateID": 5893448,
                    "TemplateLanguage": True,
                    "Subject": "XposedOrNot: Domain Verified Success",
                    "Variables": {
                        "ip": ip_address,
                        "browser": browser,
                        "platform": platform,
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=500, detail="Failed to send verification success email"
                )
            return response.json()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Failed to send verification success email"
        ) from e


async def send_domain_verification_admin_notification(
    domain: str,
) -> Optional[Dict[str, Any]]:
    """
    Sends admin notification when a domain is successfully verified.

    Args:
        domain: The verified domain name

    Returns:
        Response JSON if successful, None otherwise
    """
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": "deva@xposedornot.com"}],
                    "TemplateID": 7472516,
                    "TemplateLanguage": True,
                    "Subject": "XON: Domain Successfully Verified",
                    "Variables": {
                        "api": "Domain Verification Success",
                        "error_message": domain,
                        "exception_type": "New Domain",
                        "user_agent": "N/A",
                        "request_params": "N/A",
                    },
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )
            return response.json() if response.status_code == 200 else None
    except Exception:
        # Silently fail - don't want notification failures to break verification
        return None
