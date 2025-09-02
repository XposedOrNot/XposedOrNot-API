#!/usr/bin/python
# -*- coding: utf-8 -*-

"""XposedOrNot Mailer Sub-module API module using Mailjet"""

# Standard library imports
import os
import time
import socket
from typing import Dict, Any, Optional, List

# Third-party imports
import httpx
from fastapi import HTTPException

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
                    "TemplateID": 275596,
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
        raise HTTPException(
            status_code=500, detail="Failed to send alert confirmation: " + str(e)
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


async def send_exception_email(api: str) -> Optional[Dict[str, Any]]:
    """
    Sends Exception email to admin

    """
    rate_limit = 5
    error_window = 60
    error_count = 0
    last_error_time = 0
    current_time = time.time()

    if current_time - last_error_time <= error_window:
        error_count += 1
        if error_count > rate_limit:
            return None
    else:
        error_count = 0
    last_error_time = current_time

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
                    "Variables": {"api": api},
                }
            ]
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(
                MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
            )
            return response.json() if response.status_code == 200 else None
    except Exception:
        return None


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


async def send_monthly_digest_email(
    email: str,
    original_user_email: str,
    user_exposures: List[Dict],
    new_breaches: List[Dict],
    month_year: str,
    user_domains: List[str],
    template_id: int = 999999,  # TODO: Replace with actual Mailjet template ID
) -> Dict[str, Any]:
    """
    Sends XposedOrNot Monthly Digest Email

    Args:
        email: Recipient email address (can be test email)
        original_user_email: Original user email for tracking
        user_exposures: List of user's breach exposures from last 6 months
        new_breaches: List of new breaches added in last month
        month_year: Current month and year (e.g., "August 2025")
        user_domains: List of user's validated domains
        template_id: Mailjet template ID for monthly digest
    """
    try:
        # Format user exposures for template
        formatted_exposures = []
        for exposure in user_exposures:
            formatted_exposures.append(
                {
                    "breach_name": exposure.get("breach_name", ""),
                    "breach_date": exposure.get("breach_date", ""),
                    "data_exposed": exposure.get("data_exposed", ""),
                    "records_count": exposure.get("records_count", 0),
                    "domain": exposure.get("domain", ""),
                }
            )

        # Format new breaches for template
        formatted_new_breaches = []
        for breach in new_breaches:
            formatted_new_breaches.append(
                {
                    "breach_name": breach.get("breach_name", ""),
                    "breach_date": breach.get("breach_date", ""),
                    "records_exposed": breach.get("records_exposed", 0),
                    "data_types": breach.get("data_types", ""),
                }
            )

        # Prepare email data
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [{"Email": email}],
                    "TemplateID": template_id,
                    "TemplateLanguage": True,
                    "Subject": f"🔒 New breaches detected – check your exposure "
                    f"({month_year.split()[0]} update)",
                    "Variables": {
                        "month_year": month_year,
                        "user_exposures": formatted_exposures,
                        "new_breaches": formatted_new_breaches,
                        "user_domains": user_domains,
                        "exposures_count": len(formatted_exposures),
                        "new_breaches_count": len(formatted_new_breaches),
                        "original_user_email": original_user_email,  # For debugging
                        "recipient_email": email,  # For debugging
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
                    status_code=500,
                    detail=f"Failed to send monthly digest email: {response.text}",
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
            status_code=500, detail=f"Failed to send monthly digest email: {str(e)}"
        ) from e


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
