"""Domain verification endpoints and utilities."""

# Standard library imports
import ipaddress
import re
import socket
import threading
from collections import defaultdict
from datetime import datetime
from typing import List, Union

# Third-party imports
import domcheck
import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from google.cloud import datastore
from google.api_core import exceptions as google_exceptions
from pydantic import EmailStr

# Local imports
from config.settings import XMLAPI_KEY
from models.base import BaseResponse
from services.send_email import (
    send_domain_confirmation,
    send_domain_verified_success,
    send_exception_email,
    send_domain_verification_admin_notification,
)
from utils.custom_limiter import custom_rate_limiter
from utils.request import get_client_ip, get_user_agent_info
from utils.token import generate_confirmation_token
from utils.validation import validate_email_with_tld, validate_variables

router = APIRouter()


def validate_domain(domain: str) -> bool:
    """Validate domain with a basic format check."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


class DomainVerificationResponse(BaseResponse):
    """Response model for domain verification."""

    domainVerification: Union[str, List[str]]


def create_new_record(
    domain: str, email: str, token: str, mode: str, datastore_client: datastore.Client
):
    """Creates a new domain record with the provided domain, email, token, and verification mode."""
    new_domain_record = datastore.Entity(
        datastore_client.key("xon_domains", f"{domain}_{email}")
    )
    new_domain_record.update(
        {
            "email": email,
            "domain": domain,
            "mode": mode,
            "token": token,
            "verified": True,
            "insert_timestamp": datetime.now(),
        }
    )
    datastore_client.put(new_domain_record)


async def send_domain_confirmation_email(
    email: str, token: str, ip_address: str, browser_type: str, client_platform: str
):
    """Sends domain confirmation email with verification details."""
    # In FastAPI, we'll need to handle URL generation differently
    confirm_url = f"/v1/domain_validation?token={token}"  # Adjust base URL as needed
    await send_domain_confirmation(
        email, confirm_url, ip_address, browser_type, client_platform
    )


def list_transactions_for_domain(client: datastore.Client, domain: str) -> List[dict]:
    """Fetch transactions for a given domain."""
    query = client.query(kind="xon")
    query.add_filter("domain", "=", domain)
    try:
        return list(query.fetch())
    except (google_exceptions.GoogleAPIError, ValueError):
        # Log error if needed but don't use unused variable
        return []


def process_single_domain(domain: str):
    """Processes transactions for a given domain and updates breach summaries."""
    client = datastore.Client()
    domain_transactions = list_transactions_for_domain(client, domain)

    breach_summary = defaultdict(int)
    details_entities = {}
    batch_size = 400

    if not domain_transactions:
        entity_key = client.key("xon_domains_summary", f"{domain}+No_Breaches")
        entity = datastore.Entity(key=entity_key)
        entity.update({"domain": domain, "breach": "No_Breaches", "email_count": 0})
        client.put(entity)
        return

    processed_count = 0

    for tx in domain_transactions:
        if not tx.get("site"):
            continue

        breaches = tx["site"].split(";")
        for breach in breaches:
            email_from_key = tx.key.name
            entity_key_name = f"{breach}_{email_from_key}"

            if entity_key_name not in details_entities:
                entity_key = client.key("xon_domains_details", entity_key_name)
                entity = datastore.Entity(key=entity_key)
                entity.update(
                    {
                        "breach_email": entity_key_name,
                        "domain": domain,
                        "breach": breach,
                        "email": email_from_key,
                    }
                )
                details_entities[entity_key_name] = entity
                breach_summary[(domain, breach)] += 1

            if len(details_entities) >= batch_size:
                client.put_multi(list(details_entities.values()))
                processed_count += len(details_entities)
                details_entities = {}

    if details_entities:
        client.put_multi(list(details_entities.values()))
        processed_count += len(details_entities)

    summary_entities = {}
    for (domain, breach), count in breach_summary.items():
        entity_key_name = f"{domain}+{breach}"
        entity_key = client.key("xon_domains_summary", entity_key_name)
        entity = datastore.Entity(key=entity_key)
        entity.update({"domain": domain, "breach": breach, "email_count": count})
        summary_entities[entity_key_name] = entity

        if len(summary_entities) >= batch_size:
            client.put_multi(list(summary_entities.values()))
            summary_entities = {}

    if summary_entities:
        client.put_multi(list(summary_entities.values()))


async def check_emails(domain: str) -> DomainVerificationResponse:
    """Check domain emails using WhoisXML API."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://www.whoisxmlapi.com/whoisserver/WhoisService?"
                f"apiKey={XMLAPI_KEY}&domainName={domain}&outputFormat=JSON",
                timeout=20,
            )

            if response.status_code != 200:
                return DomainVerificationResponse(
                    status="success",
                    domainVerification=["No email found. Try DNS/HTML Verifications"],
                )

            who_is = response.json()
            registrant_email = who_is.get("WhoisRecord", {}).get(
                "contactEmail",
                who_is.get("WhoisRecord", {})
                .get("registryData", {})
                .get("contactEmail", "No email found. Try DNS/HTML Verifications"),
            )

            # If we got a string email, convert to list
            if isinstance(registrant_email, str):
                if "," in registrant_email:
                    registrant_email = [
                        email.strip() for email in registrant_email.split(",")
                    ]
                else:
                    registrant_email = [registrant_email]

            # If we got no email or invalid format, return default message
            if not registrant_email or registrant_email == [
                "No email found. Try DNS/HTML Verifications"
            ]:
                return DomainVerificationResponse(
                    status="success",
                    domainVerification=["No email found. Try DNS/HTML Verifications"],
                )

            return DomainVerificationResponse(
                status="success", domainVerification=registrant_email
            )

    except Exception:
        return DomainVerificationResponse(
            status="success",
            domainVerification=["No email found. Try DNS/HTML Verifications"],
        )


async def verify_email(
    domain: str, email: str, request: Request
) -> DomainVerificationResponse:
    """Verify email against domain's WHOIS record."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://www.whoisxmlapi.com/whoisserver/WhoisService?"
                f"apiKey={XMLAPI_KEY}&domainName={domain}&outputFormat=JSON",
                timeout=20,
            )

            if response.status_code != 200:
                return DomainVerificationResponse(
                    status="error", domainVerification="Failure"
                )

            who_is = response.json()
            registrant_email = who_is.get("WhoisRecord", {}).get(
                "contactEmail", "No email found. Try DNS/HTML Verifications"
            )

            if email == registrant_email:
                datastore_client = datastore.Client()
                domain_key = datastore_client.key("xon_domains", f"{domain}_{email}")
                domain_record = datastore_client.get(domain_key)
                token = await generate_confirmation_token(email)

                if domain_record is None:
                    create_new_record(domain, email, token, "email", datastore_client)

                threading.Thread(target=process_single_domain, args=(domain,)).start()

                # Get client information
                client_ip_address = get_client_ip(request)
                browser_type, client_platform = get_user_agent_info(request)

                await send_domain_confirmation_email(
                    email, token, client_ip_address, browser_type, client_platform
                )

                # Send admin notification
                await send_domain_verification_admin_notification(domain)

                return DomainVerificationResponse(
                    status="success", domainVerification="Success"
                )

            return DomainVerificationResponse(
                status="error", domainVerification="Failure"
            )
    except (httpx.RequestError, httpx.HTTPError, ValueError) as err:
        return DomainVerificationResponse(status="error", domainVerification="Failure")


async def verify_dns(
    domain: str, email: str, code: str, prefix: str, request: Request
) -> DomainVerificationResponse:
    """Verify domain using DNS TXT record."""
    if not validate_email_with_tld(email) or not validate_variables([code]):
        return DomainVerificationResponse(status="error", domainVerification="Failure")

    if domcheck.check(domain, prefix, code, strategies="dns_txt"):
        datastore_client = datastore.Client()
        domain_key = datastore_client.key("xon_domains", f"{domain}_{email}")
        domain_record = datastore_client.get(domain_key)

        if domain_record is None:
            create_new_record(domain, email, code, "dns_txt", datastore_client)
        else:
            domain_record["last_verified"] = datetime.now()
            datastore_client.put(domain_record)

        threading.Thread(target=process_single_domain, args=(domain,)).start()

        client_ip_address = get_client_ip(request)
        browser_type, client_platform = get_user_agent_info(request)

        await send_domain_verified_success(
            email, client_ip_address, browser_type, client_platform
        )

        # Send admin notification
        await send_domain_verification_admin_notification(domain)

        return DomainVerificationResponse(
            status="success", domainVerification="Success"
        )

    return DomainVerificationResponse(status="error", domainVerification="Failure")


async def verify_html(
    domain: str, email: str, code: str, prefix: str, request: Request
) -> DomainVerificationResponse:
    """Verify domain using HTML file."""
    if not validate_email_with_tld(email) or not validate_variables([code]):
        return DomainVerificationResponse(status="error", domainVerification="Failure")

    if await check_file(domain, prefix, code):
        datastore_client = datastore.Client()
        domain_key = datastore_client.key("xon_domains", f"{domain}_{email}")
        domain_record = datastore_client.get(domain_key)

        if domain_record is None:
            create_new_record(domain, email, code, "html_file", datastore_client)
        else:
            domain_record["last_verified"] = datetime.now()
            datastore_client.put(domain_record)

        threading.Thread(target=process_single_domain, args=(domain,)).start()

        client_ip_address = get_client_ip(request)
        browser_type, client_platform = get_user_agent_info(request)

        await send_domain_verified_success(
            email, client_ip_address, browser_type, client_platform
        )

        # Send admin notification
        await send_domain_verification_admin_notification(domain)

        return DomainVerificationResponse(
            status="success", domainVerification="Success"
        )

    return DomainVerificationResponse(status="error", domainVerification="Failure")


def get_safe_domain_ip(domain: str) -> Union[str, None]:
    """
    Resolve domain and return a safe IP address if validation passes.

    Args:
        domain: The domain to check

    Returns:
        str: A validated public IP address, or None if domain is unsafe
    """
    try:
        # Resolve domain to IP addresses
        ip_addresses = socket.getaddrinfo(domain, None, socket.AF_INET)

        if not ip_addresses:
            return None

        # Check all resolved IPs - ALL must be safe
        validated_ips = []
        for result in ip_addresses:
            ip_str = result[4][0]
            ip = ipaddress.ip_address(ip_str)

            # Check if IP is private, loopback, link-local, multicast, or reserved
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
            ):
                return None

            validated_ips.append(ip_str)

        # Return the first validated IP
        return validated_ips[0] if validated_ips else None

    except (socket.gaierror, ValueError, OSError):
        # DNS resolution failed or invalid IP
        return None


async def check_file(domain: str, prefix: str, code: str) -> bool:
    """
    Supports domain verification using HTML file check process.

    This implementation prevents SSRF attacks by:
    1. Validating the domain resolves only to public IPs
    2. Using the validated IP directly in requests
    3. Preventing DNS rebinding attacks through IP pinning
    4. Disabling redirects to prevent redirect-based SSRF

    Args:
        domain: The domain to verify
        prefix: The prefix for the verification token
        code: The verification code

    Returns:
        bool: True if verification successful, False otherwise
    """
    if not validate_domain(domain) or not validate_variables([code]):
        return False

    # Resolve domain and validate IP is safe - this prevents SSRF
    validated_ip = get_safe_domain_ip(domain)
    if not validated_ip:
        return False

    headers = {
        "User-Agent": "XposedOrNot-DomainCheck 1.0 (+https://XposedOrNot.com)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
        "Accept-Encoding": "none",
        "Accept-Language": "en-US,en;q=0.8",
        "Connection": "keep-alive",
        "Host": domain,  # Set Host header for proper virtual host routing
    }

    # Use the validated IP directly in the URL to prevent DNS rebinding
    url = f"https://{validated_ip}/{code}.html"
    token = f"{prefix}={code}"

    try:
        limits = httpx.Limits(max_connections=1, max_keepalive_connections=0)

        async with httpx.AsyncClient(
            limits=limits,
            verify=False,  # Required when using IP directly; validates via Host header
            follow_redirects=False,  # Prevent redirect-based SSRF
            timeout=20,
        ) as client:
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.content[:1000]
                decoded_data = data.strip().decode("utf-8")

                if str(token.strip()) == str(decoded_data):
                    return True
            return False

    except (httpx.RequestError, httpx.HTTPError, ValueError):
        return False


@router.get("/domain_verification", response_model=DomainVerificationResponse)
@custom_rate_limiter("2 per second;20 per hour;50 per day")
async def domain_verification(
    request: Request,
    z: str = Query(..., description="Command type"),
    d: str = Query(..., description="Domain name"),
    a: EmailStr = Query("catch-all@xposedornot.com", description="Email address"),
    v: str = Query("xon-is-good", description="Verification code"),
):
    """Used for validating domain ownership/authority."""
    try:
        if not validate_variables([z, d, a, v]):
            raise HTTPException(status_code=400, detail="Invalid input")

        prefix = "xon_verification"
        if not validate_domain(d) or not validate_email_with_tld(a):
            raise HTTPException(status_code=404, detail="Not found")

        if z == "c":
            return await check_emails(d)
        elif z == "d":
            return await verify_email(d, a)
        elif z == "e":
            return await verify_dns(d, a, v, prefix, request)
        elif z == "a":
            return await verify_html(d, a, v, prefix, request)

        return DomainVerificationResponse(status="error", domainVerification="Failure")

    except Exception as e:
        await send_exception_email(
            api_route="GET /v1/domain_verification",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"command={z}, domain={d}, email={a}",
        )
        raise HTTPException(status_code=404, detail="Verification failed") from e
