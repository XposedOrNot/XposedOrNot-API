"""Domain verification endpoints and utilities."""

# Standard library imports
import hashlib
import ipaddress
import re
import secrets
import socket
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Union

# Third-party imports
import domcheck
import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.templating import Jinja2Templates
from google.api_core import exceptions as google_exceptions
from google.cloud import datastore
from pydantic import EmailStr
from redis import RedisError

# Local imports
from config.clients import ds_client, redis_client
from config.settings import (
    BASE_URL,
    DOMAIN_EMAIL_DOMAIN_MAX_PER_HOUR,
    DOMAIN_EMAIL_GLOBAL_DAILY_BUDGET,
    DOMAIN_EMAIL_IP_MAX_PER_HOUR,
    DOMAIN_EMAIL_LIMITS_ENABLED,
    DOMAIN_EMAIL_RECIPIENT_COOLDOWN_SECONDS,
    WEBSITE_BASE_URL,
)
from models.base import BaseResponse
from services.send_email import (
    send_domain_confirmation,
    send_domain_verified_success,
    send_exception_email,
    send_domain_verification_admin_notification,
)
from services.seniority_enrichment import enrich_domain_seniority
from utils.custom_limiter import custom_rate_limiter
from utils.request import get_client_ip, get_user_agent_info
from utils.validation import validate_email_with_tld, validate_variables

router = APIRouter()
templates = Jinja2Templates(directory="templates")

DOMAIN_EMAIL_ROLES = ("security", "admin", "webmaster", "postmaster", "hostmaster")
DOMAIN_EMAIL_CHALLENGE_TTL_MINUTES = 30


def validate_domain(domain: str) -> bool:
    """Validate domain with a basic format check."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def get_domain_verification_emails(domain: str) -> List[str]:
    """Return the permitted role addresses for a validated domain."""
    normalized_domain = domain.strip().lower()
    if not validate_domain(normalized_domain):
        return []
    return [f"{role}@{normalized_domain}" for role in DOMAIN_EMAIL_ROLES]


def hash_domain_verification_token(token: str) -> str:
    """Return the datastore identifier for a domain verification token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class DomainVerificationResponse(BaseResponse):
    """Response model for domain verification."""

    domainVerification: Union[str, List[str]]


def create_new_record(
    domain: str,
    email: str,
    token: str,
    mode: str,
    datastore_client: datastore.Client,
    verified_via: str = None,
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
            "verified_via": verified_via,
        }
    )
    datastore_client.put(new_domain_record)


async def send_domain_confirmation_email(
    email: str,
    token: str,
    ip_address: str,
    browser_type: str,
    client_platform: str,
    recipient: str,
    domain: str,
):
    """Sends domain confirmation email with verification details."""
    confirm_url = f"{BASE_URL.rstrip('/')}/v1/domain_validation?token={token}"
    await send_domain_confirmation(
        email,
        confirm_url,
        ip_address,
        browser_type,
        client_platform,
        recipient,
        domain,
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
    client = ds_client
    domain_transactions = list_transactions_for_domain(client, domain)

    breach_summary = defaultdict(int)
    details_entities = {}
    batch_size = 400

    if not domain_transactions:
        entity_key = client.key("xon_domains_summary", f"{domain}+No_Breaches")
        entity = datastore.Entity(key=entity_key)
        entity.update({"domain": domain, "breach": "No_Breaches", "email_count": 0})
        client.put(entity)
        enrich_domain_seniority(domain)
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
    for (current_domain, breach), count in breach_summary.items():
        entity_key_name = f"{current_domain}+{breach}"
        entity_key = client.key("xon_domains_summary", entity_key_name)
        entity = datastore.Entity(key=entity_key)
        entity.update(
            {"domain": current_domain, "breach": breach, "email_count": count}
        )
        summary_entities[entity_key_name] = entity

        if len(summary_entities) >= batch_size:
            client.put_multi(list(summary_entities.values()))
            summary_entities = {}

    if summary_entities:
        client.put_multi(list(summary_entities.values()))

    enrich_domain_seniority(domain)


def start_domain_processing(domain: str) -> None:
    """Start asynchronous breach-summary processing for a verified domain."""
    threading.Thread(target=process_single_domain, args=(domain,)).start()


def _fixed_window_exceeded(key: str, limit: int, window_seconds: int) -> bool:
    """Increment a fixed-window counter and report whether it exceeds the limit."""
    count = redis_client.incr(key)
    if count == 1:
        redis_client.expire(key, window_seconds)
    return count > limit


def enforce_email_challenge_limits(domain: str, email: str, client_ip: str) -> None:
    """Guard verification emails against bombing via per-target and global limits.

    Applies a per-recipient cooldown, per-domain and per-IP hourly caps, and a
    global daily email budget. Fails open if Redis is unavailable so a cache
    outage cannot block legitimate verification.
    """
    if not DOMAIN_EMAIL_LIMITS_ENABLED:
        return
    try:
        if not redis_client.set(
            f"xon:dv:cooldown:rcpt:{email}",
            "1",
            nx=True,
            ex=DOMAIN_EMAIL_RECIPIENT_COOLDOWN_SECONDS,
        ):
            raise HTTPException(
                status_code=429,
                detail="Too many verification requests. Please try again later.",
            )
        if _fixed_window_exceeded(
            f"xon:dv:rate:domain:{domain}", DOMAIN_EMAIL_DOMAIN_MAX_PER_HOUR, 3600
        ):
            raise HTTPException(
                status_code=429,
                detail="Too many verification requests. Please try again later.",
            )
        if client_ip and _fixed_window_exceeded(
            f"xon:dv:rate:ip:{client_ip}", DOMAIN_EMAIL_IP_MAX_PER_HOUR, 3600
        ):
            raise HTTPException(
                status_code=429,
                detail="Too many verification requests. Please try again later.",
            )
        if _fixed_window_exceeded(
            "xon:dv:budget:global", DOMAIN_EMAIL_GLOBAL_DAILY_BUDGET, 86400
        ):
            raise HTTPException(
                status_code=429,
                detail="Too many verification requests. Please try again later.",
            )
    except RedisError:
        return


async def verify_email(
    domain: str, role_email: str, recipient: str, request: Request
) -> DomainVerificationResponse:
    """Send a verification challenge to an approved role address.

    The role address is a one-time proof target that must be one of the five
    permitted role mailboxes. The recipient is the domain owner / alert address
    that will own the verified domain and receive breach alerts; it must be a
    valid mailbox on the same domain so a single controlled role mailbox cannot
    route breach data off-domain.
    """
    normalized_domain = domain.strip().lower()
    normalized_role = role_email.strip().lower()
    normalized_recipient = recipient.strip().lower()
    if normalized_role not in get_domain_verification_emails(normalized_domain):
        return DomainVerificationResponse(status="error", domainVerification="Failure")

    if not validate_email_with_tld(normalized_recipient):
        return DomainVerificationResponse(status="error", domainVerification="Failure")
    if normalized_recipient.rsplit("@", 1)[-1] != normalized_domain:
        return DomainVerificationResponse(status="error", domainVerification="Failure")

    client_ip_address = get_client_ip(request)
    enforce_email_challenge_limits(
        normalized_domain, normalized_role, client_ip_address
    )

    token = secrets.token_urlsafe(32)
    token_hash = hash_domain_verification_token(token)
    datastore_client = ds_client
    challenge = datastore.Entity(
        datastore_client.key("xon_domain_verification_challenges", token_hash)
    )
    now = datetime.now(timezone.utc)
    challenge.update(
        {
            "domain": normalized_domain,
            "email": normalized_role,
            "recipient": normalized_recipient,
            "created_at": now,
            "expires_at": now + timedelta(minutes=DOMAIN_EMAIL_CHALLENGE_TTL_MINUTES),
            "used": False,
        }
    )
    datastore_client.put(challenge)

    browser_type, client_platform = get_user_agent_info(request)
    try:
        await send_domain_confirmation_email(
            normalized_role,
            token,
            client_ip_address,
            browser_type,
            client_platform,
            normalized_recipient,
            normalized_domain,
        )
    except HTTPException:
        datastore_client.delete(challenge.key)
        raise

    return DomainVerificationResponse(status="success", domainVerification="Success")


def _domain_verified_error(request: Request):
    """Render the friendly domain verification failure page."""
    return templates.TemplateResponse(
        request, "domain_verified_error.html", status_code=400
    )


@router.get("/domain_validation", response_model=None)
@custom_rate_limiter("2 per second;20 per hour;50 per day")
async def domain_validation(
    request: Request,
    token: str = Query(..., min_length=32, max_length=128),
):
    """Redeem a single-use domain email verification challenge."""
    token_hash = hash_domain_verification_token(token)
    datastore_client = ds_client
    challenge_key = datastore_client.key(
        "xon_domain_verification_challenges", token_hash
    )

    try:
        with datastore_client.transaction():
            challenge = datastore_client.get(challenge_key)
            if not challenge or challenge.get("used"):
                raise HTTPException(status_code=404, detail="Verification failed")

            expires_at = challenge.get("expires_at")
            if (
                not isinstance(expires_at, datetime)
                or datetime.now(timezone.utc) > expires_at
            ):
                raise HTTPException(status_code=404, detail="Verification failed")

            domain = challenge.get("domain", "")
            role_email = challenge.get("email", "")
            recipient = challenge.get("recipient", "")
            if not validate_domain(
                domain
            ) or role_email not in get_domain_verification_emails(domain):
                raise HTTPException(status_code=404, detail="Verification failed")
            if not validate_email_with_tld(recipient) or (
                recipient.rsplit("@", 1)[-1] != domain
            ):
                raise HTTPException(status_code=404, detail="Verification failed")

            domain_key = datastore_client.key("xon_domains", f"{domain}_{recipient}")
            domain_record = datastore_client.get(domain_key)
            if domain_record is None:
                create_new_record(
                    domain,
                    recipient,
                    token_hash,
                    "email",
                    datastore_client,
                    verified_via=role_email,
                )
            else:
                domain_record["last_verified"] = datetime.utcnow()
                datastore_client.put(domain_record)

            challenge["used"] = True
            challenge["used_at"] = datetime.now(timezone.utc)
            datastore_client.put(challenge)

        start_domain_processing(domain)

        client_ip_address = get_client_ip(request)
        browser_type, client_platform = get_user_agent_info(request)
        await send_domain_verified_success(
            recipient, client_ip_address, browser_type, client_platform
        )
        await send_domain_verification_admin_notification(domain)
        return templates.TemplateResponse(
            request,
            "domain_verified_success.html",
            context={
                "dashboard_url": f"{WEBSITE_BASE_URL.rstrip('/')}/my-dashboard.html"
            },
        )
    except HTTPException:
        return _domain_verified_error(request)
    except Exception as exc:
        await send_exception_email(
            api_route="GET /v1/domain_validation",
            error_message=str(exc),
            exception_type=type(exc).__name__,
            user_agent=request.headers.get("User-Agent"),
        )
        return _domain_verified_error(request)


async def verify_dns(
    domain: str, email: str, code: str, prefix: str, request: Request
) -> DomainVerificationResponse:
    """Verify domain using DNS TXT record."""
    if not validate_email_with_tld(email) or not validate_variables([code]):
        return DomainVerificationResponse(status="error", domainVerification="Failure")

    if domcheck.check(domain, prefix, code, strategies="dns_txt"):
        datastore_client = ds_client
        domain_key = datastore_client.key("xon_domains", f"{domain}_{email}")
        domain_record = datastore_client.get(domain_key)

        if domain_record is None:
            create_new_record(domain, email, code, "dns_txt", datastore_client)
        else:
            domain_record["last_verified"] = datetime.now()
            datastore_client.put(domain_record)

        start_domain_processing(domain)

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
        datastore_client = ds_client
        domain_key = datastore_client.key("xon_domains", f"{domain}_{email}")
        domain_record = datastore_client.get(domain_key)

        if domain_record is None:
            create_new_record(domain, email, code, "html_file", datastore_client)
        else:
            domain_record["last_verified"] = datetime.now()
            datastore_client.put(domain_record)

        start_domain_processing(domain)

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


def _is_safe_public_ip(ip) -> bool:
    """
    Return True only for routable public IPs (IPv4 or IPv6).

    IPv4-mapped IPv6 addresses (e.g. ``::ffff:127.0.0.1``) are unwrapped and the
    embedded IPv4 is validated, so they cannot be used to smuggle an internal
    target past the IPv4 checks.
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def get_safe_domain_ip(domain: str) -> Union[str, None]:
    """
    Resolve a domain (IPv4 and IPv6) and return a safe public IP to pin to.

    Strict policy: every resolved address across both families must be
    public/safe, otherwise the domain is rejected (prevents SSRF and
    DNS-rebinding via a mixed public/private record set). IPv4 is preferred
    when both families are available, falling back to IPv6.

    Args:
        domain: The domain to check

    Returns:
        str: A validated public IP address, or None if domain is unsafe
    """
    try:
        # Dual-stack resolve (A + AAAA records)
        ip_addresses = socket.getaddrinfo(
            domain, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )

        if not ip_addresses:
            return None

        ipv4_safe = []
        ipv6_safe = []
        for result in ip_addresses:
            ip_str = result[4][0]
            # Strip any IPv6 scope id (e.g. fe80::1%eth0) before parsing
            ip = ipaddress.ip_address(ip_str.split("%")[0])

            # Strict: a single unsafe address rejects the whole domain
            if not _is_safe_public_ip(ip):
                return None

            if ip.version == 4:
                ipv4_safe.append(ip_str)
            else:
                ipv6_safe.append(ip_str)

        # Prefer IPv4, fall back to IPv6
        if ipv4_safe:
            return ipv4_safe[0]
        if ipv6_safe:
            return ipv6_safe[0]
        return None

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
    # (bracket IPv6 literals for a valid URL authority)
    host = f"[{validated_ip}]" if ":" in validated_ip else validated_ip
    url = f"https://{host}/{code}.html"
    token = f"{prefix}={code}"

    try:
        limits = httpx.Limits(max_connections=1, max_keepalive_connections=0)

        async with httpx.AsyncClient(
            limits=limits,
            verify=True,
            follow_redirects=False,  # Prevent redirect-based SSRF
            timeout=20,
        ) as client:
            response = await client.get(
                url, headers=headers, extensions={"sni_hostname": domain}
            )

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
    r: EmailStr = Query("", description="Monitoring recipient email"),
):
    """Used for validating domain ownership/authority."""
    try:
        normalized_domain = d.strip().lower()
        normalized_email = str(a).strip().lower()
        if not validate_variables([z, normalized_domain, normalized_email, v]):
            raise HTTPException(status_code=400, detail="Invalid input")

        prefix = "xon_verification"
        if not validate_domain(normalized_domain) or not validate_email_with_tld(
            normalized_email
        ):
            raise HTTPException(status_code=404, detail="Not found")

        if z == "c":
            return DomainVerificationResponse(
                status="success",
                domainVerification=get_domain_verification_emails(normalized_domain),
            )
        if z == "d":
            return await verify_email(
                normalized_domain, normalized_email, str(r).strip().lower(), request
            )
        if z == "e":
            return await verify_dns(
                normalized_domain, normalized_email, v, prefix, request
            )
        if z == "a":
            return await verify_html(
                normalized_domain, normalized_email, v, prefix, request
            )

        return DomainVerificationResponse(status="error", domainVerification="Failure")

    except HTTPException:
        raise
    except Exception as e:
        await send_exception_email(
            api_route="GET /v1/domain_verification",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"command={z}, domain={d}, email={a}",
        )
        raise HTTPException(status_code=404, detail="Verification failed") from e
