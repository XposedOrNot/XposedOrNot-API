"""Owner resolution and domain-ownership checks for notification-channel routes.

A notification channel belongs to the verified owner of a domain, proven one
of two ways (both already exist in this codebase):

1. ``x-api-key`` header  -> ``xon_api_key`` row (key name = owner email).
2. ``email`` + ``token``  -> dashboard magic-link session in
   ``xon_domains_session`` (``utils.token.validate_dashboard_session``).

The owner must then hold a verified ``xon_domains`` row for the domain.
"""

import asyncio
import logging
from typing import Optional

from fastapi import HTTPException, Request
from google.cloud import datastore

from config.clients import ds_client
from utils.token import validate_dashboard_session
from utils.validation import validate_email_with_tld, validate_token

logger = logging.getLogger(__name__)

MAX_SESSION_TOKEN_LENGTH = 512


def _email_for_api_key(api_key: str, client: datastore.Client) -> Optional[str]:
    """Return the owner email for a regular (xon_api_key) API key, else None."""
    query = client.query(kind="xon_api_key")
    query.add_filter("api_key", "=", api_key)
    results = list(query.fetch(limit=1))
    if not results:
        return None
    return results[0].key.name


def _resolve_owner_sync(
    api_key: Optional[str],
    email: Optional[str],
    token: Optional[str],
    client: datastore.Client,
) -> str:
    """Blocking half of resolve_domain_owner (runs off the event loop)."""
    if api_key:
        api_key = api_key.strip()
        if not api_key or not validate_token(api_key):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
        owner = _email_for_api_key(api_key, client)
        if not owner or not validate_email_with_tld(owner):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
        return owner.strip().lower()

    if email and token:
        email = email.strip().lower()
        if not validate_email_with_tld(email) or len(token) > MAX_SESSION_TOKEN_LENGTH:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        if not validate_dashboard_session(client, email, token):
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        return email

    raise HTTPException(
        status_code=401,
        detail="Authentication required: send an x-api-key header or email + token",
    )


async def resolve_domain_owner(
    request: Request, email: Optional[str], token: Optional[str]
) -> str:
    """Return the authenticated owner email or raise HTTPException(401).

    The API key header wins when present; otherwise the dashboard session
    (email + token) is checked.
    """
    api_key = request.headers.get("x-api-key")
    return await asyncio.to_thread(
        _resolve_owner_sync, api_key, email, token, ds_client
    )


def _owns_verified_domain_sync(
    email: str, domain: str, client: datastore.Client
) -> bool:
    """True when ``email`` holds a verified ``xon_domains`` row for ``domain``."""
    entity = client.get(client.key("xon_domains", f"{domain}_{email}"))
    if entity and entity.get("verified"):
        return True

    query = client.query(kind="xon_domains")
    query.add_filter("email", "=", email)
    query.add_filter("domain", "=", domain)
    query.add_filter("verified", "=", True)
    try:
        return len(list(query.fetch(limit=1))) > 0
    except Exception:  # pylint: disable=broad-except
        logger.exception("xon_domains ownership query failed")
        return False


async def verify_domain_ownership(email: str, domain: str) -> bool:
    """Async wrapper: Datastore work runs off the event loop."""
    if not email or not domain:
        return False
    return await asyncio.to_thread(
        _owns_verified_domain_sync,
        email.strip().lower(),
        domain.strip().lower(),
        ds_client,
    )
