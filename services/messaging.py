"""Common messaging service functionality (Slack, Teams, generic webhook).

Channels are owned by the verified domain owner (email) resolved by
``utils.channel_auth``; rows are keyed ``{owner_email}_{domain}``.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import string
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import httpx
from fastapi import HTTPException
from google.cloud import datastore

from config.clients import ds_client as datastore_client
from models.channels import ChannelSetupRequest
from utils.http_client import shared_http_client
from utils.webhook_security import (
    decrypt_webhook,
    encrypt_webhook,
    is_safe_public_url,
    validate_custom_headers,
    validate_generic_webhook_url,
    validate_slack_webhook_url,
    validate_teams_webhook_url,
)

logger = logging.getLogger(__name__)


def generate_verification_code(length: int = 8) -> str:
    """Generate a random verification code."""
    characters = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


async def send_slack_verification_message(
    webhook_url: str, verification_code: str, domain: str
) -> bool:
    """
    Send verification code to Slack channel via webhook.

    Args:
        webhook_url: The Slack webhook URL
        verification_code: The verification code to send
        domain: The domain being configured

    Returns:
        bool: True if message was sent successfully

    Raises:
        HTTPException: If webhook delivery fails
    """
    try:
        message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🔔 Welcome to XposedOrNot Data Breach Alerts!",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "*Verification Required*\n\nYour verification "
                            f"token for domain `{domain}` is:"
                        ),
                    },
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"```{verification_code}```"},
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "*What to do next?*\nCopy this token and paste it "
                            "back into your application to complete the "
                            "verification process."
                        ),
                    },
                },
                {"type": "divider"},
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                "Once verified, you'll receive real-time "
                                "breach notifications for your domain."
                            ),
                        }
                    ],
                },
            ]
        }

        async with shared_http_client() as client:
            response = await client.post(webhook_url, json=message)
            response.raise_for_status()

        logger.info(
            f"Successfully sent Slack verification message for domain: {domain}"
        )
        return True

    except httpx.HTTPError as e:
        logger.error(f"Failed to send Slack verification message: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail="Failed to send verification message to Slack. Please check your webhook URL.",
        ) from e


async def send_slack_success_message(webhook_url: str, domain: str) -> bool:
    """
    Send verification success confirmation to Slack channel.

    Args:
        webhook_url: The Slack webhook URL
        domain: The domain that was verified

    Returns:
        bool: True if message was sent successfully
    """
    try:
        message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "✅ Verification Successful!",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Your Slack channel is now successfully connected "
                            f"to *XposedOrNot* for domain `{domain}`."
                        ),
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "🔔 You will start receiving new data breach "
                            "notifications here."
                        ),
                    },
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                "Stay informed about security incidents "
                                "affecting your domain in real-time."
                            ),
                        }
                    ],
                },
            ]
        }

        async with shared_http_client() as client:
            response = await client.post(webhook_url, json=message)
            response.raise_for_status()

        logger.info(
            f"Successfully sent Slack verification success message for domain: {domain}"
        )
        return True

    except httpx.HTTPError as e:
        logger.error(f"Failed to send Slack success message: {str(e)}")
        return False


async def send_teams_verification_message(
    webhook_url: str, verification_code: str, domain: str
) -> bool:
    """
    Send verification code to Teams channel via webhook.

    Args:
        webhook_url: The Teams webhook URL
        verification_code: The verification code to send
        domain: The domain being configured

    Returns:
        bool: True if message was sent successfully

    Raises:
        HTTPException: If webhook delivery fails
    """
    try:
        if "api.powerplatform.com" in webhook_url:
            message = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "type": "AdaptiveCard",
                            "version": "1.4",
                            "body": [
                                {
                                    "type": "TextBlock",
                                    "text": "🔔 Welcome to XposedOrNot Data Breach Alerts!",
                                    "weight": "Bolder",
                                    "size": "Large",
                                    "color": "Accent",
                                },
                                {
                                    "type": "TextBlock",
                                    "text": "Verification Required",
                                    "weight": "Bolder",
                                    "size": "Medium",
                                    "spacing": "Medium",
                                },
                                {
                                    "type": "FactSet",
                                    "facts": [
                                        {"title": "Domain:", "value": domain},
                                        {
                                            "title": "Verification Code:",
                                            "value": verification_code,
                                        },
                                    ],
                                },
                                {
                                    "type": "TextBlock",
                                    "text": "**What to do next?**",
                                    "weight": "Bolder",
                                    "spacing": "Medium",
                                },
                                {
                                    "type": "TextBlock",
                                    "text": (
                                        "Copy this verification code and "
                                        "paste it back into your application "
                                        "to complete the verification "
                                        "process. Once verified, you'll "
                                        "receive real-time breach "
                                        "notifications for your domain."
                                    ),
                                    "wrap": True,
                                },
                            ],
                        },
                    }
                ],
            }
        else:
            message = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": "XposedOrNot Data Breach Alerts - Verification Required",
                "themeColor": "0078D4",
                "title": "🔔 Welcome to XposedOrNot Data Breach Alerts!",
                "sections": [
                    {
                        "activityTitle": "**Verification Required**",
                        "facts": [
                            {"name": "Domain:", "value": domain},
                            {
                                "name": "Verification Token:",
                                "value": f"**{verification_code}**",
                            },
                        ],
                        "text": (
                            "**What to do next?**\n\nCopy this token and "
                            "paste it back into your application to complete "
                            "the verification process.\n\nOnce verified, "
                            "you'll receive real-time breach notifications "
                            "for your domain."
                        ),
                    }
                ],
            }

        async with shared_http_client() as client:
            response = await client.post(webhook_url, json=message)
            response.raise_for_status()

        logger.info(
            f"Successfully sent Teams verification message for domain: {domain}"
        )
        return True

    except httpx.HTTPError as e:
        logger.error(f"Failed to send Teams verification message: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail="Failed to send verification message to Teams. Please check your webhook URL.",
        ) from e


async def send_teams_success_message(webhook_url: str, domain: str) -> bool:
    """
    Send verification success confirmation to Teams channel.

    Args:
        webhook_url: The Teams webhook URL
        domain: The domain that was verified

    Returns:
        bool: True if message was sent successfully
    """
    try:
        if "api.powerplatform.com" in webhook_url:
            message = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "type": "AdaptiveCard",
                            "version": "1.4",
                            "body": [
                                {
                                    "type": "TextBlock",
                                    "text": "✅ Verification Successful!",
                                    "weight": "Bolder",
                                    "size": "Large",
                                    "color": "Good",
                                },
                                {
                                    "type": "TextBlock",
                                    "text": (
                                        "Your Teams channel is now "
                                        "successfully connected to "
                                        f"**XposedOrNot** for domain `{domain}`."
                                    ),
                                    "wrap": True,
                                    "spacing": "Medium",
                                },
                                {
                                    "type": "TextBlock",
                                    "text": (
                                        "🔔 You will start receiving new data "
                                        "breach notifications here. Stay "
                                        "informed about security incidents "
                                        "affecting your domain in real-time."
                                    ),
                                    "wrap": True,
                                },
                            ],
                        },
                    }
                ],
            }
        else:
            message = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": "XposedOrNot Channel Verification Successful",
                "themeColor": "28a745",
                "title": "✅ Verification Successful!",
                "sections": [
                    {
                        "activityTitle": (
                            "Your Teams channel is now successfully connected "
                            f"to **XposedOrNot** for domain `{domain}`."
                        ),
                        "text": (
                            "🔔 You will start receiving new data breach "
                            "notifications here.\n\nStay informed about "
                            "security incidents affecting your domain in "
                            "real-time."
                        ),
                    }
                ],
            }

        async with shared_http_client() as client:
            response = await client.post(webhook_url, json=message)
            response.raise_for_status()

        logger.info(
            f"Successfully sent Teams verification success message for domain: {domain}"
        )
        return True

    except httpx.HTTPError as e:
        logger.error(f"Failed to send Teams success message: {str(e)}")
        return False


PLATFORM_MAP = {
    "slack": "xon_slack_channel",
    "teams": "xon_teams_channel",
    "webhook": "xon_webhook_channel",
}

CHANNEL_SOURCE = "community"

SERVICE_NAME = "XposedOrNot"


def _utcnow() -> datetime:
    """Timezone-aware current time (UTC)."""
    return datetime.now(timezone.utc)


def get_channel_kind(platform: str) -> str:
    """Get the datastore kind for a given platform."""
    kind = PLATFORM_MAP.get(platform)
    if not kind:
        raise HTTPException(status_code=400, detail=f"Invalid platform: {platform}")
    return kind


WEBHOOK_MAX_ATTEMPTS = 3
WEBHOOK_CONNECT_TIMEOUT = 5.0
WEBHOOK_TOTAL_TIMEOUT = 10.0
WEBHOOK_BACKOFF_BASE = 0.5
WEBHOOK_MAX_RETRY_AFTER = 5.0


def generate_signing_secret() -> str:
    """Generate a random per-webhook HMAC signing secret (hex)."""
    return secrets.token_hex(32)


def compute_webhook_signature(secret: str, timestamp: str, body: bytes) -> str:
    """
    Compute the payload signature delivered with every webhook.

    Signature = HMAC_SHA256(secret, f"{timestamp}." + body), hex-encoded.
    Sent to the owner as `X-XON-Signature: sha256=<hex>` with
    `X-XON-Timestamp: <timestamp>` so they can verify authenticity and reject
    replays.
    """
    message = f"{timestamp}.".encode() + body
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


async def deliver_signed_webhook(
    webhook_url: str,
    payload: Dict,
    signing_secret: str,
    custom_headers: Optional[Dict[str, str]],
    event: str,
) -> bool:
    """
    Deliver a signed JSON payload to an owner webhook with a bounded,
    transient-only retry policy.

    - HTTPS + SSRF re-check on every attempt (anti DNS-rebinding).
    - Redirects disabled (a 30x to an internal address is an SSRF bypass).
    - Retries only connection errors / timeouts / 5xx / 429 (respecting a capped
      Retry-After); never retries other 4xx (permanent client errors).
    - Bounded response read; small total time budget.

    Raises:
        HTTPException(400): if delivery ultimately fails (so onboarding does not
        activate an unreachable endpoint).
    """
    body_bytes = json.dumps(payload, separators=(",", ":")).encode()
    timeout = httpx.Timeout(WEBHOOK_TOTAL_TIMEOUT, connect=WEBHOOK_CONNECT_TIMEOUT)
    last_error = "unknown error"

    for attempt in range(1, WEBHOOK_MAX_ATTEMPTS + 1):
        safe, reason = await asyncio.to_thread(is_safe_public_url, webhook_url)
        if not safe:
            raise HTTPException(
                status_code=400, detail=f"Webhook URL rejected: {reason}"
            )

        timestamp = str(int(time.time()))
        signature = compute_webhook_signature(signing_secret, timestamp, body_bytes)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"{SERVICE_NAME}-Webhook/1.0",
            "X-XON-Event": event,
            "X-XON-Timestamp": timestamp,
            "X-XON-Signature": f"sha256={signature}",
        }
        if custom_headers:
            headers.update(custom_headers)

        retry_after: Optional[float] = None
        try:
            async with shared_http_client() as client:
                response = await client.post(
                    webhook_url, content=body_bytes, headers=headers, timeout=timeout
                )

            if response.status_code < 400:
                logger.info(
                    f"Delivered webhook '{event}' ping (status={response.status_code})"
                )
                return True

            last_error = f"endpoint returned HTTP {response.status_code}"
            if 400 <= response.status_code < 500 and response.status_code != 429:
                break

            header_value = response.headers.get("Retry-After")
            if header_value:
                try:
                    retry_after = min(float(header_value), WEBHOOK_MAX_RETRY_AFTER)
                except ValueError:
                    retry_after = None
        except httpx.HTTPError as exc:
            last_error = str(exc) or "connection error"

        if attempt < WEBHOOK_MAX_ATTEMPTS:
            backoff = (
                retry_after
                if retry_after is not None
                else WEBHOOK_BACKOFF_BASE * (2 ** (attempt - 1))
            )
            await asyncio.sleep(backoff)

    logger.warning(f"Failed to deliver webhook '{event}' ping: {last_error}")
    raise HTTPException(
        status_code=400,
        detail=f"Failed to deliver {event} to webhook after {WEBHOOK_MAX_ATTEMPTS} "
        f"attempt(s): {last_error}",
    )


async def send_webhook_verification_message(
    webhook_url: str,
    verification_code: str,
    domain: str,
    signing_secret: str,
    custom_headers: Optional[Dict[str, str]] = None,
) -> bool:
    """Deliver a signed verification payload to the owner webhook."""
    payload = {
        "event": "verification",
        "service": SERVICE_NAME,
        "domain": domain,
        "verification_code": verification_code,
        "message": (
            "Verify your XposedOrNot webhook channel by submitting this "
            "verification_code back to the API with action=verify."
        ),
    }
    return await deliver_signed_webhook(
        webhook_url, payload, signing_secret, custom_headers, event="verification"
    )


async def send_webhook_success_message(
    webhook_url: str,
    domain: str,
    signing_secret: str,
    custom_headers: Optional[Dict[str, str]] = None,
) -> bool:
    """Deliver a signed verification-success payload to the owner webhook."""
    payload = {
        "event": "verification_success",
        "service": SERVICE_NAME,
        "domain": domain,
        "message": (
            "Your XposedOrNot webhook channel is verified and active. You will "
            "start receiving signed data-breach notifications for this domain."
        ),
    }
    return await deliver_signed_webhook(
        webhook_url,
        payload,
        signing_secret,
        custom_headers,
        event="verification_success",
    )


async def setup_webhook_channel(
    channel_data: ChannelSetupRequest, email: str
) -> Tuple[bool, str]:
    """
    Set up (or reconfigure) a generic webhook channel for a domain.

    Behavior:
    - Brand-new channel: generate a signing secret, send a verification ping,
      store as unverified/inactive, and return the secret ONCE.
    - Existing but unverified, or verified with a CHANGED destination URL:
      re-send verification and reset to unverified/inactive (a destination
      change must re-prove control). The existing signing secret is preserved
      (rotate it explicitly via action=rotate_secret); it is NOT returned again.
    - Existing, verified, URL unchanged: update custom headers in place
      and keep the channel verified/active (no re-verification needed).

    Returns:
        Tuple[bool, str]: (success, signing_secret) — signing_secret is non-empty
        only when a brand-new secret was generated (show-once).
    """
    if not all([channel_data.domain, channel_data.webhook]):
        raise HTTPException(
            status_code=400,
            detail="Missing required fields: domain or webhook",
        )
    if not email:
        raise HTTPException(
            status_code=400,
            detail="Missing required parameter: email",
        )

    url_ok, url_reason = await asyncio.to_thread(
        validate_generic_webhook_url, channel_data.webhook
    )
    if not url_ok:
        raise HTTPException(status_code=400, detail=url_reason)

    headers_provided = channel_data.custom_headers is not None
    normalized_headers: Optional[Dict[str, str]] = None
    if headers_provided:
        headers_ok, headers_reason, normalized_headers = validate_custom_headers(
            channel_data.custom_headers
        )
        if not headers_ok:
            raise HTTPException(status_code=400, detail=headers_reason)

    kind = get_channel_kind("webhook")
    entity_key_name = f"{email}_{channel_data.domain}"
    channel_key = datastore_client.key(kind, entity_key_name)
    existing_entity = await asyncio.to_thread(datastore_client.get, channel_key)

    now = _utcnow()
    encrypted_webhook = encrypt_webhook(channel_data.webhook)
    if headers_provided:
        encrypted_headers = (
            encrypt_webhook(json.dumps(normalized_headers))
            if normalized_headers
            else None
        )
    else:
        encrypted_headers = (
            existing_entity.get("custom_headers") if existing_entity else None
        )
        normalized_headers = _decrypt_custom_headers(encrypted_headers)

    existing_url = None
    if existing_entity and existing_entity.get("webhook"):
        try:
            existing_url = decrypt_webhook(existing_entity.get("webhook"))
        except ValueError:
            existing_url = None
    is_verified = bool(existing_entity and existing_entity.get("verified"))
    url_unchanged = existing_url == channel_data.webhook

    if existing_entity and is_verified and url_unchanged:
        existing_entity.update(
            {
                "custom_headers": encrypted_headers,
                "updated_at": now,
            }
        )
        await asyncio.to_thread(datastore_client.put, existing_entity)
        logger.info(
            f"Updated verified webhook channel in place for "
            f"owner={email}, domain={channel_data.domain}"
        )
        return True, ""

    signing_secret_plain = ""
    if existing_entity and existing_entity.get("signing_secret"):
        signing_secret_enc = existing_entity.get("signing_secret")
        secret_for_signing = decrypt_webhook(signing_secret_enc)
        if not (existing_entity.get("verified") or existing_entity.get("verified_at")):
            signing_secret_plain = secret_for_signing
    else:
        secret_for_signing = generate_signing_secret()
        signing_secret_enc = encrypt_webhook(secret_for_signing)
        signing_secret_plain = secret_for_signing

    verification_code = generate_verification_code()
    channel_entity = datastore.Entity(key=channel_key)
    channel_entity.update(
        {
            "owner_email": email,
            "domain": channel_data.domain,
            "scope": "domain",
            "source": CHANNEL_SOURCE,
            "created_by": email,
            "webhook": encrypted_webhook,
            "custom_headers": encrypted_headers,
            "signing_secret": signing_secret_enc,
            "previous_signing_secret": (
                existing_entity.get("previous_signing_secret")
                if existing_entity
                else None
            ),
            "secret_rotated_at": (
                existing_entity.get("secret_rotated_at") if existing_entity else None
            ),
            "verify_token": verification_code,
            "verified": False,
            "active": False,
            "verified_at": (
                existing_entity.get("verified_at") if existing_entity else None
            ),
            "last_verification_error": None,
            "last_attempt_at": now,
            "consecutive_failures": 0,
            "disabled_at": None,
            "created_at": (
                existing_entity.get("created_at", now) if existing_entity else now
            ),
            "updated_at": now,
        }
    )

    try:
        await send_webhook_verification_message(
            channel_data.webhook,
            verification_code,
            channel_data.domain,
            secret_for_signing,
            normalized_headers,
        )
    except HTTPException as ping_exc:
        channel_entity["last_verification_error"] = str(ping_exc.detail)
        channel_entity["consecutive_failures"] = (
            existing_entity.get("consecutive_failures", 0) if existing_entity else 0
        ) + 1
        await asyncio.to_thread(datastore_client.put, channel_entity)
        logger.warning(
            f"Webhook verification ping failed for owner={email}, "
            f"domain={channel_data.domain}: {ping_exc.detail}"
        )
        raise

    await asyncio.to_thread(datastore_client.put, channel_entity)
    logger.info(
        f"Set up webhook channel for owner={email}, "
        f"domain={channel_data.domain} (re-verification required)"
    )
    return True, signing_secret_plain


async def verify_webhook_channel(channel_data: ChannelSetupRequest, email: str) -> bool:
    """Verify a webhook channel using the code delivered to the endpoint."""
    if not all([channel_data.domain, channel_data.verify_token]):
        raise HTTPException(
            status_code=400,
            detail="Missing required fields: domain or verify_token",
        )
    if not email:
        raise HTTPException(status_code=400, detail="Missing required parameter: email")

    kind = get_channel_kind("webhook")
    entity_key_name = f"{email}_{channel_data.domain}"
    channel_key = datastore_client.key(kind, entity_key_name)
    channel_entity = await asyncio.to_thread(datastore_client.get, channel_key)

    if not channel_entity:
        raise HTTPException(
            status_code=404,
            detail=f"Webhook channel not found for domain {channel_data.domain}",
        )

    if channel_entity.get("owner_email") != email:
        raise HTTPException(status_code=403, detail="Channel belongs to another owner")

    stored_verify_token = channel_entity.get("verify_token")
    if not stored_verify_token:
        raise HTTPException(
            status_code=400,
            detail="Channel not set up properly. Please run setup again.",
        )

    if not hmac.compare_digest(
        str(stored_verify_token), str(channel_data.verify_token)
    ):
        raise HTTPException(status_code=403, detail="Invalid verification code")

    now = _utcnow()
    channel_entity.update(
        {
            "verified": True,
            "active": True,
            "verified_at": now,
            "updated_at": now,
            "consecutive_failures": 0,
            "disabled_at": None,
            "last_verification_error": None,
        }
    )
    await asyncio.to_thread(datastore_client.put, channel_entity)
    logger.info(
        f"Verified webhook channel for owner={email}, domain={channel_data.domain}"
    )

    try:
        encrypted_webhook = channel_entity.get("webhook")
        signing_secret_enc = channel_entity.get("signing_secret")
        if encrypted_webhook and signing_secret_enc:
            await send_webhook_success_message(
                decrypt_webhook(encrypted_webhook),
                channel_data.domain,
                decrypt_webhook(signing_secret_enc),
                _decrypt_custom_headers(channel_entity.get("custom_headers")),
            )
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(f"Failed to send webhook success message: {str(exc)}")

    return True


async def rotate_webhook_secret(channel_data: ChannelSetupRequest, email: str) -> str:
    """Async wrapper: sync Datastore work runs off the event loop."""
    return await asyncio.to_thread(_rotate_webhook_secret_sync, channel_data, email)


def _rotate_webhook_secret_sync(channel_data: ChannelSetupRequest, email: str) -> str:
    """
    Rotate a webhook channel's signing secret with an overlap grace window.

    The current secret is moved to `previous_signing_secret` (kept for
    receivers still switching over) and a new secret is generated and
    returned ONCE. The channel stays verified/active.
    """
    if not channel_data.domain:
        raise HTTPException(status_code=400, detail="Missing required field: domain")
    if not email:
        raise HTTPException(status_code=400, detail="Missing required parameter: email")

    kind = get_channel_kind("webhook")
    entity_key_name = f"{email}_{channel_data.domain}"
    channel_key = datastore_client.key(kind, entity_key_name)
    channel_entity = datastore_client.get(channel_key)

    if not channel_entity:
        raise HTTPException(status_code=404, detail="Webhook channel not found")

    if channel_entity.get("owner_email") != email:
        raise HTTPException(status_code=403, detail="Channel belongs to another owner")

    now = _utcnow()
    new_secret = generate_signing_secret()
    channel_entity.update(
        {
            "previous_signing_secret": channel_entity.get("signing_secret"),
            "signing_secret": encrypt_webhook(new_secret),
            "secret_rotated_at": now,
            "updated_at": now,
        }
    )
    datastore_client.put(channel_entity)
    logger.info(
        f"Rotated webhook signing secret for owner={email}, "
        f"domain={channel_data.domain}"
    )
    return new_secret


def _decrypt_custom_headers(encrypted_headers: Optional[str]) -> Dict[str, str]:
    """Decrypt the stored custom-headers JSON; return {} on absence/failure."""
    if not encrypted_headers:
        return {}
    try:
        return json.loads(decrypt_webhook(encrypted_headers))
    except Exception:  # pylint: disable=broad-except
        return {}


async def get_webhook_channel_config(domain: str, email: str) -> Optional[Dict]:
    """Async wrapper: sync Datastore work runs off the event loop."""
    return await asyncio.to_thread(_get_webhook_channel_config_sync, domain, email)


def _get_webhook_channel_config_sync(domain: str, email: str) -> Optional[Dict]:
    """
    Get a webhook channel's configuration (masked).

    Security: the signing secret and custom-header VALUES are never returned —
    only presence flags / header names. The signing secret is shown once at
    setup/rotation.
    """
    if not all([domain, email]):
        raise HTTPException(
            status_code=400, detail="Missing required fields: domain or email"
        )

    kind = get_channel_kind("webhook")
    entity_key_name = f"{email}_{domain}"
    channel_key = datastore_client.key(kind, entity_key_name)
    channel_entity = datastore_client.get(channel_key)

    if not channel_entity:
        return None

    encrypted_webhook = channel_entity.get("webhook")
    decrypted_webhook = None
    if encrypted_webhook:
        try:
            decrypted_webhook = decrypt_webhook(encrypted_webhook)
        except ValueError as exc:
            logger.error(f"Failed to decrypt webhook for {domain}: {str(exc)}")

    custom_header_keys: List[str] = list(
        _decrypt_custom_headers(channel_entity.get("custom_headers")).keys()
    )

    created_at = channel_entity.get("created_at")
    updated_at = channel_entity.get("updated_at")
    verified_at = channel_entity.get("verified_at")
    secret_rotated_at = channel_entity.get("secret_rotated_at")
    disabled_at = channel_entity.get("disabled_at")

    return {
        "email": channel_entity.get("owner_email") or channel_entity.get("created_by"),
        "domain": channel_entity.get("domain"),
        "scope": channel_entity.get("scope", "domain"),
        "created_by": channel_entity.get("created_by"),
        "webhook": decrypted_webhook,
        "verified": channel_entity.get("verified", False),
        "active": channel_entity.get("active", False),
        "signing_secret_set": bool(channel_entity.get("signing_secret")),
        "custom_header_keys": custom_header_keys,
        "consecutive_failures": channel_entity.get("consecutive_failures", 0),
        "last_verification_error": channel_entity.get("last_verification_error"),
        "created_at": created_at.isoformat() if created_at else None,
        "updated_at": updated_at.isoformat() if updated_at else None,
        "verified_at": verified_at.isoformat() if verified_at else None,
        "secret_rotated_at": (
            secret_rotated_at.isoformat() if secret_rotated_at else None
        ),
        "disabled_at": disabled_at.isoformat() if disabled_at else None,
    }


async def setup_messaging_channel(
    channel_data: ChannelSetupRequest, platform: str, email: str
) -> Tuple[bool, str]:
    """
    Set up a messaging channel for a given platform (Slack or Teams).

    Args:
        channel_data: Channel setup data including domain and webhook.
        platform: The messaging platform ('slack' or 'teams').
        email: Verified domain owner resolved by utils.channel_auth.

    Returns:
        Tuple[bool, str]: (success, verification_code)
    """
    if not all([channel_data.domain, channel_data.webhook]):
        raise HTTPException(
            status_code=400,
            detail="Missing required fields: domain or webhook",
        )

    if not email:
        raise HTTPException(
            status_code=400,
            detail="Missing required parameter: email",
        )

    kind = get_channel_kind(platform)
    entity_key_name = f"{email}_{channel_data.domain}"
    channel_key = datastore_client.key(kind, entity_key_name)
    existing_entity = await asyncio.to_thread(datastore_client.get, channel_key)

    if existing_entity:
        is_verified = existing_entity.get("verified", False)
        if is_verified:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"{platform.capitalize()} channel already configured and "
                    f"verified for domain {channel_data.domain}. Please "
                    "delete the existing channel first if you want to "
                    "reconfigure."
                ),
            )
        logger.info(
            f"Re-initializing unverified {platform} channel for "
            f"owner={email}, domain={channel_data.domain}"
        )

    if platform == "slack":
        if not validate_slack_webhook_url(channel_data.webhook):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Invalid Slack webhook URL format. Must be "
                    "https://hooks.slack.com/services/..."
                ),
            )
    elif platform == "teams":
        if not validate_teams_webhook_url(channel_data.webhook):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Invalid Teams webhook URL format. Must be from "
                    "outlook.office.com, webhook.office.com, or "
                    "api.powerplatform.com"
                ),
            )

    try:
        encrypted_webhook = encrypt_webhook(channel_data.webhook)
    except ValueError as e:
        logger.warning(f"Invalid webhook URL provided: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail="Invalid webhook URL format. Please provide a valid webhook URL.",
        ) from e

    verification_code = generate_verification_code()

    if platform == "slack":
        await send_slack_verification_message(
            channel_data.webhook, verification_code, channel_data.domain
        )
    elif platform == "teams":
        await send_teams_verification_message(
            channel_data.webhook, verification_code, channel_data.domain
        )

    channel_entity = datastore.Entity(key=channel_key)

    now = _utcnow()
    channel_entity.update(
        {
            "owner_email": email,
            "domain": channel_data.domain,
            "scope": "domain",
            "source": CHANNEL_SOURCE,
            "created_by": email,
            "webhook": encrypted_webhook,
            "verify_token": verification_code,
            "verified": False,
            "active": False,
            "created_at": now,
            "updated_at": now,
        }
    )
    await asyncio.to_thread(datastore_client.put, channel_entity)
    logger.info(
        f"Successfully set up {platform} channel for owner={email}, "
        f"domain={channel_data.domain}, sent verification code to channel"
    )
    return True, ""


async def verify_messaging_channel(
    channel_data: ChannelSetupRequest, platform: str, email: str
) -> bool:
    """
    Verify a messaging channel for a given platform.

    Args:
        channel_data: Channel verification data.
        platform: The messaging platform ('slack' or 'teams').
        email: Verified domain owner resolved by utils.channel_auth.

    Returns:
        bool: True if verification was successful.
    """
    if not all([channel_data.domain, channel_data.verify_token]):
        raise HTTPException(
            status_code=400,
            detail="Missing required fields: domain or verify_token",
        )

    if not email:
        raise HTTPException(status_code=400, detail="Missing required parameter: email")

    kind = get_channel_kind(platform)
    entity_key_name = f"{email}_{channel_data.domain}"
    channel_key = datastore_client.key(kind, entity_key_name)
    channel_entity = await asyncio.to_thread(datastore_client.get, channel_key)

    if not channel_entity:
        detail = f"{platform.capitalize()} channel not found for domain {channel_data.domain}"
        raise HTTPException(status_code=404, detail=detail)

    if channel_entity.get("owner_email") != email:
        raise HTTPException(status_code=403, detail="Channel belongs to another owner")

    stored_verify_token = channel_entity.get("verify_token")
    if not stored_verify_token:
        raise HTTPException(
            status_code=400,
            detail="Channel not set up properly. Please run setup again.",
        )

    if not hmac.compare_digest(
        str(stored_verify_token), str(channel_data.verify_token)
    ):
        raise HTTPException(status_code=403, detail="Invalid verification code")

    now = _utcnow()
    channel_entity.update(
        {
            "verified": True,
            "active": True,
            "verified_at": now,
            "updated_at": now,
        }
    )
    await asyncio.to_thread(datastore_client.put, channel_entity)
    logger.info(
        f"Successfully verified {platform} channel for owner={email}, domain={channel_data.domain}"
    )

    try:
        encrypted_webhook = channel_entity.get("webhook")
        if encrypted_webhook:
            decrypted_webhook = decrypt_webhook(encrypted_webhook)

            if platform == "slack":
                await send_slack_success_message(decrypted_webhook, channel_data.domain)
            elif platform == "teams":
                await send_teams_success_message(decrypted_webhook, channel_data.domain)
    except Exception as e:  # pylint: disable=broad-except
        logger.error(f"Failed to send success message to {platform}: {str(e)}")

    return True


async def get_channel_config(domain: str, email: str, platform: str) -> Optional[Dict]:
    """Async wrapper: sync Datastore work runs off the event loop."""
    return await asyncio.to_thread(_get_channel_config_sync, domain, email, platform)


def _get_channel_config_sync(domain: str, email: str, platform: str) -> Optional[Dict]:
    """
    Get channel configuration for a given platform.

    Args:
        domain: The domain to get configuration for.
        email: Verified domain owner resolved by utils.channel_auth.
        platform: The messaging platform ('slack' or 'teams').

    Returns:
        Optional[Dict]: Channel configuration if found (with decrypted webhook).
    """
    if not all([domain, email]):
        raise HTTPException(
            status_code=400, detail="Missing required fields: domain or email"
        )

    kind = get_channel_kind(platform)
    entity_key_name = f"{email}_{domain}"
    channel_key = datastore_client.key(kind, entity_key_name)
    channel_entity = datastore_client.get(channel_key)

    if not channel_entity:
        return None

    encrypted_webhook = channel_entity.get("webhook")
    decrypted_webhook = None
    if encrypted_webhook:
        try:
            decrypted_webhook = decrypt_webhook(encrypted_webhook)
        except ValueError as e:
            logger.error(f"Failed to decrypt webhook for {domain}: {str(e)}")
            decrypted_webhook = None

    created_at = channel_entity.get("created_at")
    updated_at = channel_entity.get("updated_at")
    verified_at = channel_entity.get("verified_at")

    return {
        "email": channel_entity.get("owner_email") or channel_entity.get("created_by"),
        "domain": channel_entity.get("domain"),
        "created_by": channel_entity.get("created_by"),
        "webhook": decrypted_webhook,
        "verified": channel_entity.get("verified", False),
        "active": channel_entity.get("active", False),
        "created_at": created_at.isoformat() if created_at else None,
        "updated_at": updated_at.isoformat() if updated_at else None,
        "verified_at": verified_at.isoformat() if verified_at else None,
    }


async def delete_messaging_channel(
    channel_data: ChannelSetupRequest, platform: str, email: str
) -> bool:
    """Async wrapper: sync Datastore work runs off the event loop."""
    return await asyncio.to_thread(
        _delete_messaging_channel_sync, channel_data, platform, email
    )


def _delete_messaging_channel_sync(
    channel_data: ChannelSetupRequest, platform: str, email: str
) -> bool:
    """
    Delete a messaging channel for a given platform.

    Args:
        channel_data: Channel data for deletion.
        platform: The messaging platform ('slack' or 'teams').
        email: Verified domain owner resolved by utils.channel_auth.

    Returns:
        bool: True if deletion was successful.
    """
    if not channel_data.domain:
        raise HTTPException(status_code=400, detail="Missing required field: domain")

    if not email:
        raise HTTPException(status_code=400, detail="Missing required parameter: email")

    kind = get_channel_kind(platform)
    entity_key_name = f"{email}_{channel_data.domain}"
    channel_key = datastore_client.key(kind, entity_key_name)
    channel_entity = datastore_client.get(channel_key)

    if not channel_entity:
        raise HTTPException(
            status_code=404, detail=f"{platform.capitalize()} channel not found"
        )

    if channel_entity.get("owner_email") != email:
        raise HTTPException(status_code=403, detail="Channel belongs to another owner")

    datastore_client.delete(channel_key)
    logger.info(
        f"Successfully deleted {platform} channel for owner={email}, domain={channel_data.domain}"
    )
    return True
