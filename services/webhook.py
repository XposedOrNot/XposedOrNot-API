"""Generic (custom) webhook channel service: onboarding wrappers plus the
signed alert sender.

The onboarding functions are thin wrappers over ``services.messaging``.
``send_webhook_alert`` delivers breach alerts honouring the same signing
contract as the onboarding pings (``deliver_signed_webhook``).
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from fastapi import HTTPException

from config.clients import ds_client as datastore_client
from models.channels import ChannelSetupRequest
from services.messaging import (
    _decrypt_custom_headers,
    delete_messaging_channel,
    deliver_signed_webhook,
    get_channel_kind,
    get_webhook_channel_config as _get_webhook_channel_config,
    rotate_webhook_secret as _rotate_webhook_secret,
    setup_webhook_channel as _setup_webhook_channel,
    verify_webhook_channel as _verify_webhook_channel,
)
from utils.webhook_security import decrypt_webhook

logger = logging.getLogger(__name__)

MAX_CONSECUTIVE_FAILURES = 10
BREACH_ALERT_EVENT = "breach_alert"


async def setup_webhook_channel(
    channel_data: ChannelSetupRequest, email: str
) -> Tuple[bool, str]:
    """Set up a generic webhook channel. Returns (success, signing_secret)."""
    return await _setup_webhook_channel(channel_data, email)


async def verify_webhook_channel(channel_data: ChannelSetupRequest, email: str) -> bool:
    """Verify a generic webhook channel setup."""
    return await _verify_webhook_channel(channel_data, email)


async def rotate_webhook_secret(email: str) -> str:
    """Rotate the signing secret. Returns the new secret (shown once)."""
    return await _rotate_webhook_secret(email)


async def delete_webhook_channel(email: str) -> bool:
    """Delete a generic webhook channel configuration."""
    return await delete_messaging_channel("webhook", email)


async def get_webhook_channel_config(email: str) -> Optional[Dict]:
    """Get a generic webhook channel configuration (secrets masked)."""
    return await _get_webhook_channel_config(email)


def _load_delivery_target(email: str):
    """Return the raw channel entity if it is verified and active, else None."""
    key = datastore_client.key(get_channel_kind("webhook"), email)
    entity = datastore_client.get(key)
    if not entity or not entity.get("verified") or not entity.get("active"):
        return None
    return entity


def _record_delivery_outcome(entity, success: bool, error: Optional[str]) -> None:
    """Persist success/failure counters; auto-disable after repeated failures."""
    now = datetime.now(timezone.utc)
    if success:
        entity.update(
            {
                "consecutive_failures": 0,
                "last_delivered_at": now,
                "last_delivery_error": None,
                "updated_at": now,
            }
        )
    else:
        failures = int(entity.get("consecutive_failures", 0) or 0) + 1
        entity.update(
            {
                "consecutive_failures": failures,
                "last_delivery_error": (error or "unknown error")[:500],
                "updated_at": now,
            }
        )
        if failures >= MAX_CONSECUTIVE_FAILURES:
            entity.update({"active": False, "disabled_at": now})
            logger.warning(
                f"Webhook channel {entity.key.name} disabled after {failures} failures"
            )
    datastore_client.put(entity)


async def send_webhook_alert(
    domain: str, email: str, payload: Dict, event: str = BREACH_ALERT_EVENT
) -> bool:
    """Deliver a signed ``payload`` to the owner's verified webhook endpoint.

    Uses the same HMAC contract as the onboarding pings (``X-XON-Signature``,
    ``X-XON-Timestamp``, ``X-XON-Event``) and the same bounded retry policy.
    Returns False (never raises) so a sender loop can continue; failures are
    counted on the row and the channel is auto-disabled after
    ``MAX_CONSECUTIVE_FAILURES``.

    ``domain`` identifies the breach being announced; the channel itself is
    account-wide and looked up by ``email``.
    """
    entity = await asyncio.to_thread(_load_delivery_target, email)
    if entity is None:
        logger.info(f"No active webhook channel for owner={email}; skipping {domain}")
        return False

    try:
        webhook_url = decrypt_webhook(entity.get("webhook"))
        signing_secret = decrypt_webhook(entity.get("signing_secret"))
    except ValueError as exc:
        logger.error(f"Webhook channel for owner={email} is undecryptable: {exc}")
        await asyncio.to_thread(_record_delivery_outcome, entity, False, str(exc))
        return False
    custom_headers = _decrypt_custom_headers(entity.get("custom_headers"))

    try:
        await deliver_signed_webhook(
            webhook_url, payload, signing_secret, custom_headers, event=event
        )
    except HTTPException as exc:
        await asyncio.to_thread(
            _record_delivery_outcome, entity, False, str(exc.detail)
        )
        return False

    await asyncio.to_thread(_record_delivery_outcome, entity, True, None)
    return True
