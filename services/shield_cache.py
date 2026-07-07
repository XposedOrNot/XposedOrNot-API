"""Short-TTL Redis cache for the xon_alert privacy-shield flag.

The flag is written through on every in-app shield change, so activation
propagates immediately; the TTL only bounds staleness for out-of-band
Datastore writes. Reads fall back to None (caller must consult Datastore)
on any Redis problem - the shield check is never skipped.
"""

import hashlib
import logging
from typing import Optional

from config.clients import redis_client

logger = logging.getLogger(__name__)

SHIELD_CACHE_TTL_SECONDS = 60


def _shield_key(email: str) -> str:
    return f"shield:{hashlib.sha256(email.lower().encode()).hexdigest()[:16]}"


def get_cached_shield(email: str) -> Optional[bool]:
    """Return the cached shield flag, or None when unknown or unavailable."""
    try:
        value = redis_client.get(_shield_key(email))
        if value == "1":
            return True
        if value == "0":
            return False
    except Exception as exc:
        logger.warning("shield_cache read failed: %s", exc)
    return None


def set_cached_shield(email: str, shield_on: bool) -> None:
    """Record the shield flag; best-effort only."""
    try:
        redis_client.setex(
            _shield_key(email), SHIELD_CACHE_TTL_SECONDS, "1" if shield_on else "0"
        )
    except Exception as exc:
        logger.warning("shield_cache write failed: %s", exc)


def invalidate_cached_shield(email: str) -> None:
    """Drop the cached flag after a shield state change; best-effort only."""
    try:
        redis_client.delete(_shield_key(email))
    except Exception as exc:
        logger.warning("shield_cache invalidate failed: %s", exc)
