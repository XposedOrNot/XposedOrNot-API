"""In-process cache for the xon_breaches catalog."""

import copy
import logging
import threading
import time
from typing import Any, Dict, Optional

from config.clients import ds_client, redis_client

logger = logging.getLogger(__name__)

CATALOG_TTL_SECONDS = 900
REFRESH_FAILURE_BACKOFF_SECONDS = 30

_catalog: Optional[Dict[str, Any]] = None
_loaded_at: float = 0.0
_next_attempt_at: float = 0.0
_refresh_lock = threading.Lock()


def _refresh_catalog() -> None:
    """Load the full xon_breaches kind into the in-process catalog."""
    global _catalog, _loaded_at
    query = ds_client.query(kind="xon_breaches")
    fresh = {entity.key.name: entity for entity in query.fetch()}
    _catalog = fresh
    _loaded_at = time.monotonic()
    logger.info("breach_catalog refreshed: %d breaches", len(fresh))


def _get_catalog() -> Optional[Dict[str, Any]]:
    """Return the catalog dict, refreshing it when stale.

    Serves stale data while another thread refreshes, backs off after a
    failed refresh so requests never queue behind repeated full-kind
    query attempts, and returns None if the catalog has never been
    loaded successfully so callers fall back to direct Datastore reads.
    """
    global _next_attempt_at
    now = time.monotonic()
    if _catalog is not None and now - _loaded_at < CATALOG_TTL_SECONDS:
        return _catalog
    if now < _next_attempt_at:
        return _catalog

    if _refresh_lock.acquire(blocking=_catalog is None):
        try:
            now = time.monotonic()
            if now >= _next_attempt_at and (
                _catalog is None or now - _loaded_at >= CATALOG_TTL_SECONDS
            ):
                try:
                    _refresh_catalog()
                except Exception as exc:
                    _next_attempt_at = (
                        time.monotonic() + REFRESH_FAILURE_BACKOFF_SECONDS
                    )
                    logger.error("breach_catalog refresh failed: %s", exc)
        finally:
            _refresh_lock.release()

    return _catalog


def _invalidate_breaches_route_cache(breach_id: str, entity: Any) -> None:
    """Drop the /v1/breaches Redis entries after a new breach is discovered.

    Best-effort only: a Redis failure must never affect the read path.
    """
    try:
        keys = ["breaches:all", f"breaches:id:{breach_id.lower()}"]
        domain = entity.get("domain", "")
        if domain:
            keys.append(f"breaches:domain:{domain.lower()}")
        redis_client.delete(*keys)
        logger.info("breach_catalog invalidated /v1/breaches cache for %s", breach_id)
    except Exception as exc:
        logger.warning("breach_catalog cache invalidation failed: %s", exc)


def get_breach(breach_id: str) -> Optional[Any]:
    """Return the xon_breaches entity for breach_id, or None if absent.

    Hits the in-process catalog first; on a miss falls back to a direct
    Datastore get so breaches added after the last refresh are still
    served immediately. A breach discovered this way is added to the
    catalog and the /v1/breaches Redis cache is invalidated so the list
    endpoint picks it up on its next request. Datastore errors from the
    fallback propagate to the caller unchanged. Returned entities are
    copies, safe to mutate.
    """
    catalog = _get_catalog()
    if catalog is not None:
        entity = catalog.get(breach_id)
        if entity is not None:
            return copy.deepcopy(entity)

    key = ds_client.key("xon_breaches", breach_id)
    entity = ds_client.get(key)
    if entity is not None and catalog is not None:
        catalog[breach_id] = entity
        _invalidate_breaches_route_cache(breach_id, entity)
        return copy.deepcopy(entity)
    return entity
