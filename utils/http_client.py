"""Shared pooled HTTP client: one httpx.AsyncClient per worker process.

Every outbound call previously constructed (and closed) its own
AsyncClient, paying a TCP+TLS handshake per call and hanging forever at
the seven sites that set no timeout. This client pools connections with
keep-alive and applies a 10s default timeout; sites with a deliberate
different timeout pass `timeout=` per request.

Usage:
    async with shared_http_client() as client:   # drop-in for
        await client.post(...)                   # httpx.AsyncClient()

Entering/exiting the context never closes the client; it is closed once
per process by aclose_http_client() from the app shutdown hook.
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = httpx.Timeout(10.0)
_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20)

_client: Optional[httpx.AsyncClient] = None


def get_http_client() -> httpx.AsyncClient:
    """Return the process-wide pooled client, creating it lazily."""
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, limits=_LIMITS)
    return _client


class _SharedClientContext:
    """Async context manager yielding the shared client WITHOUT closing
    it on exit — a drop-in for `async with httpx.AsyncClient() as c:`."""

    async def __aenter__(self) -> httpx.AsyncClient:
        return get_http_client()

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


def shared_http_client() -> _SharedClientContext:
    """Return a context manager yielding the pooled client without closing it."""
    return _SharedClientContext()


async def aclose_http_client() -> None:
    """Close the pooled client. Called once from app shutdown."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
        logger.info("Shared HTTP client closed")
    _client = None
