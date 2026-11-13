"""Tests for the xonAPI+ upgrade hint on 429 responses.

Runs the real ``custom_rate_limiter`` and the real routes against an in-memory
Redis, so the body and headers asserted here are what clients receive.
"""

# pylint: disable=redefined-outer-name,protected-access,wrong-import-position
# pylint: disable=wrong-import-order,too-few-public-methods

import os
import sys

import pytest
from cryptography.fernet import Fernet

os.environ.setdefault("AUTH_EMAIL", "test@example.com")
os.environ.setdefault("AUTHKEY", "test-auth-key")
os.environ.setdefault("CF_MAGIC", "test-cf-magic")
os.environ.setdefault("CF_UNBLOCK_MAGIC", "test-cf-unblock-magic")
os.environ.setdefault("DATASTORE_PROJECT_ID", "test-project")
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "test-project")
os.environ.setdefault("MJ_API_KEY", "test-mail-key")
os.environ.setdefault("MJ_API_SECRET", "test-mail-secret")
os.environ.setdefault("SECRET_APIKEY", "test-secret-api-key")
os.environ.setdefault("SECURITY_SALT", "test-security-salt")
os.environ.setdefault("WTF_CSRF_SECRET_KEY", "test-csrf-key")
os.environ.setdefault("ENCRYPTION_KEY", Fernet.generate_key().decode())

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

fakeredis = pytest.importorskip("fakeredis")

from google.cloud import datastore as _datastore  # noqa: E402
from google.cloud import pubsub_v1 as _pubsub  # noqa: E402


class _NoDatastore:
    """Stand-in client whose every operation fails fast."""

    def __init__(self, *_args, **_kwargs):
        pass

    def __getattr__(self, _name):
        def _raise(*_args, **_kwargs):
            raise RuntimeError("datastore unavailable in tests")

        return _raise


class _NoPubSub(_NoDatastore):
    """Publisher stub that can be constructed at import time."""

    def topic_path(self, *_args, **_kwargs):
        """Return a dummy topic path so module import succeeds."""
        return "projects/test/topics/test"


_datastore.Client = _NoDatastore
_pubsub.PublisherClient = _NoPubSub

import fakeredis.aioredis  # noqa: E402

from utils import custom_limiter  # noqa: E402

_fake_server = fakeredis.FakeServer()
_fake_redis = fakeredis.aioredis.FakeRedis(server=_fake_server, decode_responses=True)
_sync_redis = fakeredis.FakeRedis(server=_fake_server, decode_responses=True)


async def _fake_conn():
    return _fake_redis


import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

CLIENT_IP = "203.0.113.77"
HEADERS = {"CF-Connecting-IP": CLIENT_IP, "User-Agent": "upgrade-hint-test/1.0"}
PLUS_URL = "https://plus.xposedornot.com/products/api"


@pytest.fixture(autouse=True)
def _no_datastore(monkeypatch):
    """Point every loaded module's ``ds_client`` at the failing stub."""
    stub = _NoDatastore()
    for module in list(sys.modules.values()):
        name = getattr(module, "__name__", "")
        if not name.startswith(("api.", "config.", "services.", "utils.")):
            continue
        if hasattr(module, "ds_client"):
            monkeypatch.setattr(module, "ds_client", stub, raising=False)


@pytest.fixture(autouse=True)
def _quiet_mailer(monkeypatch):
    """Keep the exception mailer from touching the network."""

    async def _noop(**_kwargs):
        return None

    monkeypatch.setattr("services.send_email.send_exception_email", _noop)
    monkeypatch.setattr("api.v1.breaches.send_exception_email", _noop, raising=False)


@pytest.fixture(autouse=True)
def _own_redis(monkeypatch):
    """Point the limiter at this module's in-memory Redis for the test only.

    Patched per test, not at import, so another test module that swaps the
    limiter's Redis at import time keeps its own store once these finish.
    """
    monkeypatch.setattr(custom_limiter, "redis_pool", _fake_redis)
    monkeypatch.setattr(custom_limiter, "get_healthy_redis_connection", _fake_conn)
    _sync_redis.flushall()
    yield


@pytest.fixture(autouse=True)
def _no_drop(monkeypatch):
    """Keep the violation-history drop out of the quota-path tests."""
    monkeypatch.setattr(custom_limiter, "get_drop_percentage", lambda _count: 0.0)


@pytest.fixture
def client():
    """Test client that surfaces handler errors as responses."""
    return TestClient(main.app, raise_server_exceptions=False)


def _hit_until_429(client, path, attempts=4):
    for _ in range(attempts):
        response = client.get(path, headers=HEADERS)
        if response.status_code == 429:
            return response
    raise AssertionError(f"{path} never returned 429")


def _assert_upgrade_block(detail, headers):
    assert detail["upgrade"] == {
        "plan": "xonAPI+",
        "url": PLUS_URL,
        "note": "Paid plans fund the free tier.",
    }
    assert headers["Link"] == f'<{PLUS_URL}>; rel="help"; title="xonAPI+ higher limits"'


def test_check_email_429_carries_upgrade_hint(client):
    """The per-second quota on check-email returns the copy, block and headers."""
    response = _hit_until_429(client, "/v1/check-email/probe@example.com")
    detail = response.json()["detail"]
    assert detail["error"] == "Rate limit exceeded"
    assert detail["retry_after"] >= 1
    assert "reset_time" in detail
    assert detail["message"].startswith(
        "You've hit the free limit for email checks (2/second, 25/hour, 100/day)."
    )
    assert "$9/month" in detail["message"]
    assert detail["message"].endswith(PLUS_URL)
    assert response.headers["Retry-After"] == str(detail["retry_after"])
    _assert_upgrade_block(detail, response.headers)


def test_breach_analytics_429_carries_upgrade_hint(client):
    """breach-analytics gets its own first line and the same upgrade block."""
    response = _hit_until_429(client, "/v1/breach-analytics?email=probe@example.com")
    detail = response.json()["detail"]
    assert detail["message"].startswith(
        "You've hit the free limit for breach analytics (2/second, 25/hour, 100/day)."
    )
    assert detail["message"].endswith(PLUS_URL)
    _assert_upgrade_block(detail, response.headers)


def test_routes_without_opt_in_are_unchanged(client):
    """A route that passes no message keeps its old 429 body and headers."""
    response = _hit_until_429(client, "/v1/breaches")
    detail = response.json()["detail"]
    assert "message" not in detail
    assert "upgrade" not in detail
    assert "Link" not in response.headers
    assert response.headers["Retry-After"] == str(detail["retry_after"])


def test_violation_drop_429_carries_upgrade_hint(client, monkeypatch):
    """The drop path, which has no retry_after, still carries the hint."""
    monkeypatch.setattr(custom_limiter, "get_drop_percentage", lambda _count: 1.0)

    async def _two_violations(*_args, **_kwargs):
        return 2

    monkeypatch.setattr(custom_limiter, "get_violation_count", _two_violations)
    response = client.get("/v1/check-email/probe@example.com", headers=HEADERS)
    assert response.status_code == 429
    detail = response.json()["detail"]
    assert detail["error"] == "Request dropped due to violation history"
    assert detail["message"].startswith("Your requests are being dropped")
    assert detail["message"].endswith(PLUS_URL)
    assert response.headers["X-Dropped"] == "true"
    _assert_upgrade_block(detail, response.headers)


def test_mcp_429_carries_upgrade_hint(client):
    """The MCP wrapper passes the upgrade block through into the JSON-RPC error."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "check_email_breaches",
            "arguments": {"email": "probe@example.com"},
        },
    }
    error = None
    for _ in range(4):
        body = client.post("/mcp", json=payload, headers=HEADERS).json()
        if body.get("error", {}).get("code") == -32000:
            error = body["error"]
            break
    assert error is not None, "MCP call never hit the rate limit"
    assert error["data"]["status"] == 429
    assert error["data"]["upgrade"]["url"] == PLUS_URL
    assert error["message"].endswith(f"Or use xonAPI+ for higher limits: {PLUS_URL}")
