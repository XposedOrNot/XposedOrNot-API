"""Tests for the per-tool MCP rate limiting and its isolation from REST.

Runs the real ``/mcp`` handler and the real ``custom_rate_limiter`` against
an in-memory Redis, stubbing only the I/O the limiter does not care about:
Datastore, Pub/Sub and the exception mailer.
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

# One backing store shared by the async client the limiter uses and the sync
# client the assertions below use, so inspecting state never has to borrow an
# event loop from the test client.
_fake_server = fakeredis.FakeServer()
_fake_redis = fakeredis.aioredis.FakeRedis(server=_fake_server, decode_responses=True)
_sync_redis = fakeredis.FakeRedis(server=_fake_server, decode_responses=True)


async def _fake_conn():
    return _fake_redis


custom_limiter.redis_pool = _fake_redis
custom_limiter.get_healthy_redis_connection = _fake_conn

import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

CLIENT_IP = "203.0.113.42"
HEADERS = {"CF-Connecting-IP": CLIENT_IP, "User-Agent": "mcp-test-client/1.0"}

TOOL_ARGS = {
    "check_email_breaches": {"email": "probe@example.com"},
    "get_breach_analytics": {"email": "probe@example.com"},
    "domain_breach_summary": {"domain": "example.com"},
    "list_breaches": {},
    "get_breach_metrics": {},
    "get_recent_breaches": {},
}


@pytest.fixture(autouse=True)
def _no_datastore(monkeypatch):
    """Point every loaded module's ``ds_client`` at the failing stub.

    Patched per test rather than at import time because another test module
    may already have imported ``config.clients`` with a real client, which
    would otherwise make these tests reach the network.
    """
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
    monkeypatch.setattr("api.v1.metrics.send_exception_email", _noop, raising=False)
    monkeypatch.setattr("api.v1.analytics.send_exception_email", _noop, raising=False)


@pytest.fixture(autouse=True)
def _clean_redis():
    """Start every test from an empty limiter store."""
    _sync_redis.flushall()
    yield


@pytest.fixture
def client():
    """Test client that surfaces handler errors as responses."""
    return TestClient(main.app, raise_server_exceptions=False)


def _call_tool(client, tool, args=None):
    return client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": TOOL_ARGS[tool] if args is None else args,
            },
        },
        headers=HEADERS,
    )


def _is_rate_limited(response):
    body = response.json()
    return body.get("error", {}).get("code") == -32000


def _keys(pattern="*"):
    return sorted(_sync_redis.scan_iter(pattern))


def _zcard(key):
    return _sync_redis.zcard(key)


def test_shared_rest_routes_resolve():
    """The email-keyed tools must find their real REST paths (drift guard)."""
    scopes = main._mcp_tool_scopes()
    for tool in ("check_email_breaches", "get_breach_analytics"):
        assert scopes[tool]["limits"] is None
        assert scopes[tool]["route_path"], f"{tool} failed to resolve its REST route"
    assert scopes["check_email_breaches"]["route_path"] == "/v1/check-email/{email}"
    assert scopes["get_breach_analytics"]["route_path"] == "/v1/breach-analytics"


def test_each_tool_gets_its_own_counter(client):
    """Six distinct tools must produce six distinct limiter keys."""
    for tool in TOOL_ARGS:
        _call_tool(client, tool)

    keys = set(_keys("rate-limit:*"))
    assert keys == {
        f"rate-limit:/mcp:list_breaches:{CLIENT_IP}",
        f"rate-limit:/mcp:domain_breach_summary:{CLIENT_IP}",
        f"rate-limit:/mcp:get_breach_metrics:{CLIENT_IP}",
        f"rate-limit:/mcp:get_recent_breaches:{CLIENT_IP}",
        f"rate-limit:/v1/check-email/{{email}}:{CLIENT_IP}",
        f"rate-limit:/v1/breach-analytics:{CLIENT_IP}",
    }
    assert f"rate-limit:/mcp:{CLIENT_IP}" not in keys


def test_parallel_fanout_is_not_throttled(client):
    """A burst across tools must not 429, which it did on the shared counter."""
    responses = [
        _call_tool(client, tool)
        for tool in (
            "list_breaches",
            "list_breaches",
            "list_breaches",
            "domain_breach_summary",
            "get_breach_metrics",
            "get_recent_breaches",
        )
    ]
    assert not any(_is_rate_limited(r) for r in responses)


def test_email_tools_share_the_rest_counter(client):
    """MCP email lookups spend the same budget as the REST route."""
    key = f"rate-limit:/v1/check-email/{{email}}:{CLIENT_IP}"

    client.get("/v1/check-email/probe@example.com", headers=HEADERS)
    assert _zcard(key) == 1

    _call_tool(client, "check_email_breaches")
    assert _zcard(key) == 2


def test_email_tool_keeps_rest_per_second_limit(client):
    """check_email_breaches must still trip the REST 2/second allowance."""
    responses = [_call_tool(client, "check_email_breaches") for _ in range(4)]
    assert _is_rate_limited(responses[-1])


def test_mcp_rejection_does_not_penalise_the_ip(client):
    """MCP throttling must stay out of violations:{ip}."""
    responses = [_call_tool(client, "list_breaches") for _ in range(25)]
    assert any(_is_rate_limited(r) for r in responses)

    assert _zcard(f"violations:{CLIENT_IP}") == 0
    assert _zcard(f"mcp-violations:{CLIENT_IP}") > 0


def test_rest_traffic_survives_mcp_throttling(client):
    """The Oct-12 regression: MCP 429s must not drop unrelated REST calls."""
    for _ in range(25):
        _call_tool(client, "list_breaches")

    for _ in range(6):
        response = client.get("/v1/breaches", headers=HEADERS)
        assert response.headers.get("X-Dropped") is None


def test_rest_limiter_still_penalises_violations(client):
    """Non-MCP traffic must keep the violation penalty it had before."""
    for _ in range(5):
        client.get("/v1/check-email/probe@example.com", headers=HEADERS)

    assert _zcard(f"violations:{CLIENT_IP}") > 0


def test_cf_escalation_skipped_for_mcp(client, monkeypatch):
    """MCP must never reach the Cloudflare day-block escalation path."""
    called = []

    async def _spy(_client_ip, endpoint, _redis_conn):
        called.append(endpoint)
        return False

    monkeypatch.setattr(custom_limiter, "escalate_day_limit_abuse", _spy)

    for _ in range(6):
        _call_tool(client, "check_email_breaches")

    assert not called


def test_hostile_tool_names_do_not_crash(client):
    """An unhashable tool name must not reach the scope lookup as a key."""
    for name in ({"a": 1}, ["x"], 123, None, True, "", "nope"):
        response = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": {}},
            },
            headers=HEADERS,
        )
        assert response.status_code == 200, f"name={name!r} returned a server error"
        assert response.json()["error"]["code"] == -32601


def test_envelope_limit_raised():
    """initialize / tools/list serve static JSON and only need flood cover."""
    assert main._MCP_ENVELOPE_LIMIT == [(20, 1), (2000, 3600), (20000, 86400)]
