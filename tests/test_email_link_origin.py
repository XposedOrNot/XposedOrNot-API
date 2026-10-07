"""Regression tests: security links must come from configured BASE_URL, not Host."""

import asyncio
import hashlib
import os
from pathlib import Path

import pytest
from starlette.requests import Request

os.environ.setdefault("AUTH_EMAIL", "test@example.com")
os.environ.setdefault("AUTHKEY", "test-auth-key")
os.environ.setdefault("CF_MAGIC", "test-cf-magic")
os.environ.setdefault("CF_UNBLOCK_MAGIC", "test-cf-unblock-magic")
os.environ.setdefault("DATASTORE_EMULATOR_HOST", "127.0.0.1:9999")
os.environ.setdefault("DATASTORE_PROJECT_ID", "test-project")
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "test-project")
os.environ.setdefault("MJ_API_KEY", "test-mail-key")
os.environ.setdefault("MJ_API_SECRET", "test-mail-secret")
os.environ.setdefault("SECRET_APIKEY", "test-secret-api-key")
os.environ.setdefault("SECURITY_SALT", "test-security-salt")
os.environ.setdefault("WTF_CSRF_SECRET_KEY", "test-csrf-key")

from api.v1 import alert as alert_module
from api.v1 import analytics as analytics_module
from config.settings import BASE_URL

REPO_ROOT = Path(__file__).resolve().parent.parent


class FakeEntity(dict):
    """Minimal datastore entity used by the link-origin tests."""

    def __init__(self, key, exclude_from_indexes=()):
        super().__init__()
        self.key = key


class FakeQuery:
    """Query stub returning a fixed result list."""

    def __init__(self, results):
        self._results = results

    def add_filter(self, *args, **kwargs):
        """Accept any filter without altering the fixed results."""
        return None

    def fetch(self):
        """Return the fixed results."""
        return list(self._results)


class FakeDatastoreClient:
    """In-memory datastore client used by the link-origin tests."""

    def __init__(self):
        self.entities = {}
        self.query_results = []

    def key(self, kind, name):
        """Return an in-memory key."""
        return kind, name

    def get(self, key):
        """Return an entity by key."""
        return self.entities.get(key)

    def put(self, entity):
        """Store an entity by key."""
        self.entities[entity.key] = entity

    def query(self, kind=None):
        """Return a query stub over the configured results."""
        return FakeQuery(self.query_results)


def hostile_request(path):
    """Create a request whose Host header points at an attacker origin."""
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [(b"host", b"evil.example")],
            "client": ("203.0.113.10", 12345),
            "query_string": b"",
            "server": ("evil.example", 443),
            "scheme": "https",
        }
    )


def test_no_handler_builds_links_from_request_host():
    """No application code may derive URLs from request.base_url."""
    offenders = []
    for folder in ("api", "services"):
        for path in (REPO_ROOT / folder).rglob("*.py"):
            if "request.base_url" in path.read_text(encoding="utf-8"):
                offenders.append(str(path))
    assert offenders == []


def test_unsubscribe_email_link_ignores_hostile_host(monkeypatch):
    """The unsubscribe email link uses BASE_URL even with a forged Host."""
    client = FakeDatastoreClient()
    captured = []

    async def fake_unsub_email(email, url):
        captured.append(url)

    record = FakeEntity(("xon_alert", "victim@example.com"))
    record.update({"verified": True, "unSubscribeOn": False})
    client.put(record)

    monkeypatch.setattr(alert_module, "ds_client", client)
    monkeypatch.setattr(alert_module, "send_unsub_email", fake_unsub_email)

    response = asyncio.run(
        alert_module.unsubscribe.__wrapped__(
            "victim@example.com", hostile_request("/v1/unsubscribe-on")
        )
    )

    assert response.status == "Success"
    assert len(captured) == 1
    assert captured[0].startswith(f"{BASE_URL}/v1/verify_unsub/")
    assert "evil.example" not in captured[0]


def test_dashboard_login_email_link_ignores_hostile_host(monkeypatch):
    """The magic-link login email uses BASE_URL even with a forged Host."""
    client = FakeDatastoreClient()
    domain_row = FakeEntity(("xon_domains", "example.com_victim@example.com"))
    domain_row.update({"email": "victim@example.com", "verified": True})
    client.query_results = [domain_row]
    captured = []

    async def fake_dashboard_email(email, url, ip_loc, browser, platform):
        captured.append(url)

    monkeypatch.setattr(analytics_module, "ds_client", client)
    monkeypatch.setattr(analytics_module.datastore, "Entity", FakeEntity)
    monkeypatch.setattr(
        analytics_module, "send_dashboard_email_confirmation", fake_dashboard_email
    )
    monkeypatch.setattr(
        analytics_module,
        "validate_email_deliverable",
        lambda email: (True, "victim@example.com"),
    )
    monkeypatch.setattr(
        analytics_module, "get_client_ip", lambda request: "203.0.113.10"
    )
    monkeypatch.setattr(
        analytics_module, "get_location_from_headers", lambda request: "Test City"
    )
    monkeypatch.setattr(
        analytics_module, "get_user_agent_info", lambda request: ("Browser", "OS")
    )

    response = asyncio.run(
        analytics_module.domain_alert.__wrapped__(
            hostile_request("/v1/domain-alert"), "victim@example.com", None
        )
    )

    assert response.Success == "Domain Alert Successful"
    assert len(captured) == 1
    assert captured[0].startswith(f"{BASE_URL}/v1/domain-verify/")
    assert "evil.example" not in captured[0]
    assert ("xon_domains_session", "victim@example.com") not in client.entities
    challenge = captured[0].rsplit("/", 1)[-1]
    challenge_key = (
        "xon_dashboard_login_challenges",
        hashlib.sha256(challenge.encode("utf-8")).hexdigest(),
    )
    assert client.entities[challenge_key]["email"] == "victim@example.com"
    assert client.entities[challenge_key]["used"] is False
