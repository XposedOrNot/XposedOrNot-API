"""Regression tests: send_verification rejects a cryptographically expired token."""

import asyncio
import datetime
import os

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

from api.v1 import alert as module


class FakeEntity(dict):
    """Minimal datastore entity."""

    def __init__(self, key):
        super().__init__()
        self.key = key


class FakeDatastoreClient:
    """In-memory datastore client."""

    def __init__(self):
        self.entities = {}

    def key(self, kind, name):
        """Return an in-memory key."""
        return kind, name

    def get(self, key):
        """Return an entity by key."""
        return self.entities.get(key)


def make_request():
    """Create a minimal request."""
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/send_verification",
            "headers": [(b"host", b"api.xposedornot.com")],
            "query_string": b"",
            "client": ("203.0.113.10", 12345),
            "scheme": "https",
            "server": ("api.xposedornot.com", 443),
        }
    )


@pytest.fixture
def env(monkeypatch):
    """Install an in-memory datastore with one verified subscriber."""
    client = FakeDatastoreClient()

    async def fake_exception_email(**_kwargs):
        return None

    key = ("xon_alert", "victim@example.com")
    record = FakeEntity(key)
    record.update(
        {
            "verified": True,
            "token": "stored-token",
            "verify_timestamp": datetime.datetime.now(datetime.timezone.utc),
            "recent_timestamp": datetime.datetime.now(datetime.timezone.utc),
        }
    )
    client.entities[key] = record
    xon_key = ("xon", "victim@example.com")
    xon_record = FakeEntity(xon_key)
    xon_record.update({"site": "LinkedIn", "sensitive_site": "AdultSite"})
    client.entities[xon_key] = xon_record
    monkeypatch.setattr(module, "ds_client", client)
    monkeypatch.setattr(module, "send_exception_email", fake_exception_email)
    return client


def call():
    """Invoke the real send_verification handler."""
    return asyncio.run(
        module.send_verification(
            token="stored-token", email="victim@example.com", request=make_request()
        )
    )


def test_expired_token_is_rejected_within_redemption_window(env, monkeypatch):
    """A stored token that fails signature re-check is refused despite a fresh window."""

    async def expired(_token):
        return None

    monkeypatch.setattr(module, "confirm_token", expired)

    assert call().status == "Failed"


def test_valid_token_still_succeeds(env, monkeypatch):
    """A token that still passes signature re-check keeps working."""

    async def valid(_token):
        return "victim@example.com"

    async def no_breaches(_arg):
        return {}

    monkeypatch.setattr(module, "confirm_token", valid)
    monkeypatch.setattr(module, "get_breaches", lambda _s: {"breaches_details": []})
    monkeypatch.setattr(module, "get_breaches_analytics", no_breaches)

    assert call().status == "Success"
