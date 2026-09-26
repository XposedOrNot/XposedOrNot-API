"""Regression tests for privacy shield activation."""

import asyncio
import json
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

from api.v1 import analytics as module


class FakeEntity(dict):
    """Minimal datastore entity used by the shield tests."""

    def __init__(self, key, exclude_from_indexes=()):
        super().__init__()
        self.key = key
        self.exclude_from_indexes = exclude_from_indexes


class FakeDatastoreClient:
    """In-memory datastore client used by the shield tests."""

    def __init__(self):
        self.entities = {}

    def key(self, kind, name):
        """Return an in-memory key."""
        return kind, name

    def get(self, key):
        """Return an entity by key."""
        return self.entities.get(key)

    def put(self, entity):
        """Store an entity by key."""
        self.entities[entity.key] = entity


def make_request():
    """Create a minimal request with stable client metadata."""
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/shield-on",
            "query_string": b"",
            "headers": [(b"host", b"xposedornot.com")],
            "client": ("203.0.113.10", 12345),
            "scheme": "https",
            "server": ("xposedornot.com", 443),
            "root_path": "",
        }
    )


def activate(email):
    """Invoke the shield handler without rate-limiter state."""
    return asyncio.run(module.activate_shield.__wrapped__(make_request(), email))


def body_of(response):
    """Return the decoded payload for either a model or a JSONResponse."""
    if hasattr(response, "body"):
        return json.loads(response.body)
    return response.model_dump()


@pytest.fixture
def shield_environment(monkeypatch):
    """Install no-network datastore, email, and token replacements."""
    client = FakeDatastoreClient()
    sent = []

    async def fake_send(email, confirm_url, ip_address, browser_type, client_platform):
        sent.append((email, confirm_url, ip_address, browser_type, client_platform))

    async def fake_token(email):
        return "shield-token"

    monkeypatch.setattr(module, "ds_client", client)
    monkeypatch.setattr(module.datastore, "Entity", FakeEntity)
    monkeypatch.setattr(module, "send_shield_email", fake_send)
    monkeypatch.setattr(module, "generate_confirmation_token", fake_token)
    monkeypatch.setattr(module, "get_client_ip", lambda request: "203.0.113.10")
    monkeypatch.setattr(module, "get_location_from_headers", lambda request: "IN")
    monkeypatch.setattr(
        module, "get_user_agent_info", lambda request: ("Test Browser", "Test OS")
    )
    monkeypatch.setattr(module, "invalidate_cached_shield", lambda email: None)
    monkeypatch.setattr(
        module, "validate_email_deliverable", lambda email: (True, email)
    )
    return client, sent


def test_deliverable_address_receives_shield_confirmation(shield_environment):
    """A deliverable address is recorded and sent a confirmation link."""
    client, sent = shield_environment

    response = activate("owner@example.com")

    assert body_of(response) == {"Success": "ShieldAdded"}
    assert len(sent) == 1
    assert sent[0][0] == "owner@example.com"
    assert ("xon_alert", "owner@example.com") in client.entities


def test_undeliverable_address_is_rejected_without_side_effects(
    shield_environment, monkeypatch
):
    """An address whose domain cannot receive mail gets no email or record."""
    client, sent = shield_environment
    monkeypatch.setattr(
        module,
        "validate_email_deliverable",
        lambda email: (False, "Unable to deliver email to this address"),
    )

    response = activate("owner@example.com")

    assert response.status_code == 400
    assert body_of(response) == {"Error": "Unable to deliver email to this address"}
    assert client.entities == {}
    assert sent == []


def test_malformed_address_still_returns_not_found(shield_environment, monkeypatch):
    """Malformed input keeps its original 404 response and skips the DNS check."""
    client, sent = shield_environment

    def unexpected(email):
        raise AssertionError("deliverability checked before format validation")

    monkeypatch.setattr(module, "validate_email_deliverable", unexpected)

    response = activate("not-an-email")

    assert response.status_code == 404
    assert body_of(response) == {"Error": "Not found"}
    assert client.entities == {}
    assert sent == []


def test_normalized_address_is_used_for_the_alert_key(shield_environment, monkeypatch):
    """The normalized address keys the alert row so routes stay consistent."""
    client, sent = shield_environment
    monkeypatch.setattr(
        module, "validate_email_deliverable", lambda email: (True, "owner@example.com")
    )

    response = activate("Owner@Example.com")

    assert body_of(response) == {"Success": "ShieldAdded"}
    assert ("xon_alert", "owner@example.com") in client.entities
    assert sent[0][0] == "owner@example.com"


def test_already_enabled_shield_is_not_re_sent(shield_environment):
    """An address with the shield already on receives no further email."""
    client, sent = shield_environment
    existing = FakeEntity(("xon_alert", "owner@example.com"))
    existing["shieldOn"] = True
    client.put(existing)

    response = activate("owner@example.com")

    assert body_of(response) == {"Success": "AlreadyOn"}
    assert sent == []
