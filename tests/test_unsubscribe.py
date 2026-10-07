"""Regression tests for the confirmed-only alert unsubscribe flow."""

import asyncio
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
from api.v1 import monitor as monitor_module


class FakeEntity(dict):
    """Minimal datastore entity used by the unsubscribe tests."""

    def __init__(self, key):
        super().__init__()
        self.key = key


class FakeDatastoreClient:
    """In-memory datastore client used by the unsubscribe tests."""

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

    def delete(self, key):
        """Delete an entity by key."""
        self.entities.pop(key, None)


def make_request(path="/v1/unsubscribe-on"):
    """Create a minimal request with stable client metadata."""
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [],
            "client": ("203.0.113.10", 12345),
            "query_string": b"",
            "server": ("api.xposedornot.com", 443),
            "scheme": "https",
        }
    )


@pytest.fixture
def env(monkeypatch):
    """Install an in-memory datastore and capture outbound email."""
    client = FakeDatastoreClient()
    unsub_emails = []
    revoked = []

    async def fake_unsub_email(email, url):
        unsub_emails.append((email, url))

    async def fake_exception_email(**kwargs):
        return None

    monkeypatch.setattr(module, "ds_client", client)
    monkeypatch.setattr(module, "send_unsub_email", fake_unsub_email)
    monkeypatch.setattr(module, "send_exception_email", fake_exception_email)
    monkeypatch.setattr(monitor_module, "revoke_monitors_for_target", revoked.append)
    return client, unsub_emails, revoked


def subscriber(client, email, verified=True):
    """Store a verified alert subscriber record."""
    key = ("xon_alert", email)
    record = FakeEntity(key)
    record.update({"verified": verified, "unSubscribeOn": False, "shieldOn": False})
    client.put(record)
    return key


def initiate(email):
    """Invoke the real unsubscribe initiation handler."""
    return asyncio.run(module.unsubscribe.__wrapped__(email, make_request()))


def confirm(token):
    """Invoke the real unsubscribe confirmation handler."""
    return asyncio.run(
        module.verify_unsubscribe.__wrapped__(token, make_request("/v1/verify_unsub"))
    )


def dashboard_eligible(record):
    """Mirror the alert-only dashboard login guard from analytics."""
    return bool(
        record
        and record.get("verified", False)
        and not record.get("unSubscribeOn", False)
    )


def test_initiation_does_not_change_subscription_state(env):
    """An unauthenticated initiation leaves the flag and eligibility intact."""
    client, unsub_emails, _ = env
    key = subscriber(client, "victim@example.com")

    response = initiate("victim@example.com")

    assert response.status == "Success"
    record = client.entities[key]
    assert record["unSubscribeOn"] is False
    assert dashboard_eligible(record) is True
    assert record["unsub_token"]
    assert len(unsub_emails) == 1


def test_confirmed_unsubscribe_deletes_record_and_revokes_monitors(env):
    """The emailed token still completes the unsubscribe end to end."""
    client, unsub_emails, revoked = env
    key = subscriber(client, "victim@example.com")
    initiate("victim@example.com")
    token = client.entities[key]["unsub_token"]
    assert token in unsub_emails[0][1]

    response = confirm(token)

    assert response.status_code == 200
    assert key not in client.entities
    assert revoked == ["victim@example.com"]


def test_wrong_token_does_not_unsubscribe(env):
    """A token for another email cannot complete the unsubscribe."""
    client, _, revoked = env
    key = subscriber(client, "victim@example.com")
    initiate("victim@example.com")
    other_key = subscriber(client, "other@example.com")
    initiate("other@example.com")
    other_token = client.entities[other_key]["unsub_token"]
    client.entities.pop(other_key)

    response = confirm(other_token)

    assert response.status_code == 404
    assert key in client.entities
    assert revoked == []


def test_confirm_without_initiation_fails(env):
    """A forged confirmation with no pending token is rejected."""
    client, _, revoked = env
    key = subscriber(client, "victim@example.com")
    token = asyncio.run(module.generate_confirmation_token("victim@example.com"))

    response = confirm(token)

    assert response.status_code == 404
    assert key in client.entities
    assert revoked == []


def test_confirm_replay_after_deletion_fails(env):
    """Replaying a consumed unsubscribe link is rejected."""
    client, _, revoked = env
    key = subscriber(client, "victim@example.com")
    initiate("victim@example.com")
    token = client.entities[key]["unsub_token"]
    confirm(token)

    replay = confirm(token)

    assert replay.status_code == 404
    assert revoked == ["victim@example.com"]


def test_unverified_subscriber_gets_no_unsubscribe_email(env):
    """Initiation for unverified or unknown emails stays a silent success."""
    client, unsub_emails, _ = env
    key = subscriber(client, "pending@example.com", verified=False)

    response = initiate("pending@example.com")
    missing = initiate("ghost@example.com")

    assert response.status == "Success"
    assert missing.status == "Success"
    assert unsub_emails == []
    assert "unsub_token" not in client.entities[key]


def test_repeated_initiations_keep_victim_eligible(env):
    """Hammering initiation never blocks the victim's dashboard access."""
    client, unsub_emails, _ = env
    key = subscriber(client, "victim@example.com")

    for _ in range(5):
        initiate("victim@example.com")

    record = client.entities[key]
    assert record["unSubscribeOn"] is False
    assert dashboard_eligible(record) is True
    assert len(unsub_emails) == 5

    latest_token = record["unsub_token"]
    response = confirm(latest_token)
    assert response.status_code == 200
    assert key not in client.entities
