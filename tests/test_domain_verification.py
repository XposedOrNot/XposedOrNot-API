"""Regression tests for role-address domain verification."""

import asyncio
import os
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from redis import RedisError
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

from api.v1 import domain_verification as module


class FakeEntity(dict):
    """Minimal datastore entity used by the verification tests."""

    def __init__(self, key):
        super().__init__()
        self.key = key


class FakeDatastoreClient:
    """In-memory datastore client used by the verification tests."""

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

    def transaction(self):
        """Return a transaction-compatible context manager."""
        return nullcontext()


class FakeRedis:
    """Minimal in-memory Redis used to exercise anti-bombing limits."""

    def __init__(self):
        self.store = {}

    def set(self, key, value, nx=False, ex=None):
        """Set a key, honouring NX semantics for cooldown locks."""
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    def incr(self, key):
        """Increment and return a fixed-window counter."""
        value = int(self.store.get(key, 0)) + 1
        self.store[key] = value
        return value

    def expire(self, key, seconds):
        """No-op expiry; windows are not time-advanced in tests."""
        return True


class BrokenRedis:
    """Redis stand-in that always raises to exercise fail-open behaviour."""

    def set(self, *args, **kwargs):
        """Raise as if Redis were unreachable."""
        raise RedisError("redis down")

    def incr(self, *args, **kwargs):
        """Raise as if Redis were unreachable."""
        raise RedisError("redis down")

    def expire(self, *args, **kwargs):
        """Raise as if Redis were unreachable."""
        raise RedisError("redis down")


def make_request():
    """Create a minimal request with stable client metadata."""
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/domain_verification",
            "headers": [],
            "client": ("203.0.113.10", 12345),
        }
    )


def redeem_challenge(token):
    """Invoke the redemption handler without rate-limiter state."""
    return module.domain_validation.__wrapped__(make_request(), token)


@pytest.fixture
def verification_environment(monkeypatch):
    """Install no-network datastore, email, and thread replacements."""
    client = FakeDatastoreClient()
    sent = []
    notifications = []
    processing_starts = []
    success_emails = []

    async def fake_send(email, token, ip_address, browser_type, client_platform):
        sent.append((email, token, ip_address, browser_type, client_platform))

    async def fake_notification(domain):
        notifications.append(domain)

    async def fake_success(email, ip_address, browser_type, client_platform):
        success_emails.append((email, ip_address, browser_type, client_platform))

    monkeypatch.setattr(module, "ds_client", client)
    monkeypatch.setattr(module, "redis_client", FakeRedis())
    monkeypatch.setattr(module.datastore, "Entity", FakeEntity)
    monkeypatch.setattr(module, "send_domain_confirmation_email", fake_send)
    monkeypatch.setattr(
        module, "send_domain_verification_admin_notification", fake_notification
    )
    monkeypatch.setattr(module, "send_domain_verified_success", fake_success)
    monkeypatch.setattr(module, "start_domain_processing", processing_starts.append)
    monkeypatch.setattr(module, "get_client_ip", lambda request: "203.0.113.10")
    monkeypatch.setattr(
        module, "get_user_agent_info", lambda request: ("Test Browser", "Test OS")
    )
    return client, sent, notifications, processing_starts, success_emails


def test_role_addresses_are_static_and_normalized():
    """Only the five approved role addresses are generated."""
    assert module.get_domain_verification_emails("Example.COM") == [
        "security@example.com",
        "admin@example.com",
        "webmaster@example.com",
        "postmaster@example.com",
        "hostmaster@example.com",
    ]
    assert module.get_domain_verification_emails("invalid") == []


def test_arbitrary_recipient_is_rejected_without_side_effects(
    verification_environment,
):
    """A caller-supplied non-role mailbox cannot receive a challenge."""
    client, sent, _, processing_starts, success_emails = verification_environment
    response = asyncio.run(
        module.verify_email("example.com", "owner@example.com", make_request())
    )

    assert response.status == "error"
    assert response.domainVerification == "Failure"
    assert client.entities == {}
    assert sent == []
    assert not processing_starts
    assert not success_emails


def test_role_recipient_stays_pending_until_redeemed(verification_environment):
    """Sending a challenge does not prematurely verify the domain."""
    client, sent, notifications, processing_starts, success_emails = (
        verification_environment
    )
    response = asyncio.run(
        module.verify_email("example.com", "security@example.com", make_request())
    )

    assert response.status == "success"
    assert len(sent) == 1
    assert not any(key[0] == "xon_domains" for key in client.entities)
    assert notifications == []
    assert not processing_starts
    assert not success_emails

    token = sent[0][1]
    redeemed = asyncio.run(redeem_challenge(token))

    assert redeemed.status == "success"
    domain_key = "xon_domains", "example.com_security@example.com"
    assert client.entities[domain_key]["verified"] is True
    assert client.entities[domain_key][
        "token"
    ] == module.hash_domain_verification_token(token)
    assert notifications == ["example.com"]
    assert processing_starts == ["example.com"]
    assert success_emails == [
        ("security@example.com", "203.0.113.10", "Test Browser", "Test OS")
    ]

    with pytest.raises(HTTPException) as replay:
        asyncio.run(redeem_challenge(token))
    assert replay.value.status_code == 404


def test_expired_challenge_cannot_verify_domain(verification_environment):
    """Expired challenges fail without creating a verified record."""
    client, sent, notifications, processing_starts, success_emails = (
        verification_environment
    )
    asyncio.run(
        module.verify_email("example.com", "postmaster@example.com", make_request())
    )
    token = sent[0][1]
    challenge_key = (
        "xon_domain_verification_challenges",
        module.hash_domain_verification_token(token),
    )
    client.entities[challenge_key]["expires_at"] = datetime.now(
        timezone.utc
    ) - timedelta(seconds=1)

    with pytest.raises(HTTPException) as expired:
        asyncio.run(redeem_challenge(token))

    assert expired.value.status_code == 404
    assert not any(key[0] == "xon_domains" for key in client.entities)
    assert notifications == []
    assert not processing_starts
    assert not success_emails


def test_seniority_enrichment_runs_when_domain_has_no_breaches(monkeypatch):
    """Verified domains without breach rows still receive seniority enrichment."""
    client = FakeDatastoreClient()
    enriched = []
    monkeypatch.setattr(module, "ds_client", client)
    monkeypatch.setattr(module.datastore, "Entity", FakeEntity)
    monkeypatch.setattr(
        module, "list_transactions_for_domain", lambda client, domain: []
    )
    monkeypatch.setattr(module, "enrich_domain_seniority", enriched.append)

    module.process_single_domain("example.com")

    summary_key = "xon_domains_summary", "example.com+No_Breaches"
    assert client.entities[summary_key]["email_count"] == 0
    assert enriched == ["example.com"]


def test_recipient_cooldown_blocks_repeat_challenge(verification_environment):
    """A second challenge to the same role address is throttled with 429."""
    _, sent, _, _, _ = verification_environment

    first = asyncio.run(
        module.verify_email("example.com", "security@example.com", make_request())
    )
    assert first.status == "success"
    assert len(sent) == 1

    with pytest.raises(HTTPException) as throttled:
        asyncio.run(
            module.verify_email("example.com", "security@example.com", make_request())
        )
    assert throttled.value.status_code == 429
    assert len(sent) == 1


def test_domain_hourly_cap_blocks_across_role_addresses(
    verification_environment, monkeypatch
):
    """Distinct role addresses share a per-domain hourly cap."""
    _, sent, _, _, _ = verification_environment
    monkeypatch.setattr(module, "DOMAIN_EMAIL_DOMAIN_MAX_PER_HOUR", 2)

    for role in ("security", "admin"):
        response = asyncio.run(
            module.verify_email("example.com", f"{role}@example.com", make_request())
        )
        assert response.status == "success"

    with pytest.raises(HTTPException) as throttled:
        asyncio.run(
            module.verify_email("example.com", "webmaster@example.com", make_request())
        )
    assert throttled.value.status_code == 429
    assert len(sent) == 2


def test_global_daily_budget_blocks_new_domains(verification_environment, monkeypatch):
    """The global daily budget caps challenges across unrelated domains."""
    _, sent, _, _, _ = verification_environment
    monkeypatch.setattr(module, "DOMAIN_EMAIL_GLOBAL_DAILY_BUDGET", 1)

    first = asyncio.run(
        module.verify_email("example.com", "security@example.com", make_request())
    )
    assert first.status == "success"

    with pytest.raises(HTTPException) as throttled:
        asyncio.run(
            module.verify_email("other.com", "security@other.com", make_request())
        )
    assert throttled.value.status_code == 429
    assert len(sent) == 1


def test_limits_fail_open_when_redis_unavailable(verification_environment, monkeypatch):
    """Challenges still send when Redis raises, so an outage cannot block users."""
    _, sent, _, _, _ = verification_environment
    monkeypatch.setattr(module, "redis_client", BrokenRedis())

    for role in ("security", "admin"):
        response = asyncio.run(
            module.verify_email("example.com", f"{role}@example.com", make_request())
        )
        assert response.status == "success"
    assert len(sent) == 2


def test_limits_disabled_skips_redis(verification_environment, monkeypatch):
    """Disabling the feature flag bypasses all Redis-backed limits."""
    _, sent, _, _, _ = verification_environment
    monkeypatch.setattr(module, "redis_client", BrokenRedis())
    monkeypatch.setattr(module, "DOMAIN_EMAIL_LIMITS_ENABLED", False)

    for _ in range(3):
        response = asyncio.run(
            module.verify_email("example.com", "security@example.com", make_request())
        )
        assert response.status == "success"
    assert len(sent) == 3
