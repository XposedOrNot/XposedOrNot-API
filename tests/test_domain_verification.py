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

    async def fake_send(
        email, token, ip_address, browser_type, client_platform, recipient, domain
    ):
        sent.append(
            (email, token, ip_address, browser_type, client_platform, recipient, domain)
        )

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
    monkeypatch.setattr(
        module, "validate_email_deliverable", lambda email: (True, email)
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


def test_arbitrary_role_is_rejected_without_side_effects(
    verification_environment,
):
    """A caller-supplied non-role proof mailbox cannot receive a challenge."""
    client, sent, _, processing_starts, success_emails = verification_environment
    response = asyncio.run(
        module.verify_email(
            "example.com", "owner@example.com", "owner@example.com", make_request()
        )
    )

    assert response.status == "error"
    assert response.domainVerification == "Failure"
    assert client.entities == {}
    assert sent == []
    assert not processing_starts
    assert not success_emails


def test_offdomain_recipient_is_rejected_without_side_effects(
    verification_environment,
):
    """A recipient on a different domain cannot own the verification."""
    client, sent, _, processing_starts, success_emails = verification_environment
    response = asyncio.run(
        module.verify_email(
            "example.com", "admin@example.com", "attacker@evil.com", make_request()
        )
    )

    assert response.status == "error"
    assert response.domainVerification == "Failure"
    assert client.entities == {}
    assert sent == []
    assert not processing_starts
    assert not success_emails


def test_undeliverable_recipient_is_rejected_without_side_effects(
    verification_environment, monkeypatch
):
    """A recipient whose domain cannot receive mail gets no challenge."""
    client, sent, _, processing_starts, success_emails = verification_environment
    monkeypatch.setattr(
        module,
        "validate_email_deliverable",
        lambda email: (False, "Unable to deliver email to this address"),
    )

    response = asyncio.run(
        module.verify_email(
            "example.com", "security@example.com", "owner@example.com", make_request()
        )
    )

    assert response.status == "error"
    assert response.domainVerification == "Failure"
    assert client.entities == {}
    assert sent == []
    assert not processing_starts
    assert not success_emails


def test_deliverability_is_checked_against_the_recipient_address(
    verification_environment, monkeypatch
):
    """The deliverability gate inspects the recipient, not the role mailbox."""
    _, sent, _, _, _ = verification_environment
    checked = []

    def record(email):
        checked.append(email)
        return True, email

    monkeypatch.setattr(module, "validate_email_deliverable", record)

    response = asyncio.run(
        module.verify_email(
            "example.com", "security@example.com", "owner@example.com", make_request()
        )
    )

    assert response.status == "success"
    assert checked == ["owner@example.com"]
    assert len(sent) == 1


def test_role_recipient_stays_pending_until_redeemed(verification_environment):
    """Sending a challenge does not prematurely verify the domain."""
    client, sent, notifications, processing_starts, success_emails = (
        verification_environment
    )
    response = asyncio.run(
        module.verify_email(
            "example.com", "security@example.com", "owner@example.com", make_request()
        )
    )

    assert response.status == "success"
    assert len(sent) == 1
    assert not any(key[0] == "xon_domains" for key in client.entities)
    assert notifications == []
    assert not processing_starts
    assert not success_emails

    token = sent[0][1]
    redeemed = asyncio.run(redeem_challenge(token))

    assert redeemed.status_code == 200
    assert b"Domain Verified Successfully" in redeemed.body
    domain_key = "xon_domains", "example.com_owner@example.com"
    assert client.entities[domain_key]["verified"] is True
    assert client.entities[domain_key]["email"] == "owner@example.com"
    assert client.entities[domain_key]["verified_via"] == "security@example.com"
    assert client.entities[domain_key][
        "token"
    ] == module.hash_domain_verification_token(token)
    assert notifications == ["example.com"]
    assert processing_starts == ["example.com"]
    assert success_emails == [
        ("owner@example.com", "203.0.113.10", "Test Browser", "Test OS")
    ]

    replay = asyncio.run(redeem_challenge(token))
    assert replay.status_code == 400
    assert b"Domain Verification Failed" in replay.body


def test_expired_challenge_cannot_verify_domain(verification_environment):
    """Expired challenges fail without creating a verified record."""
    client, sent, notifications, processing_starts, success_emails = (
        verification_environment
    )
    asyncio.run(
        module.verify_email(
            "example.com", "postmaster@example.com", "owner@example.com", make_request()
        )
    )
    token = sent[0][1]
    challenge_key = (
        "xon_domain_verification_challenges",
        module.hash_domain_verification_token(token),
    )
    client.entities[challenge_key]["expires_at"] = datetime.now(
        timezone.utc
    ) - timedelta(seconds=1)

    expired = asyncio.run(redeem_challenge(token))

    assert expired.status_code == 400
    assert b"Domain Verification Failed" in expired.body
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
        module.verify_email(
            "example.com", "security@example.com", "owner@example.com", make_request()
        )
    )
    assert first.status == "success"
    assert len(sent) == 1

    with pytest.raises(HTTPException) as throttled:
        asyncio.run(
            module.verify_email(
                "example.com",
                "security@example.com",
                "owner@example.com",
                make_request(),
            )
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
            module.verify_email(
                "example.com",
                f"{role}@example.com",
                "owner@example.com",
                make_request(),
            )
        )
        assert response.status == "success"

    with pytest.raises(HTTPException) as throttled:
        asyncio.run(
            module.verify_email(
                "example.com",
                "webmaster@example.com",
                "owner@example.com",
                make_request(),
            )
        )
    assert throttled.value.status_code == 429
    assert len(sent) == 2


def test_global_daily_budget_blocks_new_domains(verification_environment, monkeypatch):
    """The global daily budget caps challenges across unrelated domains."""
    _, sent, _, _, _ = verification_environment
    monkeypatch.setattr(module, "DOMAIN_EMAIL_GLOBAL_DAILY_BUDGET", 1)

    first = asyncio.run(
        module.verify_email(
            "example.com", "security@example.com", "owner@example.com", make_request()
        )
    )
    assert first.status == "success"

    with pytest.raises(HTTPException) as throttled:
        asyncio.run(
            module.verify_email(
                "other.com", "security@other.com", "owner@other.com", make_request()
            )
        )
    assert throttled.value.status_code == 429
    assert len(sent) == 1


def test_limits_fail_open_when_redis_unavailable(verification_environment, monkeypatch):
    """Challenges still send when Redis raises, so an outage cannot block users."""
    _, sent, _, _, _ = verification_environment
    monkeypatch.setattr(module, "redis_client", BrokenRedis())

    for role in ("security", "admin"):
        response = asyncio.run(
            module.verify_email(
                "example.com",
                f"{role}@example.com",
                "owner@example.com",
                make_request(),
            )
        )
        assert response.status == "success"
    assert len(sent) == 2


def issue_proof_challenge(domain, email):
    """Issue a DNS/HTML proof challenge and return its code."""
    response = asyncio.run(module.begin_proof_challenge(domain, email))
    assert response.status == "success"
    return response.domainVerification


def test_dns_proof_replay_without_challenge_is_rejected(
    verification_environment, monkeypatch
):
    """A publicly visible proof cannot create a record without a bound challenge."""
    client, _, notifications, processing_starts, success_emails = (
        verification_environment
    )
    monkeypatch.setattr(module.domcheck, "check", lambda *args, **kwargs: True)

    response = asyncio.run(
        module.verify_dns(
            "example.com",
            "attacker@evil.com",
            "stolen-public-code",
            "xon_verification",
            make_request(),
        )
    )

    assert response.status == "error"
    assert not any(key[0] == "xon_domains" for key in client.entities)
    assert notifications == []
    assert not processing_starts
    assert not success_emails


def test_dns_challenge_bound_to_other_email_is_rejected(
    verification_environment, monkeypatch
):
    """A challenge issued to one email cannot verify a different email."""
    client, _, _, processing_starts, _ = verification_environment
    monkeypatch.setattr(module.domcheck, "check", lambda *args, **kwargs: True)
    code = issue_proof_challenge("example.com", "owner@example.com")

    response = asyncio.run(
        module.verify_dns(
            "example.com", "attacker@evil.com", code, "xon_verification", make_request()
        )
    )

    assert response.status == "error"
    assert not any(key[0] == "xon_domains" for key in client.entities)
    assert not processing_starts


def test_dns_challenge_bound_to_other_domain_is_rejected(
    verification_environment, monkeypatch
):
    """A challenge issued for one domain cannot verify a different domain."""
    client, _, _, _, _ = verification_environment
    monkeypatch.setattr(module.domcheck, "check", lambda *args, **kwargs: True)
    code = issue_proof_challenge("example.com", "owner@example.com")

    response = asyncio.run(
        module.verify_dns(
            "other.com", "owner@example.com", code, "xon_verification", make_request()
        )
    )

    assert response.status == "error"
    assert not any(key[0] == "xon_domains" for key in client.entities)


def test_bound_dns_challenge_verifies_once(verification_environment, monkeypatch):
    """A bound challenge verifies its own email once and cannot be reused."""
    client, _, notifications, processing_starts, success_emails = (
        verification_environment
    )
    monkeypatch.setattr(module.domcheck, "check", lambda *args, **kwargs: True)
    code = issue_proof_challenge("example.com", "owner@example.com")

    response = asyncio.run(
        module.verify_dns(
            "example.com", "owner@example.com", code, "xon_verification", make_request()
        )
    )

    assert response.status == "success"
    domain_key = "xon_domains", "example.com_owner@example.com"
    assert client.entities[domain_key]["verified"] is True
    assert client.entities[domain_key]["mode"] == "dns_txt"
    assert notifications == ["example.com"]
    assert processing_starts == ["example.com"]
    assert len(success_emails) == 1

    client.entities.pop(domain_key)
    replay = asyncio.run(
        module.verify_dns(
            "example.com", "owner@example.com", code, "xon_verification", make_request()
        )
    )
    assert replay.status == "error"
    assert domain_key not in client.entities


def test_expired_dns_challenge_is_rejected(verification_environment, monkeypatch):
    """An expired challenge cannot create a verified record."""
    client, _, _, _, _ = verification_environment
    monkeypatch.setattr(module.domcheck, "check", lambda *args, **kwargs: True)
    code = issue_proof_challenge("example.com", "owner@example.com")
    challenge_key = (
        "xon_domain_proof_challenges",
        module.hash_domain_verification_token(code),
    )
    client.entities[challenge_key]["expires_at"] = datetime.now(
        timezone.utc
    ) - timedelta(seconds=1)

    response = asyncio.run(
        module.verify_dns(
            "example.com", "owner@example.com", code, "xon_verification", make_request()
        )
    )

    assert response.status == "error"
    assert not any(key[0] == "xon_domains" for key in client.entities)


def test_existing_domain_reverifies_without_challenge(
    verification_environment, monkeypatch
):
    """Already-verified domains keep re-verifying with their original code."""
    client, _, notifications, processing_starts, success_emails = (
        verification_environment
    )
    monkeypatch.setattr(module.domcheck, "check", lambda *args, **kwargs: True)
    domain_key = ("xon_domains", "example.com_owner@example.com")
    existing = FakeEntity(domain_key)
    existing.update(
        {
            "email": "owner@example.com",
            "domain": "example.com",
            "mode": "dns_txt",
            "token": "legacy-client-code",
            "verified": True,
        }
    )
    client.put(existing)

    response = asyncio.run(
        module.verify_dns(
            "example.com",
            "owner@example.com",
            "legacy-client-code",
            "xon_verification",
            make_request(),
        )
    )

    assert response.status == "success"
    assert client.entities[domain_key]["verified"] is True
    assert "last_verified" in client.entities[domain_key]
    assert notifications == ["example.com"]
    assert processing_starts == ["example.com"]
    assert len(success_emails) == 1


def test_html_proof_replay_without_challenge_is_rejected(
    verification_environment, monkeypatch
):
    """The HTML strategy also rejects unbound public proofs."""
    client, _, _, processing_starts, _ = verification_environment

    async def fake_check_file(domain, prefix, code):
        return True

    monkeypatch.setattr(module, "check_file", fake_check_file)

    response = asyncio.run(
        module.verify_html(
            "example.com",
            "attacker@evil.com",
            "stolen-public-code",
            "xon_verification",
            make_request(),
        )
    )

    assert response.status == "error"
    assert not any(key[0] == "xon_domains" for key in client.entities)
    assert not processing_starts


def test_bound_html_challenge_verifies_owner(verification_environment, monkeypatch):
    """A bound challenge lets the HTML strategy verify its own email."""
    client, _, notifications, processing_starts, _ = verification_environment

    async def fake_check_file(domain, prefix, code):
        return True

    monkeypatch.setattr(module, "check_file", fake_check_file)
    code = issue_proof_challenge("example.com", "owner@example.com")

    response = asyncio.run(
        module.verify_html(
            "example.com", "owner@example.com", code, "xon_verification", make_request()
        )
    )

    assert response.status == "success"
    domain_key = "xon_domains", "example.com_owner@example.com"
    assert client.entities[domain_key]["verified"] is True
    assert client.entities[domain_key]["mode"] == "html_file"
    assert notifications == ["example.com"]
    assert processing_starts == ["example.com"]


def test_failed_proof_check_does_not_consume_challenge(
    verification_environment, monkeypatch
):
    """A DNS lookup failure leaves the challenge pending for retry."""
    client, _, _, _, _ = verification_environment
    monkeypatch.setattr(module.domcheck, "check", lambda *args, **kwargs: False)
    code = issue_proof_challenge("example.com", "owner@example.com")

    response = asyncio.run(
        module.verify_dns(
            "example.com", "owner@example.com", code, "xon_verification", make_request()
        )
    )

    assert response.status == "error"
    challenge_key = (
        "xon_domain_proof_challenges",
        module.hash_domain_verification_token(code),
    )
    assert client.entities[challenge_key]["used"] is False


def test_limits_disabled_skips_redis(verification_environment, monkeypatch):
    """Disabling the feature flag bypasses all Redis-backed limits."""
    _, sent, _, _, _ = verification_environment
    monkeypatch.setattr(module, "redis_client", BrokenRedis())
    monkeypatch.setattr(module, "DOMAIN_EMAIL_LIMITS_ENABLED", False)

    for _ in range(3):
        response = asyncio.run(
            module.verify_email(
                "example.com",
                "security@example.com",
                "owner@example.com",
                make_request(),
            )
        )
        assert response.status == "success"
    assert len(sent) == 3
