"""Regression tests for dashboard login challenge / session bearer separation.

Covers Codex finding #2 and its four confirmed bypasses: a signed-out or
replayed login link must never recreate a dashboard session.
"""

import asyncio
import datetime
import hashlib
import os

import pytest
from fastapi import HTTPException
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
from utils import token as token_module


class FakeEntity(dict):
    """Minimal datastore entity used by the session tests."""

    def __init__(self, key):
        super().__init__()
        self.key = key


class FakeDatastoreClient:
    """In-memory datastore client with a no-op transaction context."""

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
        from contextlib import nullcontext

        return nullcontext()


def make_request(path="/v1/domain-verify"):
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
    """Install an in-memory datastore shared by the route module and validator."""
    client = FakeDatastoreClient()
    monkeypatch.setattr(module, "ds_client", client)
    monkeypatch.setattr(module.datastore, "Entity", FakeEntity)

    async def fake_exception_email(**kwargs):
        return None

    monkeypatch.setattr(module, "send_exception_email", fake_exception_email)
    return client


def issue_challenge(email, dashboard=""):
    """Issue a login challenge as /v1/domain-alert would."""
    return module.create_login_challenge(email, dashboard)


def redeem(challenge):
    """Redeem a login challenge through the real domain_verify handler."""
    return asyncio.run(
        module.domain_verify.__wrapped__(make_request(), challenge, None)
    )


def sign_out(email, token):
    """Invoke the real sign-out handler without rate-limiter state."""
    return asyncio.run(
        module.dashboard_sign_out.__wrapped__(
            make_request("/v1/dashboard/sign-out"), email=email, token=token
        )
    )


def session_key(email):
    return "xon_domains_session", email


def bearer_from_link(response):
    """Extract the token (session bearer) from the success page link."""
    import re

    body = response.body.decode()
    match = re.search(r"token=([A-Za-z0-9_\-=]+)", body)
    return match.group(1) if match else None


def test_login_challenge_mints_distinct_random_bearer(env):
    """Redeeming a challenge creates a session whose bearer is not the challenge."""
    challenge = issue_challenge("owner@example.com")
    response = redeem(challenge)

    assert response.status_code == 200
    bearer = bearer_from_link(response)
    assert bearer and bearer != challenge
    session = env.entities[session_key("owner@example.com")]
    assert session["domain_magic"] == bearer
    assert token_module.validate_dashboard_session(env, "owner@example.com", bearer)
    assert not token_module.validate_dashboard_session(
        env, "owner@example.com", challenge
    )


def test_challenge_is_single_use(env):
    """A login challenge cannot be redeemed twice (superseded-link replay)."""
    challenge = issue_challenge("owner@example.com")
    first = redeem(challenge)
    assert first.status_code == 200
    env.delete(session_key("owner@example.com"))

    second = redeem(challenge)
    assert second.status_code == 404
    assert session_key("owner@example.com") not in env.entities


def test_signout_deletes_session_and_bearer_cannot_be_reused(env):
    """After sign-out the random bearer is dead and nothing can revive it."""
    challenge = issue_challenge("owner@example.com")
    bearer = bearer_from_link(redeem(challenge))

    response = sign_out("owner@example.com", bearer)
    assert response.status == "success"
    assert session_key("owner@example.com") not in env.entities
    assert not token_module.validate_dashboard_session(env, "owner@example.com", bearer)
    replay = redeem(challenge)
    assert replay.status_code == 404
    assert session_key("owner@example.com") not in env.entities


def test_same_second_reissue_does_not_reproduce_a_known_bearer(env):
    """Two challenges issued in the same second yield different bearers."""
    c1 = issue_challenge("owner@example.com")
    c2 = issue_challenge("owner@example.com")
    assert c1 != c2

    b1 = bearer_from_link(redeem(c1))
    env.delete(session_key("owner@example.com"))
    b2 = bearer_from_link(redeem(c2))
    assert b1 != b2


def test_expiry_cannot_be_reset_by_replay(env):
    """An absolute created_at cap is enforced and never rewritten on redemption."""
    challenge = issue_challenge("owner@example.com")
    bearer = bearer_from_link(redeem(challenge))
    session = env.entities[session_key("owner@example.com")]

    old = datetime.datetime.utcnow() - datetime.timedelta(hours=13)
    session["magic_timestamp"] = old
    session["created_at"] = old
    assert not token_module.validate_dashboard_session(env, "owner@example.com", bearer)

    replay = redeem(challenge)
    assert replay.status_code == 404
    assert env.entities[session_key("owner@example.com")]["created_at"] == old


def test_expired_challenge_is_rejected(env):
    """A login challenge past its TTL cannot create a session."""
    challenge = issue_challenge("owner@example.com")
    challenge_key = (
        "xon_dashboard_login_challenges",
        hashlib.sha256(challenge.encode("utf-8")).hexdigest(),
    )
    env.entities[challenge_key]["expires_at"] = datetime.datetime.now(
        datetime.timezone.utc
    ) - datetime.timedelta(seconds=1)

    response = redeem(challenge)
    assert response.status_code == 404
    assert session_key("owner@example.com") not in env.entities


def test_unknown_challenge_is_rejected(env):
    """A forged/unknown challenge value cannot create a session."""
    response = redeem("totally-made-up-challenge-value")
    assert response.status_code == 404
    assert env.entities == {}


def test_signout_wrong_bearer_is_rejected(env):
    """A mismatched bearer cannot sign out another session."""
    challenge = issue_challenge("owner@example.com")
    bearer = bearer_from_link(redeem(challenge))

    with pytest.raises(HTTPException) as denied:
        sign_out("owner@example.com", "someone-elses-bearer")

    assert denied.value.status_code == 401
    assert session_key("owner@example.com") in env.entities
    assert env.entities[session_key("owner@example.com")]["domain_magic"] == bearer


def test_signout_without_session_is_idempotent(env):
    """Signing out with no active session succeeds without error."""
    response = sign_out("owner@example.com", "any-bearer")
    assert response.status == "success"
    assert env.entities == {}


def test_dashboard_preference_is_carried_through_challenge(env):
    """The dashboard preference stored on the challenge reaches the session."""
    challenge = issue_challenge("owner@example.com", dashboard="my")
    response = redeem(challenge)
    assert response.status_code == 200
    assert "my-dashboard.html" in response.body.decode()
    assert env.entities[session_key("owner@example.com")]["dashboard"] == "my"
