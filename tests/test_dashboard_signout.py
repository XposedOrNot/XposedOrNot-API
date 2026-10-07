"""Regression tests for dashboard sign-out magic-link revocation."""

import asyncio
import hashlib
import os
import time

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
from utils.token import generate_confirmation_token


class FakeEntity(dict):
    """Minimal datastore entity used by the sign-out tests."""

    def __init__(self, key):
        super().__init__()
        self.key = key


class FakeDatastoreClient:
    """In-memory datastore client used by the sign-out tests."""

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
    """Install an in-memory datastore and silence the exception mailer."""
    client = FakeDatastoreClient()
    monkeypatch.setattr(module, "ds_client", client)
    monkeypatch.setattr(module.datastore, "Entity", FakeEntity)

    async def fake_exception_email(**kwargs):
        return None

    monkeypatch.setattr(module, "send_exception_email", fake_exception_email)
    return client


def make_token(email):
    """Generate a real signed magic-link token for the email."""
    return asyncio.run(generate_confirmation_token(email))


def login(client, email, token):
    """Redeem a magic link through the real domain_verify handler."""
    return asyncio.run(module.domain_verify.__wrapped__(make_request(), token, None))


def sign_out(email, token):
    """Invoke the real sign-out handler without rate-limiter state."""
    return asyncio.run(
        module.dashboard_sign_out.__wrapped__(
            make_request("/v1/dashboard/sign-out"), email=email, token=token
        )
    )


def session_key(email):
    return "xon_domains_session", email


def revocation_key(token):
    return "xon_revoked_magic_tokens", hashlib.sha256(token.encode("utf-8")).hexdigest()


def test_login_and_repeat_click_still_work(env):
    """Redeeming a magic link twice without sign-out keeps working."""
    token = make_token("owner@example.com")

    first = login(env, "owner@example.com", token)
    assert first.status_code == 200
    assert session_key("owner@example.com") in env.entities

    second = login(env, "owner@example.com", token)
    assert second.status_code == 200
    assert env.entities[session_key("owner@example.com")]["domain_magic"] == token


def test_signout_deletes_session_and_revokes_token(env):
    """Sign-out removes the session and records the token as revoked."""
    token = make_token("owner@example.com")
    login(env, "owner@example.com", token)

    response = sign_out("owner@example.com", token)

    assert response.status == "success"
    assert session_key("owner@example.com") not in env.entities
    revoked = env.entities[revocation_key(token)]
    assert revoked["email"] == "owner@example.com"
    assert revoked["expires_at"] > revoked["revoked_at"]


def test_replayed_token_cannot_recreate_session_after_signout(env):
    """A signed-out magic link must not restore dashboard access."""
    token = make_token("owner@example.com")
    login(env, "owner@example.com", token)
    sign_out("owner@example.com", token)

    replay = login(env, "owner@example.com", token)

    assert replay.status_code == 404
    assert session_key("owner@example.com") not in env.entities


def test_new_login_after_signout_works(env):
    """A freshly issued magic link still signs the user in after sign-out."""
    old_token = make_token("owner@example.com")
    login(env, "owner@example.com", old_token)
    sign_out("owner@example.com", old_token)

    time.sleep(1.1)
    new_token = make_token("owner@example.com")
    assert new_token != old_token

    response = login(env, "owner@example.com", new_token)

    assert response.status_code == 200
    assert env.entities[session_key("owner@example.com")]["domain_magic"] == new_token


def test_signout_with_wrong_token_revokes_nothing(env):
    """A mismatched token is rejected and leaves the session intact."""
    token = make_token("owner@example.com")
    login(env, "owner@example.com", token)
    intruder_token = make_token("intruder@example.com")

    with pytest.raises(HTTPException) as denied:
        sign_out("owner@example.com", intruder_token)

    assert denied.value.status_code == 401
    assert session_key("owner@example.com") in env.entities
    assert revocation_key(intruder_token) not in env.entities


def test_signout_without_session_is_idempotent(env):
    """Signing out with no active session succeeds without revoking."""
    token = make_token("owner@example.com")

    response = sign_out("owner@example.com", token)

    assert response.status == "success"
    assert revocation_key(token) not in env.entities
