"""Regression tests: shield-suppressed and absent lookups are indistinguishable."""

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

from api.v1 import analytics as analytics_module
from api.v1 import breaches as breaches_module


class FakeDatastoreClient:
    """In-memory datastore client used by the oracle tests."""

    def __init__(self):
        self.entities = {}

    def key(self, kind, name):
        """Return an in-memory key."""
        return kind, name

    def get(self, key):
        """Return an entity by key."""
        return self.entities.get(key)

    def get_multi(self, keys):
        """Return stored entities for the requested keys."""
        return [self.entities[key] for key in keys if key in self.entities]


def make_request(path):
    """Create a minimal request with stable client metadata."""
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [(b"host", b"api.xposedornot.com")],
            "query_string": b"",
            "client": ("203.0.113.10", 12345),
            "scheme": "https",
            "server": ("api.xposedornot.com", 443),
        }
    )


@pytest.fixture
def oracle_env(monkeypatch):
    """Stub datastore, caches and exposure reads for both modules."""

    async def no_exposure(email):
        return {}

    async def fake_exception_email(**kwargs):
        return None

    client = FakeDatastoreClient()
    monkeypatch.setattr(breaches_module, "ds_client", client)
    monkeypatch.setattr(breaches_module, "set_cached_shield", lambda e, s: None)
    monkeypatch.setattr(breaches_module, "get_cached_breaches", lambda key: None)
    monkeypatch.setattr(breaches_module, "get_exposure", no_exposure)
    monkeypatch.setattr(breaches_module, "send_exception_email", fake_exception_email)
    monkeypatch.setattr(analytics_module, "ds_client", client)
    monkeypatch.setattr(analytics_module, "set_cached_shield", lambda e, s: None)
    monkeypatch.setattr(analytics_module, "get_cached_analytics", lambda key: None)
    monkeypatch.setattr(analytics_module, "send_exception_email", fake_exception_email)
    return client


def set_shield(monkeypatch, module, value):
    """Force the cached shield state for one lookup."""
    monkeypatch.setattr(module, "get_cached_shield", lambda e: value)


def test_check_email_shielded_matches_absent(oracle_env, monkeypatch):
    """Shield-suppressed and unknown addresses get identical check-email bodies."""
    set_shield(monkeypatch, breaches_module, True)
    shielded = asyncio.run(
        breaches_module.search_email.__wrapped__(
            make_request("/v1/check-email/a"), "shielded@example.com", False
        )
    )
    set_shield(monkeypatch, breaches_module, False)
    absent = asyncio.run(
        breaches_module.search_email.__wrapped__(
            make_request("/v1/check-email/b"), "absent@example.com", False
        )
    )

    assert type(shielded) is type(absent)
    assert shielded.model_dump() == absent.model_dump()


def test_breach_analytics_shielded_matches_absent(oracle_env, monkeypatch):
    """Shield-suppressed and unknown addresses get identical analytics bodies."""
    set_shield(monkeypatch, breaches_module, True)
    shielded = asyncio.run(
        breaches_module.search_data_breaches.__wrapped__(
            make_request("/v1/breach-analytics"), "shielded@example.com", None
        )
    )
    set_shield(monkeypatch, breaches_module, False)
    absent = asyncio.run(
        breaches_module.search_data_breaches.__wrapped__(
            make_request("/v1/breach-analytics"), "absent@example.com", None
        )
    )

    assert type(shielded) is type(absent)
    assert shielded.model_dump() == absent.model_dump()


def test_analytics_hierarchy_shielded_matches_absent(oracle_env, monkeypatch):
    """Shield-suppressed and unknown addresses get identical hierarchy responses."""
    set_shield(monkeypatch, analytics_module, True)
    shielded = asyncio.run(
        analytics_module.get_analytics.__wrapped__(
            make_request("/v1/analytics/a"), "shielded@example.com"
        )
    )
    set_shield(monkeypatch, analytics_module, False)
    absent = asyncio.run(
        analytics_module.get_analytics.__wrapped__(
            make_request("/v1/analytics/b"), "absent@example.com"
        )
    )

    assert shielded.status_code == absent.status_code
    assert shielded.body == absent.body


def test_check_email_unusable_record_matches_absent(oracle_env, monkeypatch):
    """An indexed record with no usable site is indistinguishable from absent."""
    set_shield(monkeypatch, breaches_module, False)

    async def empty_site_exposure(email):
        return {"site": " ; ; "}

    monkeypatch.setattr(breaches_module, "get_exposure", empty_site_exposure)
    unusable = asyncio.run(
        breaches_module.search_email.__wrapped__(
            make_request("/v1/check-email/c"), "oddrow@example.com", False
        )
    )

    async def no_exposure(email):
        return {}

    monkeypatch.setattr(breaches_module, "get_exposure", no_exposure)
    absent = asyncio.run(
        breaches_module.search_email.__wrapped__(
            make_request("/v1/check-email/d"), "absent@example.com", False
        )
    )

    assert type(unusable) is type(absent)
    assert unusable.model_dump() == absent.model_dump()
