"""Regression tests: phishing cache is partitioned by privilege tier."""

import os

import pytest

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

from api.v1 import domain_phishing as module


class FakeRedis:
    """In-memory Redis stand-in for the cache functions."""

    def __init__(self):
        self.store = {}

    def get(self, key):
        """Return a stored value or None."""
        return self.store.get(key)

    def setex(self, key, _ttl, value):
        """Store a value under a key."""
        self.store[key] = value


@pytest.fixture
def fake_redis(monkeypatch):
    """Point the cache functions at an in-memory store."""
    client = FakeRedis()
    monkeypatch.setattr(module, "redis_client", client)
    return client


def test_basic_blob_does_not_satisfy_authenticated_read(fake_redis):
    """A blob cached at the basic tier is not returned for an authenticated read."""
    module.cache_result("example.com", {"total_scanned": 1}, detailed=False)

    assert module.get_cached_result("example.com", False) == {"total_scanned": 1}
    assert module.get_cached_result("example.com", True) is None


def test_whois_blob_does_not_satisfy_anonymous_read(fake_redis):
    """A blob cached at the whois tier is not returned for an anonymous read."""
    module.cache_result("example.com", {"total_scanned": 2}, detailed=True)

    assert module.get_cached_result("example.com", True) == {"total_scanned": 2}
    assert module.get_cached_result("example.com", False) is None


def test_tiers_use_distinct_keys(fake_redis):
    """The two tiers write to separate Redis keys for the same domain."""
    module.cache_result("example.com", {"total_scanned": 1}, detailed=False)
    module.cache_result("example.com", {"total_scanned": 2}, detailed=True)

    assert sorted(fake_redis.store) == [
        "phishing_check:basic:example.com",
        "phishing_check:whois:example.com",
    ]
