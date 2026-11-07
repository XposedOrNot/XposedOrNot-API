"""Regression tests: a withdrawn monitor target is not immediately re-invitable."""

import datetime
import os

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

from api.v1 import monitor as module


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def test_target_withdrawal_blocks_reinvite_within_cooldown():
    """A target-revoked edge blocks a fresh invite during the cooldown window."""
    now = _now()
    edge = {
        "status": module.STATUS_REVOKED,
        "revoked_by": "target",
        "responded_at": now,
    }
    assert module._existing_edge_blocks_invite(edge, now) is True


def test_target_withdrawal_allows_reinvite_after_cooldown():
    """Past the cooldown, a target-revoked edge no longer blocks."""
    now = _now()
    old = now - datetime.timedelta(days=module.REJECT_COOLDOWN_DAYS + 1)
    edge = {
        "status": module.STATUS_REVOKED,
        "revoked_by": "target",
        "responded_at": old,
    }
    assert module._existing_edge_blocks_invite(edge, now) is False


def test_requester_revoke_does_not_block_reinvite():
    """A requester-side revoke is the requester's own choice and does not block."""
    now = _now()
    edge = {
        "status": module.STATUS_REVOKED,
        "revoked_by": "requester",
        "responded_at": now,
    }
    assert module._existing_edge_blocks_invite(edge, now) is False


class _FakeQuery:
    def __init__(self, records):
        self._records = records

    def add_filter(self, *_args, **_kwargs):
        """Accept and ignore filters."""

    def fetch(self):
        """Return the seeded records."""
        return list(self._records)


class _FakeClient:
    def __init__(self, records):
        self._records = records
        self.put_calls = []

    def query(self, **_kwargs):
        """Return a query over the seeded records."""
        return _FakeQuery(self._records)

    def put(self, record):
        """Capture a written record."""
        self.put_calls.append(record)


def test_global_optout_cascade_marks_edges_target_revoked(monkeypatch):
    """The alert opt-out cascade tags revoked edges as target-driven."""
    edge = {"status": module.STATUS_ACCEPTED, "target_email": "victim@example.com"}
    client = _FakeClient([edge])
    monkeypatch.setattr(module, "ds_client", client)

    count = module.revoke_monitors_for_target("victim@example.com")

    assert count == 1
    assert edge["status"] == module.STATUS_REVOKED
    assert edge["revoked_by"] == "target"
    assert edge["unSubscribeOn"] is True
