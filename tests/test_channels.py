"""Tests for the notification-channel core and the generic webhook channel.

Runs the real service, auth and route code with in-memory fakes for the only
I/O involved: Datastore, outbound HTTP (httpx), DNS resolution, the rate
limiter and the exception mailer.
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-lines

import asyncio
import json
import os
import sys
import time
import types
from collections import namedtuple
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.fernet import Fernet
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
os.environ.setdefault("ENCRYPTION_KEY", Fernet.generate_key().decode())


_limiter_stub = types.ModuleType("utils.custom_limiter")


def _passthrough_rate_limiter(_rate_limit_str, message=None):  # noqa: ARG001
    def decorator(func):
        return func

    return decorator


_limiter_stub.custom_rate_limiter = _passthrough_rate_limiter

_mailer_stub = types.ModuleType("services.send_email")
EXCEPTION_EMAILS = []


async def _record_exception_email(**kwargs):
    EXCEPTION_EMAILS.append(kwargs)


_mailer_stub.send_exception_email = _record_exception_email

_ORIGINALS = {}
for _name, _stub in (
    ("utils.custom_limiter", _limiter_stub),
    ("services.send_email", _mailer_stub),
):
    _ORIGINALS[_name] = sys.modules.get(_name)
    sys.modules[_name] = _stub

# pylint: disable=wrong-import-position
from api.v1 import slack as slack_routes  # noqa: E402
from api.v1 import webhook as webhook_routes  # noqa: E402
from models.channels import ChannelConfigRequest, ChannelSetupRequest  # noqa: E402
from services import messaging, slack, webhook  # noqa: E402
from utils import channel_auth, http_client, webhook_security  # noqa: E402

for _name, _orig in _ORIGINALS.items():
    if _orig is not None:
        sys.modules[_name] = _orig
    else:
        del sys.modules[_name]


FakeKey = namedtuple("FakeKey", "kind name")


class FakeEntity(dict):
    """Minimal datastore entity."""

    def __init__(self, key=None, **kwargs):
        super().__init__(**kwargs)
        self.key = key


class FakeQuery:
    """Equality-filter query over the fake store."""

    def __init__(self, store, kind):
        self.store = store
        self.kind = kind
        self.filters = []

    def add_filter(self, prop, op, value):
        assert op == "="
        self.filters.append((prop, value))

    def fetch(self, limit=None):
        out = []
        for key, entity in self.store.entities.items():
            if key.kind != self.kind:
                continue
            if all(entity.get(p) == v for p, v in self.filters):
                out.append(entity)
        return out[:limit] if limit else out


class FakeDatastoreClient:
    """In-memory Datastore client."""

    def __init__(self):
        self.entities = {}

    def key(self, kind, name):
        return FakeKey(kind, name)

    def get(self, key):
        return self.entities.get(key)

    def put(self, entity):
        self.entities[entity.key] = entity

    def delete(self, key):
        self.entities.pop(key, None)

    def query(self, kind):
        return FakeQuery(self, kind)


class FakeResponse:
    """Minimal httpx response."""

    def __init__(self, status_code, headers=None):
        self.status_code = status_code
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=httpx.Request("POST", "https://x"),
                response=httpx.Response(self.status_code),
            )


class FakeAsyncClient:
    """Records outbound posts; per-URL scripted responses."""

    def __init__(self):
        self.posts = []
        self.responses = {}
        self.is_closed = False

    async def post(self, url, json=None, content=None, headers=None, timeout=None):
        self.posts.append(
            {
                "url": url,
                "json": json,
                "content": content,
                "headers": headers or {},
                "timeout": timeout,
            }
        )
        scripted = self.responses.get(url)
        if scripted is None:
            return FakeResponse(200)
        if isinstance(scripted, Exception):
            raise scripted
        code = scripted.pop(0) if len(scripted) > 1 else scripted[0]
        return FakeResponse(code)


def _public_getaddrinfo(host, port, proto=None):  # noqa: ARG001
    if host.startswith("internal") or host in ("localhost",):
        ip = "10.0.0.5"
    elif host == "unresolvable.test":
        raise OSError("no such host")
    else:
        ip = "93.184.216.34"
    return [(2, 1, 6, "", (ip, port))]


def make_request(headers=None, path="/v1/webhook/setup", query=""):
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "root_path": "",
        "scheme": "https",
        "server": ("api.xposedornot.com", 443),
        "query_string": query.encode(),
        "headers": raw_headers,
        "client": ("203.0.113.9", 1234),
    }
    return Request(scope)


OWNER = "owner@example.com"
OTHER = "other@rival.com"
DOMAIN = "example.com"
API_KEY = "key-owner-123"
SESSION = "magic-token-abc"
SLACK_URL = "https://hooks.slack.com/services/" + "/".join(
    ["T" + "0" * 8, "B" + "0" * 8, "X" * 24]
)
TEAMS_URL = "https://contoso.webhook.office.com/webhookb2/abc/IncomingWebhook/def"
HOOK_URL = "https://hooks.example.org/xon"

VALID_URL = {"slack": SLACK_URL, "teams": TEAMS_URL}


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def env(monkeypatch):
    """Wire every module under test to fresh fakes."""
    ds = FakeDatastoreClient()
    http = FakeAsyncClient()
    monkeypatch.setattr(messaging, "datastore_client", ds)
    monkeypatch.setattr(webhook, "datastore_client", ds)
    monkeypatch.setattr(channel_auth, "ds_client", ds)
    monkeypatch.setattr(http_client, "get_http_client", lambda: http)
    monkeypatch.setattr(webhook_security.socket, "getaddrinfo", _public_getaddrinfo)
    monkeypatch.setattr(messaging, "WEBHOOK_BACKOFF_BASE", 0)
    EXCEPTION_EMAILS.clear()

    ds.put(FakeEntity(FakeKey("xon_api_key", OWNER), api_key=API_KEY))
    ds.put(
        FakeEntity(
            FakeKey("xon_domains_session", OWNER),
            domain_magic=SESSION,
            magic_timestamp=datetime.now(timezone.utc),
        )
    )
    ds.put(
        FakeEntity(
            FakeKey("xon_domains", f"{DOMAIN}_{OWNER}"),
            email=OWNER,
            domain=DOMAIN,
            verified=True,
        )
    )
    ds.put(FakeEntity(FakeKey("xon_api_key", OTHER), api_key="key-other"))
    ds.put(
        FakeEntity(
            FakeKey("xon_domains", f"rival.com_{OTHER}"),
            email=OTHER,
            domain="rival.com",
            verified=True,
        )
    )
    return types.SimpleNamespace(ds=ds, http=http)


def req(platform, action, **kw):
    data = {"domain": DOMAIN, "action": action}
    if action == "setup" and "webhook" not in kw:
        data["webhook"] = VALID_URL.get(platform, HOOK_URL)
    data.update(kw)
    return ChannelSetupRequest(**data)


def row(env, platform, email=OWNER, domain=DOMAIN):
    kind = messaging.PLATFORM_MAP[platform]
    return env.ds.get(FakeKey(kind, f"{email}_{domain}"))


def code_from_slack_post(post):
    for block in post["json"]["blocks"]:
        text = block.get("text", {}).get("text", "")
        if text.startswith("```"):
            return text.strip("`")
    raise AssertionError("no code in slack post")


def _find_code(node):
    if isinstance(node, dict):
        for v in node.values():
            found = _find_code(v)
            if found:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find_code(item)
            if found:
                return found
    elif isinstance(node, str):
        stripped = node.strip("*")
        if len(stripped) == 8 and stripped.isalnum() and stripped == stripped.upper():
            return stripped
    return None


def code_from_webhook_post(post):
    return json.loads(post["content"])["verification_code"]


@pytest.mark.parametrize("platform", ["slack", "teams"])
def test_chat_setup_stores_pending_row_and_posts_code(env, platform):
    ok, code = run(
        messaging.setup_messaging_channel(req(platform, "setup"), platform, OWNER)
    )
    assert (ok, code) == (True, "")
    assert len(env.http.posts) == 1
    post = env.http.posts[0]
    assert post["url"] == VALID_URL[platform]
    assert "XposedOrNot" in json.dumps(post["json"])

    entity = row(env, platform)
    assert entity is not None
    assert entity["owner_email"] == OWNER
    assert entity["created_by"] == OWNER
    assert entity["domain"] == DOMAIN
    assert entity["scope"] == "domain"
    assert entity["source"] == "community"
    assert entity["verified"] is False and entity["active"] is False
    assert "custid" not in entity and "token" not in entity and "tokens" not in entity
    assert entity["webhook"] != VALID_URL[platform]
    assert webhook_security.decrypt_webhook(entity["webhook"]) == VALID_URL[platform]
    assert len(entity["verify_token"]) == 8
    sent = (
        code_from_slack_post(post) if platform == "slack" else _find_code(post["json"])
    )
    assert sent == entity["verify_token"]


@pytest.mark.parametrize("platform", ["slack", "teams"])
def test_chat_setup_rejects_wrong_platform_url(env, platform):
    wrong = TEAMS_URL if platform == "slack" else SLACK_URL
    with pytest.raises(HTTPException) as exc:
        run(
            messaging.setup_messaging_channel(
                req(platform, "setup", webhook=wrong), platform, OWNER
            )
        )
    assert exc.value.status_code == 400
    assert env.http.posts == [] and row(env, platform) is None


def test_teams_setup_ssrf_shaped_url_rejected(env):
    bad = "https://169.254.169.254/x.webhook.office.com/webhookb2/abc"
    with pytest.raises(HTTPException) as exc:
        run(
            messaging.setup_messaging_channel(
                req("teams", "setup", webhook=bad), "teams", OWNER
            )
        )
    assert exc.value.status_code == 400


@pytest.mark.parametrize("platform", ["slack", "teams"])
def test_chat_setup_webhook_failure_creates_nothing(env, platform):
    env.http.responses[VALID_URL[platform]] = [404]
    with pytest.raises(HTTPException) as exc:
        run(messaging.setup_messaging_channel(req(platform, "setup"), platform, OWNER))
    assert exc.value.status_code == 400
    assert row(env, platform) is None


@pytest.mark.parametrize("platform", ["slack", "teams"])
def test_chat_verify_then_conflict_then_delete(env, platform):
    run(messaging.setup_messaging_channel(req(platform, "setup"), platform, OWNER))
    code = row(env, platform)["verify_token"]

    with pytest.raises(HTTPException) as exc:
        run(
            messaging.verify_messaging_channel(
                req(platform, "verify", verify_token="WRONG000"), platform, OWNER
            )
        )
    assert exc.value.status_code == 403
    assert row(env, platform)["verified"] is False

    with pytest.raises(HTTPException) as exc:
        run(
            messaging.verify_messaging_channel(
                req(platform, "verify", verify_token=code), platform, OTHER
            )
        )
    assert exc.value.status_code == 404

    assert (
        run(
            messaging.verify_messaging_channel(
                req(platform, "verify", verify_token=code), platform, OWNER
            )
        )
        is True
    )
    entity = row(env, platform)
    assert entity["verified"] is True and entity["active"] is True
    assert isinstance(entity["verified_at"], datetime)
    assert len(env.http.posts) == 2
    assert "Verification Successful" in json.dumps(env.http.posts[1]["json"])

    with pytest.raises(HTTPException) as exc:
        run(messaging.setup_messaging_channel(req(platform, "setup"), platform, OWNER))
    assert exc.value.status_code == 409

    config = run(messaging.get_channel_config(DOMAIN, OWNER, platform))
    assert config["email"] == OWNER
    assert config["webhook"] == VALID_URL[platform]
    assert config["verified"] is True and config["active"] is True
    assert "custid" not in config
    assert config["verified_at"].startswith(str(datetime.now(timezone.utc).year))

    assert run(messaging.get_channel_config(DOMAIN, OTHER, platform)) is None

    with pytest.raises(HTTPException) as exc:
        run(
            messaging.delete_messaging_channel(req(platform, "delete"), platform, OTHER)
        )
    assert exc.value.status_code == 404
    assert (
        run(
            messaging.delete_messaging_channel(req(platform, "delete"), platform, OWNER)
        )
        is True
    )
    assert row(env, platform) is None
    with pytest.raises(HTTPException) as exc:
        run(
            messaging.delete_messaging_channel(req(platform, "delete"), platform, OWNER)
        )
    assert exc.value.status_code == 404


@pytest.mark.parametrize("platform", ["slack", "teams"])
def test_chat_unverified_channel_can_be_reinitialised(env, platform):
    run(messaging.setup_messaging_channel(req(platform, "setup"), platform, OWNER))
    run(messaging.setup_messaging_channel(req(platform, "setup"), platform, OWNER))
    assert len(env.http.posts) == 2
    assert row(env, platform)["verified"] is False


def test_verify_missing_code_or_missing_row(env):
    with pytest.raises(HTTPException) as exc:
        run(messaging.verify_messaging_channel(req("slack", "verify"), "slack", OWNER))
    assert exc.value.status_code == 400
    with pytest.raises(HTTPException) as exc:
        run(
            messaging.verify_messaging_channel(
                req("slack", "verify", verify_token="ABCD1234"), "slack", OWNER
            )
        )
    assert exc.value.status_code == 404


def test_setup_requires_owner_email(env):
    with pytest.raises(HTTPException) as exc:
        run(messaging.setup_messaging_channel(req("slack", "setup"), "slack", ""))
    assert exc.value.status_code == 400


def _assert_signed(post, secret, event):
    headers = post["headers"]
    assert headers["X-XON-Event"] == event
    assert headers["User-Agent"] == "XposedOrNot-Webhook/1.0"
    assert headers["Content-Type"] == "application/json"
    sig = headers["X-XON-Signature"]
    assert sig.startswith("sha256=")
    expected = messaging.compute_webhook_signature(
        secret, headers["X-XON-Timestamp"], post["content"]
    )
    assert sig == f"sha256={expected}"
    assert abs(int(headers["X-XON-Timestamp"]) - int(time.time())) < 5
    assert post["timeout"] is not None


def test_webhook_setup_new_channel_signs_ping_and_returns_secret_once(env):
    request = req(
        "webhook",
        "setup",
        custom_headers={"Authorization": "Bearer abc", "X-Team": "sec"},
    )
    ok, secret = run(messaging.setup_webhook_channel(request, OWNER))
    assert ok is True and len(secret) == 64 and int(secret, 16) >= 0

    assert len(env.http.posts) == 1
    post = env.http.posts[0]
    assert post["url"] == HOOK_URL
    body = json.loads(post["content"])
    assert body["event"] == "verification" and body["service"] == "XposedOrNot"
    assert body["domain"] == DOMAIN
    assert post["headers"]["Authorization"] == "Bearer abc"
    assert post["headers"]["X-Team"] == "sec"
    _assert_signed(post, secret, "verification")

    entity = row(env, "webhook")
    assert entity["owner_email"] == OWNER and entity["source"] == "community"
    assert entity["verified"] is False and entity["active"] is False
    assert webhook_security.decrypt_webhook(entity["signing_secret"]) == secret
    assert json.loads(webhook_security.decrypt_webhook(entity["custom_headers"])) == {
        "Authorization": "Bearer abc",
        "X-Team": "sec",
    }
    assert entity["verify_token"] == body["verification_code"]
    assert "custid" not in entity and "token" not in entity


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.org/xon",
        "https://internal.example.org/hook",
        "https://unresolvable.test/hook",
        "https://" + "a" * 2100 + ".com/",
        "https:///nohost",
    ],
)
def test_webhook_setup_rejects_unsafe_urls(env, url):
    with pytest.raises(HTTPException) as exc:
        run(
            messaging.setup_webhook_channel(req("webhook", "setup", webhook=url), OWNER)
        )
    assert exc.value.status_code == 400
    assert env.http.posts == [] and row(env, "webhook") is None


@pytest.mark.parametrize(
    "headers",
    [
        {"X-XON-Signature": "spoof"},
        {"Host": "evil"},
        {"Content-Type": "text/plain"},
        {"Bad Name": "x"},
        {"X-Inject": "a\r\nb"},
        {f"H{i}": "v" for i in range(11)},
    ],
)
def test_webhook_setup_rejects_bad_custom_headers(env, headers):
    with pytest.raises(HTTPException) as exc:
        run(
            messaging.setup_webhook_channel(
                req("webhook", "setup", custom_headers=headers), OWNER
            )
        )
    assert exc.value.status_code == 400
    assert row(env, "webhook") is None


def test_webhook_setup_ping_failure_keeps_pending_row_and_reshows_secret(env):
    env.http.responses[HOOK_URL] = [500]
    with pytest.raises(HTTPException) as exc:
        run(messaging.setup_webhook_channel(req("webhook", "setup"), OWNER))
    assert exc.value.status_code == 400
    assert len(env.http.posts) == messaging.WEBHOOK_MAX_ATTEMPTS
    entity = row(env, "webhook")
    assert entity["verified"] is False and entity["active"] is False
    assert entity["consecutive_failures"] == 1
    assert "HTTP 500" in entity["last_verification_error"]
    stored_secret = webhook_security.decrypt_webhook(entity["signing_secret"])

    env.http.responses.pop(HOOK_URL)
    ok, secret = run(messaging.setup_webhook_channel(req("webhook", "setup"), OWNER))
    assert ok and secret == stored_secret


def test_webhook_permanent_4xx_is_not_retried(env):
    env.http.responses[HOOK_URL] = [404]
    with pytest.raises(HTTPException):
        run(messaging.setup_webhook_channel(req("webhook", "setup"), OWNER))
    assert len(env.http.posts) == 1


def test_webhook_verify_update_in_place_url_change_and_rotate(env):
    _, secret = run(messaging.setup_webhook_channel(req("webhook", "setup"), OWNER))
    code = code_from_webhook_post(env.http.posts[0])

    with pytest.raises(HTTPException) as exc:
        run(
            messaging.verify_webhook_channel(
                req("webhook", "verify", verify_token="NOPE0000"), OWNER
            )
        )
    assert exc.value.status_code == 403

    assert (
        run(
            messaging.verify_webhook_channel(
                req("webhook", "verify", verify_token=code), OWNER
            )
        )
        is True
    )
    entity = row(env, "webhook")
    assert (
        entity["verified"] and entity["active"] and entity["consecutive_failures"] == 0
    )
    success_ping = env.http.posts[-1]
    assert json.loads(success_ping["content"])["event"] == "verification_success"
    _assert_signed(success_ping, secret, "verification_success")

    posts_before = len(env.http.posts)
    ok, shown = run(
        messaging.setup_webhook_channel(
            req("webhook", "setup", custom_headers={"X-Team": "blue"}), OWNER
        )
    )
    assert (ok, shown) == (True, "")
    assert len(env.http.posts) == posts_before
    entity = row(env, "webhook")
    assert entity["verified"] is True and entity["active"] is True
    assert json.loads(webhook_security.decrypt_webhook(entity["custom_headers"])) == {
        "X-Team": "blue"
    }

    new_url = "https://hooks2.example.org/xon"
    ok, shown = run(
        messaging.setup_webhook_channel(req("webhook", "setup", webhook=new_url), OWNER)
    )
    assert (ok, shown) == (True, "")
    entity = row(env, "webhook")
    assert entity["verified"] is False and entity["active"] is False
    assert webhook_security.decrypt_webhook(entity["signing_secret"]) == secret
    assert webhook_security.decrypt_webhook(entity["webhook"]) == new_url
    assert env.http.posts[-1]["url"] == new_url
    assert json.loads(webhook_security.decrypt_webhook(entity["custom_headers"])) == {
        "X-Team": "blue"
    }

    code2 = code_from_webhook_post(env.http.posts[-1])
    run(
        messaging.verify_webhook_channel(
            req("webhook", "verify", verify_token=code2), OWNER
        )
    )

    new_secret = run(
        messaging.rotate_webhook_secret(req("webhook", "rotate_secret"), OWNER)
    )
    assert new_secret != secret and len(new_secret) == 64
    entity = row(env, "webhook")
    assert webhook_security.decrypt_webhook(entity["signing_secret"]) == new_secret
    assert webhook_security.decrypt_webhook(entity["previous_signing_secret"]) == secret
    assert isinstance(entity["secret_rotated_at"], datetime)
    assert entity["active"] is True

    with pytest.raises(HTTPException) as exc:
        run(messaging.rotate_webhook_secret(req("webhook", "rotate_secret"), OTHER))
    assert exc.value.status_code == 404

    config = run(messaging.get_webhook_channel_config(DOMAIN, OWNER))
    assert config["email"] == OWNER and config["scope"] == "domain"
    assert config["signing_secret_set"] is True
    assert config["custom_header_keys"] == ["X-Team"]
    assert "signing_secret" not in config and "blue" not in json.dumps(config)
    assert config["webhook"] == new_url
    assert config["secret_rotated_at"] is not None


def test_webhook_rotate_and_config_missing_channel(env):
    with pytest.raises(HTTPException) as exc:
        run(messaging.rotate_webhook_secret(req("webhook", "rotate_secret"), OWNER))
    assert exc.value.status_code == 404
    assert run(messaging.get_webhook_channel_config(DOMAIN, OWNER)) is None


def _verified_webhook(env):
    _, secret = run(messaging.setup_webhook_channel(req("webhook", "setup"), OWNER))
    code = code_from_webhook_post(env.http.posts[0])
    run(
        messaging.verify_webhook_channel(
            req("webhook", "verify", verify_token=code), OWNER
        )
    )
    env.http.posts.clear()
    return secret


def test_send_webhook_alert_success_failure_and_autodisable(env):
    payload = {
        "event": "breach_alert",
        "service": "XposedOrNot",
        "domain": DOMAIN,
        "breach": {"id": "b1", "name": "ExampleBreach"},
    }
    assert run(webhook.send_webhook_alert(DOMAIN, OWNER, payload)) is False
    secret = _verified_webhook(env)

    assert run(webhook.send_webhook_alert(DOMAIN, OWNER, payload)) is True
    post = env.http.posts[0]
    assert json.loads(post["content"]) == payload
    assert json.loads(post["content"])["event"] == "breach_alert"
    _assert_signed(post, secret, "breach_alert")
    entity = row(env, "webhook")
    assert entity["consecutive_failures"] == 0 and isinstance(
        entity["last_delivered_at"], datetime
    )

    env.http.responses[HOOK_URL] = [404]
    for i in range(1, webhook.MAX_CONSECUTIVE_FAILURES):
        assert run(webhook.send_webhook_alert(DOMAIN, OWNER, payload)) is False
        entity = row(env, "webhook")
        assert entity["consecutive_failures"] == i and entity["active"] is True
        assert "HTTP 404" in entity["last_delivery_error"]
    assert run(webhook.send_webhook_alert(DOMAIN, OWNER, payload)) is False
    entity = row(env, "webhook")
    assert entity["active"] is False and isinstance(entity["disabled_at"], datetime)
    assert entity["verified"] is True

    posts = len(env.http.posts)
    assert run(webhook.send_webhook_alert(DOMAIN, OWNER, payload)) is False
    assert len(env.http.posts) == posts

    env.ds.get(FakeKey("xon_webhook_channel", f"{OWNER}_{DOMAIN}")).update(
        {"active": True, "consecutive_failures": 3}
    )
    env.http.responses.pop(HOOK_URL)
    assert run(webhook.send_webhook_alert(DOMAIN, OWNER, payload)) is True
    assert row(env, "webhook")["consecutive_failures"] == 0


def test_webhook_alert_rechecks_ssrf_at_send_time(env, monkeypatch):
    _verified_webhook(env)

    def rebinding(host, port, proto=None):  # noqa: ARG001
        return [(2, 1, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(webhook_security.socket, "getaddrinfo", rebinding)
    payload = {"event": "breach_alert"}
    assert run(webhook.send_webhook_alert(DOMAIN, OWNER, payload)) is False
    assert env.http.posts == []
    assert "disallowed" in row(env, "webhook")["last_delivery_error"]


def test_resolve_owner_api_key_and_session(env):
    assert (
        run(
            channel_auth.resolve_domain_owner(
                make_request({"x-api-key": API_KEY}), None, None
            )
        )
        == OWNER
    )
    assert (
        run(
            channel_auth.resolve_domain_owner(
                make_request({"x-api-key": API_KEY}), OTHER, "x"
            )
        )
        == OWNER
    )
    assert (
        run(channel_auth.resolve_domain_owner(make_request(), OWNER.upper(), SESSION))
        == OWNER
    )

    for headers, email, token in [
        ({"x-api-key": "nope"}, None, None),
        ({"x-api-key": "bad key!"}, None, None),
        ({"x-api-key": "  "}, None, None),
        ({}, OWNER, "wrong"),
        ({}, OTHER, SESSION),
        ({}, "not-an-email", SESSION),
        ({}, OWNER, None),
        ({}, None, None),
    ]:
        with pytest.raises(HTTPException) as exc:
            run(channel_auth.resolve_domain_owner(make_request(headers), email, token))
        assert exc.value.status_code == 401, (headers, email, token)


def test_resolve_owner_expired_session(env):
    env.ds.get(FakeKey("xon_domains_session", OWNER))["magic_timestamp"] = datetime.now(
        timezone.utc
    ) - timedelta(hours=13)
    with pytest.raises(HTTPException) as exc:
        run(channel_auth.resolve_domain_owner(make_request(), OWNER, SESSION))
    assert exc.value.status_code == 401


def test_verify_domain_ownership_paths(env):
    assert run(channel_auth.verify_domain_ownership(OWNER, DOMAIN)) is True
    assert run(channel_auth.verify_domain_ownership(OWNER, "EXAMPLE.com")) is True
    assert run(channel_auth.verify_domain_ownership(OTHER, DOMAIN)) is False
    assert run(channel_auth.verify_domain_ownership(OWNER, "rival.com")) is False
    assert run(channel_auth.verify_domain_ownership("", DOMAIN)) is False
    assert run(channel_auth.verify_domain_ownership(OWNER, "")) is False
    env.ds.put(
        FakeEntity(
            FakeKey("xon_domains", f"pending.com_{OWNER}"),
            email=OWNER,
            domain="pending.com",
            verified=False,
        )
    )
    assert run(channel_auth.verify_domain_ownership(OWNER, "pending.com")) is False
    env.ds.put(
        FakeEntity(
            FakeKey("xon_domains", "legacy-id"),
            email=OWNER,
            domain="legacy.com",
            verified=True,
        )
    )
    assert run(channel_auth.verify_domain_ownership(OWNER, "legacy.com")) is True


def cfg_req(domain=DOMAIN, **kw):
    return ChannelConfigRequest(domain=domain, **kw)


def test_webhook_route_lifecycle_and_masked_config(env):
    request = make_request({"x-api-key": API_KEY})
    resp = run(
        webhook_routes.setup_webhook_channel_endpoint(
            request, req("webhook", "setup", custom_headers={"X-Team": "a"})
        )
    )
    assert resp.signing_secret and len(resp.signing_secret) == 64
    code = code_from_webhook_post(env.http.posts[0])

    resp = run(
        webhook_routes.setup_webhook_channel_endpoint(
            request, req("webhook", "verify", verify_token=code)
        )
    )
    assert resp.signing_secret is None and "verified" in resp.message

    resp = run(
        webhook_routes.setup_webhook_channel_endpoint(
            request, req("webhook", "rotate_secret")
        )
    )
    assert resp.signing_secret and len(resp.signing_secret) == 64

    cfg = run(
        webhook_routes.get_webhook_channel_config_endpoint(
            make_request({"x-api-key": API_KEY}, path="/v1/webhook/config"), cfg_req()
        )
    )
    assert cfg.signing_secret_set is True and cfg.custom_header_keys == ["X-Team"]
    assert not hasattr(cfg, "signing_secret")
    assert cfg.email == OWNER and cfg.active is True

    resp = run(
        webhook_routes.setup_webhook_channel_endpoint(request, req("webhook", "delete"))
    )
    assert "deleted" in resp.message and row(env, "webhook") is None
    with pytest.raises(HTTPException) as exc:
        run(
            webhook_routes.get_webhook_channel_config_endpoint(
                make_request({"x-api-key": API_KEY}), cfg_req()
            )
        )
    assert exc.value.status_code == 404


def test_webhook_route_with_session_auth(env):
    request = make_request()
    resp = run(
        webhook_routes.setup_webhook_channel_endpoint(
            request,
            req("webhook", "setup", domain="Example.COM", email=OWNER, token=SESSION),
        )
    )
    assert resp.status == "success"
    assert row(env, "webhook") is not None
    cfg = run(
        webhook_routes.get_webhook_channel_config_endpoint(
            request, cfg_req(email=OWNER, token=SESSION)
        )
    )
    assert cfg.verified is False and cfg.webhook == HOOK_URL


def test_route_auth_and_input_failures(env):
    with pytest.raises(HTTPException) as exc:
        run(
            webhook_routes.setup_webhook_channel_endpoint(
                make_request(), req("webhook", "setup")
            )
        )
    assert exc.value.status_code == 401
    with pytest.raises(HTTPException) as exc:
        run(
            webhook_routes.setup_webhook_channel_endpoint(
                make_request({"x-api-key": "key-other"}), req("webhook", "setup")
            )
        )
    assert exc.value.status_code == 403
    assert row(env, "webhook") is None and env.http.posts == []
    for body in [
        req("webhook", "setup", domain="not a domain"),
        req("webhook", "frobnicate"),
        ChannelSetupRequest(domain=DOMAIN, action="setup"),
        req("webhook", "verify"),
    ]:
        with pytest.raises(HTTPException) as exc:
            run(
                webhook_routes.setup_webhook_channel_endpoint(
                    make_request({"x-api-key": API_KEY}), body
                )
            )
        assert exc.value.status_code == 400, body
    with pytest.raises(HTTPException) as exc:
        run(
            webhook_routes.get_webhook_channel_config_endpoint(
                make_request({"x-api-key": "key-other"}), cfg_req()
            )
        )
    assert exc.value.status_code == 403


def test_route_unexpected_error_is_masked_and_reported(env, monkeypatch):
    async def explode(*_a, **_k):
        raise RuntimeError("datastore down: secret detail")

    monkeypatch.setattr(webhook_routes, "setup_webhook_channel", explode)
    with pytest.raises(HTTPException) as exc:
        run(
            webhook_routes.setup_webhook_channel_endpoint(
                make_request({"x-api-key": API_KEY}), req("webhook", "setup")
            )
        )
    assert exc.value.status_code == 500 and exc.value.detail == "Internal server error"
    assert len(EXCEPTION_EMAILS) == 1
    assert EXCEPTION_EMAILS[0]["api_route"] == "POST /v1/webhook/setup"
    assert "secret detail" in EXCEPTION_EMAILS[0]["error_message"]


def test_service_error_propagates_to_route_handler(env, monkeypatch):
    monkeypatch.setattr(messaging, "datastore_client", None)
    with pytest.raises(HTTPException) as exc:
        run(
            webhook_routes.setup_webhook_channel_endpoint(
                make_request({"x-api-key": API_KEY}), req("webhook", "setup")
            )
        )
    assert exc.value.status_code == 500 and exc.value.detail == "Internal server error"
    assert len(EXCEPTION_EMAILS) == 1


def test_webhook_route_rejects_private_url_without_touching_store(env):
    with pytest.raises(HTTPException) as exc:
        run(
            webhook_routes.setup_webhook_channel_endpoint(
                make_request({"x-api-key": API_KEY}),
                req("webhook", "setup", webhook="https://internal.corp/hook"),
            )
        )
    assert exc.value.status_code == 400 and "internal" in exc.value.detail
    assert row(env, "webhook") is None and env.http.posts == []


def _verified_chat(env, platform):
    run(messaging.setup_messaging_channel(req(platform, "setup"), platform, OWNER))
    code = row(env, platform)["verify_token"]
    run(
        messaging.verify_messaging_channel(
            req(platform, "verify", verify_token=code), platform, OWNER
        )
    )
    env.http.posts.clear()


def test_send_slack_alert_paths(env):
    msg = slack.build_slack_breach_message(
        DOMAIN,
        "ExampleBreach",
        "2026-08-01",
        1200000,
        ["Emails", "Passwords"],
        42,
        "https://xposedornot.com/d",
    )
    assert run(slack.send_slack_alert(DOMAIN, OWNER, msg)) is False
    run(messaging.setup_messaging_channel(req("slack", "setup"), "slack", OWNER))
    env.http.posts.clear()
    assert run(slack.send_slack_alert(DOMAIN, OWNER, msg)) is False
    assert env.http.posts == []
    _verified_chat(env, "slack")
    assert run(slack.send_slack_alert(DOMAIN, OWNER, msg)) is True
    assert env.http.posts[0]["url"] == SLACK_URL and env.http.posts[0]["json"] is msg
    assert "1,200,000" in json.dumps(msg) and "example.com" in json.dumps(msg)
    env.http.responses[SLACK_URL] = [500]
    assert run(slack.send_slack_alert(DOMAIN, OWNER, msg)) is False
    assert run(slack.send_slack_alert(DOMAIN, OTHER, msg)) is False


def test_slack_route_full_lifecycle_with_api_key(env):
    request = make_request({"x-api-key": API_KEY}, path="/v1/slack/setup")
    resp = run(
        slack_routes.setup_slack_channel_endpoint(
            request, req("slack", "setup", domain="Example.COM")
        )
    )
    assert resp.status == "success" and "Verification code sent" in resp.message
    code = row(env, "slack")["verify_token"]

    resp = run(
        slack_routes.setup_slack_channel_endpoint(
            request, req("slack", "verify", verify_token=code)
        )
    )
    assert resp.message == "Slack channel verified successfully"

    cfg = run(
        slack_routes.get_slack_channel_config_endpoint(
            make_request({"x-api-key": API_KEY}, path="/v1/slack/config"), cfg_req()
        )
    )
    assert cfg.email == OWNER and cfg.webhook == SLACK_URL and cfg.verified is True

    resp = run(
        slack_routes.setup_slack_channel_endpoint(request, req("slack", "delete"))
    )
    assert resp.message == "Slack channel deleted successfully"
    with pytest.raises(HTTPException) as exc:
        run(
            slack_routes.get_slack_channel_config_endpoint(
                make_request({"x-api-key": API_KEY}, path="/v1/slack/config"), cfg_req()
            )
        )
    assert exc.value.status_code == 404


def test_slack_route_with_session_auth(env):
    request = make_request(path="/v1/slack/setup")
    resp = run(
        slack_routes.setup_slack_channel_endpoint(
            request, req("slack", "setup", email=OWNER, token=SESSION)
        )
    )
    assert resp.status == "success"
    cfg = run(
        slack_routes.get_slack_channel_config_endpoint(
            make_request(path="/v1/slack/config"), cfg_req(email=OWNER, token=SESSION)
        )
    )
    assert cfg.verified is False and cfg.webhook == SLACK_URL


def test_slack_route_auth_failures(env):
    with pytest.raises(HTTPException) as exc:
        run(
            slack_routes.setup_slack_channel_endpoint(
                make_request(path="/v1/slack/setup"), req("slack", "setup")
            )
        )
    assert exc.value.status_code == 401
    with pytest.raises(HTTPException) as exc:
        run(
            slack_routes.setup_slack_channel_endpoint(
                make_request({"x-api-key": "key-other"}, path="/v1/slack/setup"),
                req("slack", "setup"),
            )
        )
    assert exc.value.status_code == 403
    assert row(env, "slack") is None and env.http.posts == []
    with pytest.raises(HTTPException) as exc:
        run(
            slack_routes.get_slack_channel_config_endpoint(
                make_request({"x-api-key": "key-other"}, path="/v1/slack/config"),
                cfg_req(),
            )
        )
    assert exc.value.status_code == 403
