"""Tests for the monthly digest unsubscribe link, routes and send filter."""

# pylint: disable=wrong-import-position,redefined-outer-name,protected-access

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

from api.v1 import monthly_digest as module
from api.v1 import monthly_digest_helpers as helpers
from utils import token as token_module

EMAIL = "admin@acme.com"


class FakeKey:
    """Datastore key stub exposing the kind and name."""

    def __init__(self, kind, name):
        self.kind = kind
        self.name = name

    def __hash__(self):
        return hash((self.kind, self.name))

    def __eq__(self, other):
        return (self.kind, self.name) == (other.kind, other.name)


class FakeEntity(dict):
    """Minimal datastore entity that remembers its key."""

    def __init__(self, key):
        super().__init__()
        self.key = key


class FakeDatastoreClient:
    """In-memory datastore client for the opt-out records."""

    def __init__(self):
        self.entities = {}

    def key(self, kind, name):
        """Return an in-memory key."""
        return FakeKey(kind, name)

    def get(self, key):
        """Return an entity by key."""
        return self.entities.get(key)

    def get_multi(self, keys):
        """Return the entities that exist for the given keys."""
        return [self.entities[key] for key in keys if key in self.entities]

    def put(self, entity):
        """Store an entity by key."""
        self.entities[entity.key] = entity


def make_request(method="GET", body=b""):
    """Create a minimal request that can serve a body."""

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": method,
            "path": "/v1/digest-unsubscribe/x",
            "headers": [],
            "client": ("203.0.113.10", 12345),
            "query_string": b"",
            "server": ("api.xposedornot.com", 443),
            "scheme": "https",
        },
        receive,
    )


class FakeRedis:
    """Redis stub with the claim, release and last-run operations."""

    def __init__(self):
        self.claims = {}
        self.written = {}

    def set(self, key, value, nx=False, ex=None):
        """Store a key, honouring set-if-absent."""
        assert nx and ex
        if key in self.claims:
            return None
        self.claims[key] = value
        return True

    def delete(self, key):
        """Remove a claimed key."""
        self.claims.pop(key, None)

    def setex(self, key, _ttl, value):
        """Record a key written with an expiry."""
        self.written[key] = value


@pytest.fixture(autouse=True)
def redis(monkeypatch):
    """Install an in-memory Redis for the send guard."""
    fake = FakeRedis()
    monkeypatch.setattr(module, "redis_client", fake)
    return fake


@pytest.fixture
def client(monkeypatch):
    """Install an in-memory datastore for the routes and helpers."""
    fake = FakeDatastoreClient()
    monkeypatch.setattr(module, "ds_client", fake)
    monkeypatch.setattr(helpers.datastore, "Entity", FakeEntity)
    return fake


def open_link(unsub_token):
    """Invoke the real GET confirmation handler."""
    return asyncio.run(
        module.digest_unsubscribe_confirm.__wrapped__(make_request(), unsub_token)
    )


def submit(unsub_token, body=b""):
    """Invoke the real POST recording handler."""
    return asyncio.run(
        module.digest_unsubscribe_record.__wrapped__(
            make_request("POST", body), unsub_token
        )
    )


def optout(client, email=EMAIL):
    """Return the stored opt-out record for an email."""
    return client.get(client.key(helpers.DIGEST_OPTOUT_KIND, email))


def test_token_round_trips_and_rejects_tampering():
    """A token resolves to its email and any change to it is rejected."""
    unsub_token = token_module.generate_digest_unsub_token(EMAIL)
    assert token_module.confirm_digest_unsub_token(unsub_token) == EMAIL
    assert token_module.confirm_digest_unsub_token(unsub_token[:-2] + "xx") is None
    assert token_module.confirm_digest_unsub_token("") is None


def test_tokens_from_other_flows_are_rejected():
    """A dashboard confirmation token cannot be used to unsubscribe."""
    other = asyncio.run(token_module.generate_confirmation_token(EMAIL))
    assert token_module.confirm_digest_unsub_token(other) is None
    unsub_token = token_module.generate_digest_unsub_token(EMAIL)
    assert asyncio.run(token_module.confirm_token(unsub_token)) is None


def test_opening_the_link_shows_confirm_page_and_records_nothing(client):
    """The GET only renders the confirmation page with the POST target."""
    unsub_token = token_module.generate_digest_unsub_token(EMAIL)
    response = open_link(unsub_token)

    assert response.status_code == 200
    page = response.body.decode()
    assert EMAIL in page
    assert f'action="{module.BASE_URL}/v1/digest-unsubscribe/{unsub_token}"' in page
    assert not client.entities


def test_confirming_records_the_optout_once(client):
    """The POST records the opt-out and a repeat keeps the first record."""
    unsub_token = token_module.generate_digest_unsub_token(EMAIL)
    response = submit(unsub_token)

    assert response.status_code == 200
    assert "You've Been Unsubscribed" in response.body.decode()
    record = optout(client)
    assert record["unsubscribed"] is True
    assert record["source"] == "email_link"
    first_time = record["unsubscribed_at"]

    assert submit(unsub_token, b"List-Unsubscribe=One-Click").status_code == 200
    assert optout(client)["unsubscribed_at"] == first_time
    assert optout(client)["source"] == "email_link"


def test_one_click_post_is_recorded_with_its_source(client):
    """The mailbox provider one-click POST records the opt-out."""
    unsub_token = token_module.generate_digest_unsub_token(EMAIL)
    response = submit(unsub_token, b"List-Unsubscribe=One-Click")

    assert response.status_code == 200
    assert optout(client)["source"] == "one_click"


@pytest.mark.parametrize("bad_token", ["not-a-token", "a b", "<script>", "x" * 400])
def test_invalid_tokens_get_the_error_page_and_record_nothing(client, bad_token):
    """Forged or malformed tokens never render an email or record anything."""
    assert open_link(bad_token).status_code == 404
    assert submit(bad_token).status_code == 404
    assert not client.entities


def test_datastore_failure_returns_an_error_and_not_success(client, monkeypatch):
    """A failed write is reported as a failure so it can be retried."""

    def failing_put(_entity):
        raise module.google_exceptions.ServiceUnavailable("down")

    monkeypatch.setattr(client, "put", failing_put)
    response = submit(token_module.generate_digest_unsub_token(EMAIL))

    assert response.status_code == 500
    assert "You've Been Unsubscribed" not in response.body.decode()


def test_send_filter_returns_only_opted_out_emails(client):
    """The send loop lookup finds exactly the recipients who opted out."""
    helpers.record_digest_optout(client, "gone@acme.com", "email_link")

    assert helpers.fetch_digest_optouts(
        client, ["gone@acme.com", "stays@acme.com"]
    ) == {"gone@acme.com"}
    assert helpers.fetch_digest_optouts(client, []) == set()


def test_unsubscribe_link_is_in_html_and_text_only_when_given():
    """The digest carries the unsubscribe link in both bodies."""
    url = helpers.build_digest_unsubscribe_url(EMAIL)
    context = {
        "email": EMAIL,
        "user_domains": ["acme.com"],
        "month_name": "October",
        "year": 2026,
        "new_exposures": [],
        "earlier_exposures": [],
        "new_breaches": [],
        "dashboard_url": "https://xposedornot.com/breach-dashboard",
        "dashboard_url_text": "https://xposedornot.com/breach-dashboard",
        "unsubscribe_url": url,
    }

    assert url.startswith(f"{module.BASE_URL}/v1/digest-unsubscribe/")
    assert f'href="{url}"' in helpers.render_digest_html(context)
    assert f"Unsubscribe from the monthly digest: {url}" in (
        helpers.render_digest_text(context)
    )

    context["unsubscribe_url"] = ""
    assert "Unsubscribe" not in helpers.render_digest_html(context)
    assert "Unsubscribe" not in helpers.render_digest_text(context)


class RunQuery:
    """Query stub for the kinds a full digest run reads."""

    def __init__(self, rows):
        self.rows = rows
        self.order = []

    def add_filter(self, *_args):
        """Accept any filter; the stored rows are already the wanted ones."""

    def fetch(self, limit=None):
        """Return the stored rows."""
        return self.rows[:limit] if limit else list(self.rows)


class RunDatastoreClient(FakeDatastoreClient):
    """In-memory datastore that can serve a whole digest run."""

    def __init__(self, domain_rows):
        super().__init__()
        self.domain_rows = domain_rows

    def query(self, kind):
        """Return verified domains for xon_domains and nothing elsewhere."""
        return RunQuery(self.domain_rows if kind == "xon_domains" else [])

    def put_multi(self, entities):
        """Store several entities."""
        for entity in entities:
            self.put(entity)


class FakeMailResponse:
    """Mail API response stub reporting success."""

    status_code = 200


class FakeMailClient:
    """HTTP client stub that captures every outbound digest message."""

    sent = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def post(self, _url, json=None, **_kwargs):
        """Capture the message instead of calling the mail provider."""
        FakeMailClient.sent.append(json["Messages"][0])
        return FakeMailResponse()


def test_full_run_sends_only_to_recipients_who_did_not_unsubscribe(monkeypatch):
    """A real digest run skips the opted-out recipient and mails the rest."""
    fake = RunDatastoreClient(
        [
            {"domain": "acme.com", "email": "Stays@acme.com", "verified": True},
            {"domain": "gone.com", "email": "gone@gone.com", "verified": True},
            {"domain": "gone.org", "email": " GONE@gone.com", "verified": True},
        ]
    )
    FakeMailClient.sent = []
    monkeypatch.setattr(module, "ds_client", fake)
    monkeypatch.setattr(module, "ENVIRONMENT", "production")
    monkeypatch.setattr(module.httpx, "AsyncClient", FakeMailClient)
    monkeypatch.setattr(helpers.datastore, "Entity", FakeEntity)

    unsub_token = token_module.generate_digest_unsub_token("gone@gone.com")
    assert submit(unsub_token).status_code == 200

    result = asyncio.run(module.process_monthly_digest_for_all_users())

    recipients = [message["To"][0]["Email"] for message in FakeMailClient.sent]
    assert recipients == ["stays@acme.com"]
    assert result["emails_sent"] == 1
    assert result["skipped_unsubscribed"] == 1
    assert result["total_unique_emails"] == 1
    assert not [key for key in fake.entities if key.kind == "xon_domains_session"]

    message = FakeMailClient.sent[0]
    stays_url = helpers.build_digest_unsubscribe_url("stays@acme.com")
    assert message["Headers"]["List-Unsubscribe"] == f"<{stays_url}>"
    assert message["Headers"]["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
    assert stays_url in message["HTMLPart"]
    assert stays_url in message["TextPart"]


def test_full_run_sends_nothing_when_optout_lookup_fails(monkeypatch):
    """If opt-outs cannot be read the run stops instead of mailing everyone."""
    fake = RunDatastoreClient(
        [{"domain": "acme.com", "email": "stays@acme.com", "verified": True}]
    )

    def failing_get_multi(_keys):
        raise module.google_exceptions.ServiceUnavailable("down")

    FakeMailClient.sent = []
    monkeypatch.setattr(fake, "get_multi", failing_get_multi)
    monkeypatch.setattr(module, "ds_client", fake)
    monkeypatch.setattr(module, "ENVIRONMENT", "production")
    monkeypatch.setattr(module.httpx, "AsyncClient", FakeMailClient)

    with pytest.raises(Exception):
        asyncio.run(module.process_monthly_digest_for_all_users())
    assert not FakeMailClient.sent


TWO_OWNERS = [
    {"domain": "acme.com", "email": "me@acme.com", "verified": True},
    {"domain": "other.com", "email": "someone@other.com", "verified": True},
]


def run_with_target(monkeypatch, target_email):
    """Run the real digest for a target and return the result and recipients."""
    fake = RunDatastoreClient(TWO_OWNERS)
    FakeMailClient.sent = []
    monkeypatch.setattr(module, "ds_client", fake)
    monkeypatch.setattr(module, "ENVIRONMENT", "production")
    monkeypatch.setattr(module.httpx, "AsyncClient", FakeMailClient)
    result = asyncio.run(module.process_monthly_digest_for_all_users(target_email))
    return result, [message["To"][0]["Email"] for message in FakeMailClient.sent]


def test_target_email_restricts_the_run_to_that_recipient(monkeypatch):
    """A targeted run mails only the target, matched case-insensitively."""
    result, recipients = run_with_target(monkeypatch, " Me@Acme.com ")

    assert recipients == ["me@acme.com"]
    assert result["emails_sent"] == 1


@pytest.mark.parametrize("target", ["nobody@nowhere.com", "", "acme.com"])
def test_unknown_or_empty_target_sends_nothing(monkeypatch, target):
    """A target that owns no verified domain never falls back to everyone."""
    result, recipients = run_with_target(monkeypatch, target)

    assert recipients == []
    assert result["emails_sent"] == 0


def test_run_without_target_mails_every_owner(monkeypatch):
    """Without a target the run still reaches all eligible owners."""
    result, recipients = run_with_target(monkeypatch, None)

    assert sorted(recipients) == ["me@acme.com", "someone@other.com"]
    assert result["emails_sent"] == 2


def trigger(monkeypatch, target_email):
    """Call the real manual trigger route and return its response and Redis."""
    fake = RunDatastoreClient(TWO_OWNERS)
    redis = FakeRedis()
    FakeMailClient.sent = []
    monkeypatch.setattr(module, "ds_client", fake)
    monkeypatch.setattr(module, "redis_client", redis)
    monkeypatch.setattr(module, "ENVIRONMENT", "production")
    monkeypatch.setattr(module.httpx, "AsyncClient", FakeMailClient)
    response = asyncio.run(
        module.trigger_manual_monthly_digest.__wrapped__(
            make_request("POST"), module.CF_UNBLOCK_MAGIC, target_email
        )
    )
    return response, redis


def test_targeted_trigger_does_not_mark_the_month_as_sent(monkeypatch):
    """A test send must not block the real monthly run."""
    response, redis = trigger(monkeypatch, "me@acme.com")

    assert len(FakeMailClient.sent) == 1
    assert response.testing_mode is True
    assert response.target_email == "me@acme.com"
    assert not redis.written


def test_full_trigger_marks_the_month_as_sent(monkeypatch):
    """A full manual run records the month and is not reported as a test."""
    response, redis = trigger(monkeypatch, None)

    assert len(FakeMailClient.sent) == 2
    assert response.testing_mode is False
    assert list(redis.written) == [f"{module.ENVIRONMENT}_monthly_digest_last_run"]


def mail_client(sent, reject=(), raises=None):
    """Build a mail client stub that can reject or fail for some recipients."""

    class Response:
        """Mail API response stub with a chosen status."""

        def __init__(self, status_code):
            self.status_code = status_code

    class Client:
        """HTTP client stub capturing accepted messages."""

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def post(self, _url, json=None, **_kwargs):
            """Accept, reject or fail the message by recipient."""
            recipient = json["Messages"][0]["To"][0]["Email"]
            if raises is not None:
                raise raises
            if recipient in reject:
                return Response(500)
            sent.append(recipient)
            return Response(200)

    return Client


def full_run(monkeypatch, sent, target_email=None, **mail_options):
    """Run the real digest for the two owners with a configurable mail stub."""
    monkeypatch.setattr(module, "ds_client", RunDatastoreClient(TWO_OWNERS))
    monkeypatch.setattr(module, "ENVIRONMENT", "production")
    monkeypatch.setattr(module.httpx, "AsyncClient", mail_client(sent, **mail_options))
    return asyncio.run(module.process_monthly_digest_for_all_users(target_email))


def test_second_full_run_in_the_same_period_sends_nothing(monkeypatch):
    """A repeated full run cannot mail a recipient twice."""
    sent = []
    first = full_run(monkeypatch, sent)
    second = full_run(monkeypatch, sent)

    assert sorted(sent) == ["me@acme.com", "someone@other.com"]
    assert first["emails_sent"] == 2
    assert second["emails_sent"] == 0
    assert second["skipped_already_sent"] == 2
    assert second["total_errors"] == 0


def test_rerun_after_a_rejected_send_mails_only_the_missed_recipient(monkeypatch):
    """A recipient the mail API rejected is retried and the rest are not."""
    sent = []
    first = full_run(monkeypatch, sent, reject={"someone@other.com"})
    assert sent == ["me@acme.com"]
    assert first["email_sending_errors"] == 1

    second = full_run(monkeypatch, sent)
    assert sorted(sent) == ["me@acme.com", "someone@other.com"]
    assert second["emails_sent"] == 1
    assert second["skipped_already_sent"] == 1


def test_connection_failure_releases_the_claim_for_retry(monkeypatch, redis):
    """A send that never reached the mail API can be retried."""
    sent = []
    full_run(monkeypatch, sent, raises=module.httpx.ConnectError("refused"))
    assert not sent
    assert not redis.claims

    full_run(monkeypatch, sent)
    assert len(sent) == 2


def test_ambiguous_failure_keeps_the_claim_to_avoid_a_duplicate(monkeypatch, redis):
    """A timeout after the request was sent is not retried automatically."""
    sent = []
    full_run(monkeypatch, sent, raises=module.httpx.ReadTimeout("slow"))
    assert len(redis.claims) == 2

    second = full_run(monkeypatch, sent)
    assert not sent
    assert second["skipped_already_sent"] == 2


def test_no_redis_means_no_unguarded_sends(monkeypatch):
    """Without Redis the full run reports errors and mails nobody."""
    sent = []
    monkeypatch.setattr(module, "redis_client", None)
    result = full_run(monkeypatch, sent)

    assert not sent
    assert result["emails_sent"] == 0
    assert result["email_sending_errors"] == 2


def test_targeted_test_send_ignores_and_does_not_set_the_guard(monkeypatch, redis):
    """Test sends repeat freely and never block the real monthly send."""
    sent = []
    full_run(monkeypatch, sent, target_email="me@acme.com")
    full_run(monkeypatch, sent, target_email="me@acme.com")
    assert sent == ["me@acme.com", "me@acme.com"]
    assert not redis.claims

    full_run(monkeypatch, sent)
    assert sorted(sent[2:]) == ["me@acme.com", "someone@other.com"]


def test_guard_key_is_scoped_to_period_and_hides_the_email():
    """Each reporting month has its own marker and no address is stored."""
    october = module._digest_sent_key("2026-10", "me@acme.com")
    november = module._digest_sent_key("2026-11", "me@acme.com")

    assert october != november
    assert "me@acme.com" not in october
    assert october.endswith(module._digest_sent_key("2026-10", "me@acme.com")[-32:])


def test_owner_beyond_the_old_thousand_domain_cap_is_mailed(monkeypatch):
    """Verified domains past the first thousand rows are still read."""
    rows = [
        {"domain": f"d{i}.com", "email": "big@acme.com", "verified": True}
        for i in range(1100)
    ]
    rows.append({"domain": "late.com", "email": "late@late.com", "verified": True})
    sent = []
    monkeypatch.setattr(module, "ds_client", RunDatastoreClient(rows))
    monkeypatch.setattr(module, "ENVIRONMENT", "production")
    monkeypatch.setattr(module.httpx, "AsyncClient", mail_client(sent))

    result = asyncio.run(module.process_monthly_digest_for_all_users())

    assert module.DIGEST_MAX_VERIFIED_DOMAINS == 10000
    assert sorted(sent) == ["big@acme.com", "late@late.com"]
    assert result["total_verified_domains"] == 1101


def test_clean_run_reports_success(monkeypatch):
    """A run with no failed sends keeps the success status."""
    result = full_run(monkeypatch, [])

    assert result["status"] == "success"
    assert result["message"] == "Monthly digest processing complete"


def test_run_with_some_failed_sends_reports_partial(monkeypatch):
    """A run where some recipients failed is not reported as success."""
    result = full_run(monkeypatch, [], reject={"someone@other.com"})

    assert result["status"] == "partial"
    assert result["emails_sent"] == 1
    assert "1 failed sends" in result["message"]


def test_run_where_every_send_fails_reports_failed(monkeypatch):
    """A run that delivered nothing is reported as failed."""
    result = full_run(monkeypatch, [], reject={"me@acme.com", "someone@other.com"})

    assert result["status"] == "failed"
    assert result["emails_sent"] == 0


def test_rerun_that_only_has_failures_left_is_partial_not_failed(monkeypatch):
    """A retry whose remaining recipient fails again still counts earlier sends."""
    sent = []
    full_run(monkeypatch, sent, reject={"someone@other.com"})
    second = full_run(monkeypatch, sent, reject={"someone@other.com"})

    assert second["status"] == "partial"
    assert second["skipped_already_sent"] == 1


def test_partial_manual_run_does_not_mark_the_month_as_sent(monkeypatch, redis):
    """The trigger reports the partial status and leaves the month open."""
    monkeypatch.setattr(module, "ds_client", RunDatastoreClient(TWO_OWNERS))
    monkeypatch.setattr(module, "ENVIRONMENT", "production")
    monkeypatch.setattr(
        module.httpx, "AsyncClient", mail_client([], reject={"someone@other.com"})
    )

    response = asyncio.run(
        module.trigger_manual_monthly_digest.__wrapped__(
            make_request("POST"), module.CF_UNBLOCK_MAGIC, None
        )
    )

    assert response.status == "partial"
    assert "emails sent: 1, failed: 1" in response.message
    assert not redis.written
