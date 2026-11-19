"""Tests for the subject, HTML and text content of the monthly digest."""

# pylint: disable=wrong-import-position,too-few-public-methods

import asyncio
import os
from datetime import datetime, timedelta, timezone

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

from api.v1 import monthly_digest_helpers as module

MONTH_START, MONTH_END = module.digest_target_month()
MONTH_NAME = MONTH_START.strftime("%B")
IN_MONTH = MONTH_START + timedelta(days=3)
EARLIER = MONTH_START - timedelta(days=40)


class FakeQuery:
    """Query stub that returns the summary rows of the requested domains."""

    def __init__(self, rows):
        self.rows = rows
        self.domains = []

    def add_filter(self, _field, _operator, value):
        """Record the domains the caller filters on."""
        self.domains = value

    def fetch(self):
        """Return the rows that belong to the filtered domains."""
        return [row for row in self.rows if row["domain"] in self.domains]


class FakeClient:
    """Datastore stub that serves xon_domains_summary rows."""

    def __init__(self, rows):
        self.rows = rows

    def query(self, kind):
        """Return a query over the stored summary rows."""
        assert kind == "xon_domains_summary"
        return FakeQuery(self.rows)


def breach(timestamp, data="Email addresses;Passwords;", records=1000):
    """Build a breach record like the prefetch step stores."""
    return {
        "timestamp": timestamp,
        "breached_date": timestamp - timedelta(days=30),
        "xposed_data": data,
        "xposed_records": records,
    }


def breach_data(details, new_breaches=None):
    """Build the prefetched data passed to the content builder."""
    return {
        "new_breaches": new_breaches or [],
        "breach_details": details,
        "target_month_start": MONTH_START,
        "target_month_end": MONTH_END,
    }


def build(rows, details, domains, new_breaches=None):
    """Run the real content builder against the stub client."""
    return asyncio.run(
        module.build_monthly_digest_content(
            "admin@acme.com",
            "tok&en",
            domains,
            breach_data(details, new_breaches),
            FakeClient(rows),
        )
    )


def test_target_month_is_previous_calendar_month_in_early_march():
    """The first days of March report on February, not January."""
    start, end = module.digest_target_month(
        datetime(2027, 3, 2, 9, 0, tzinfo=timezone.utc)
    )
    assert (start.year, start.month, start.day) == (2027, 2, 1)
    assert (end.year, end.month, end.day) == (2027, 3, 1)


def test_new_exposure_shows_email_count_domain_and_subject():
    """A breach added in the target month is reported as new with its numbers."""
    rows = [{"domain": "acme.com", "breach": "BigLeak", "email_count": 42}]
    content = build(rows, {"BigLeak": breach(IN_MONTH)}, ["acme.com"])

    assert content["subject"] == (
        f"acme.com: 42 email exposures in 1 new breach ({MONTH_NAME})"
    )
    assert "42 emails from your domain (acme.com)" in content["html"]
    assert "Data exposed: Email addresses, Passwords" in content["html"]
    assert "See affected emails in your dashboard" in content["html"]
    assert "What to do now" in content["html"]
    assert "token=tok%26en" in content["html"]
    assert "email=admin%40acme.com&amp;token=" in content["html"]
    assert "42 emails from your domain (acme.com)" in content["text"]
    assert "email=admin%40acme.com&token=" in content["text"]


def test_clean_month_has_calm_subject_and_no_alarm_button():
    """A user with no new exposure gets the calm subject and no alert button."""
    content = build([], {}, ["acme.com"])

    assert content["subject"] == f"acme.com: no new exposure in {MONTH_NAME}"
    assert "No new exposure." in content["html"]
    assert "See affected emails in your dashboard" not in content["html"]
    assert "Good habits to keep" in content["html"]
    assert f"No new breaches were added in {MONTH_NAME}." in content["html"]
    assert "🚨" not in content["subject"] + content["html"] + content["text"]


def test_earlier_exposure_is_listed_separately_from_new():
    """An older exposure does not count as new and lands in the earlier section."""
    rows = [
        {"domain": "acme.com", "breach": "OldLeak", "email_count": 7},
        {"domain": "acme.io", "breach": "BigLeak", "email_count": 1},
        {"domain": "acme.io", "breach": "No_Breaches", "email_count": 0},
    ]
    details = {"OldLeak": breach(EARLIER), "BigLeak": breach(IN_MONTH)}
    content = build(rows, details, ["acme.com", "acme.io"])

    assert content["subject"] == (
        f"Your 2 domains: 1 email exposure in 1 new breach ({MONTH_NAME})"
    )
    assert "Earlier exposures (last 6 months)" in content["html"]
    assert "1 breach, 7 email exposures" in content["html"]
    assert "1 email from your domain (acme.io)" in content["html"]
    assert "No_Breaches" not in content["html"]


def test_catalogue_lists_largest_breaches_first_and_counts_the_rest():
    """The catalogue ranks by record count and says how many are not shown."""
    new_breaches = [
        {
            "breach_name": f"Leak{i}",
            "records_count": i * 1_000_000,
            "data_exposed": "Email addresses;",
        }
        for i in range(1, 8)
    ]
    content = build([], {}, ["acme.com"], new_breaches)

    assert "7 breaches, 28M records in total" in content["html"]
    assert content["html"].index("Leak7") < content["html"].index("Leak3")
    assert "Leak2" not in content["html"]
    assert "and 2 more" in content["html"]


def test_breach_and_domain_names_are_html_escaped():
    """Names from the datastore cannot inject markup into the email."""
    rows = [{"domain": "acme.com", "breach": "<b>X</b>", "email_count": 2}]
    content = build(rows, {"<b>X</b>": breach(IN_MONTH)}, ["acme.com"])

    assert "<b>X</b>" not in content["html"]
    assert "&lt;b&gt;X&lt;/b&gt;" in content["html"]
