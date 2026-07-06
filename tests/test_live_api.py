"""Live smoke tests against the deployed XposedOrNot API.

Zero-configuration black-box tests: no environment variables, credentials,
mocks, or local services required. Each endpoint is requested exactly once
per run (module-scoped fixtures) and validated for contract shape rather
than exact data, since the live breach directory keeps growing.

Run with: pytest tests/test_live_api.py -m live
"""

# pylint: disable=redefined-outer-name

import os
import time
import xml.etree.ElementTree as ET

import httpx
import pytest

BASE_URL = os.environ.get("XON_API_BASE_URL", "https://api.xposedornot.com")
USER_AGENT = "XON-API-smoke-test/1.0"
TEST_EMAIL = "test@example.com"
KNOWN_BREACH_ID = "Adobe"
KNOWN_BREACH_DOMAIN = "adobe.com"
REQUEST_SPACING_SECONDS = 0.6
REQUEST_TIMEOUT_SECONDS = 30.0

pytestmark = pytest.mark.live


def _live_get(client: httpx.Client, path: str, params: dict = None) -> httpx.Response:
    """GET a live endpoint with request spacing and rate-limit awareness."""
    time.sleep(REQUEST_SPACING_SECONDS)
    response = client.get(path, params=params)
    if response.status_code == 429:
        pytest.skip(f"Rate limited on {path}; re-run after the limit window resets")
    if response.status_code == 403:
        pytest.skip(f"Blocked at the edge (403) on {path}; check WAF rules for CI IPs")
    return response


@pytest.fixture(scope="module")
def client():
    """Shared HTTP client for all live smoke tests."""
    with httpx.Client(
        base_url=BASE_URL,
        headers={"User-Agent": USER_AGENT},
        timeout=REQUEST_TIMEOUT_SECONDS,
        follow_redirects=True,
    ) as http_client:
        yield http_client


@pytest.fixture(scope="module")
def breaches_by_id(client):
    """Response for /v1/breaches filtered by a known breach ID."""
    return _live_get(client, "/v1/breaches", params={"breach_id": KNOWN_BREACH_ID})


@pytest.fixture(scope="module")
def breaches_by_domain(client):
    """Response for /v1/breaches filtered by a known domain."""
    return _live_get(client, "/v1/breaches", params={"domain": KNOWN_BREACH_DOMAIN})


@pytest.fixture(scope="module")
def check_email(client):
    """Response for /v1/check-email with the standard test address."""
    return _live_get(client, f"/v1/check-email/{TEST_EMAIL}")


@pytest.fixture(scope="module")
def breach_analytics(client):
    """Response for /v1/breach-analytics with the standard test address."""
    return _live_get(client, "/v1/breach-analytics", params={"email": TEST_EMAIL})


@pytest.fixture(scope="module")
def rss(client):
    """Response for the /v1/rss feed."""
    return _live_get(client, "/v1/rss")


@pytest.fixture(scope="module")
def xon_pulse(client):
    """Response for the /v1/xon-pulse news feed."""
    return _live_get(client, "/v1/xon-pulse")


class TestBreaches:
    """Contract tests for GET /v1/breaches."""

    def test_breach_id_filter_returns_known_breach(self, breaches_by_id):
        """Filtering by breach_id returns exactly the known breach."""
        assert breaches_by_id.status_code == 200
        body = breaches_by_id.json()
        assert body["status"] == "success"
        breaches = body["exposedBreaches"]
        assert isinstance(breaches, list) and len(breaches) == 1
        assert breaches[0]["breachID"] == KNOWN_BREACH_ID

    def test_breach_record_has_expected_fields(self, breaches_by_id):
        """A breach record exposes the documented field set."""
        record = breaches_by_id.json()["exposedBreaches"][0]
        expected_fields = {
            "breachID",
            "breachedDate",
            "domain",
            "industry",
            "logo",
            "passwordRisk",
            "searchable",
            "sensitive",
            "verified",
            "exposedData",
            "exposedRecords",
            "exposureDescription",
            "referenceURL",
        }
        assert expected_fields <= set(record.keys())
        assert record["domain"] == KNOWN_BREACH_DOMAIN
        assert isinstance(record["exposedData"], list) and record["exposedData"]
        assert isinstance(record["exposedRecords"], int)
        assert record["exposedRecords"] > 0

    def test_domain_filter_returns_only_matching_domain(self, breaches_by_domain):
        """Filtering by domain returns only breaches for that domain."""
        assert breaches_by_domain.status_code == 200
        body = breaches_by_domain.json()
        assert body["status"] == "success"
        breaches = body["exposedBreaches"]
        assert isinstance(breaches, list) and breaches
        assert all(record["domain"] == KNOWN_BREACH_DOMAIN for record in breaches)


class TestCheckEmail:
    """Contract tests for GET /v1/check-email/{email}."""

    def test_breached_email_returns_breach_list(self, check_email):
        """A breached email returns a non-empty breach name list."""
        assert check_email.status_code == 200
        body = check_email.json()
        assert body["email"] == TEST_EMAIL
        assert body.get("status") == "success"
        breaches = body["breaches"]
        assert isinstance(breaches, list) and breaches
        assert isinstance(breaches[0], list) and breaches[0]
        assert all(isinstance(name, str) and name for name in breaches[0])

    def test_known_breach_present_for_test_email(self, check_email):
        """The known anchor breach appears for the test email."""
        breaches = check_email.json()["breaches"][0]
        assert KNOWN_BREACH_ID in breaches

    def test_invalid_email_returns_error(self, client):
        """An invalid email returns the documented error body."""
        response = _live_get(client, "/v1/check-email/not-an-email")
        assert response.status_code == 200
        assert response.json().get("Error") == "Not found"


class TestBreachAnalytics:
    """Contract tests for GET /v1/breach-analytics."""

    def test_analytics_returns_expected_sections(self, breach_analytics):
        """Analytics responses carry all documented top-level sections."""
        assert breach_analytics.status_code == 200
        body = breach_analytics.json()
        expected_sections = {
            "ExposedBreaches",
            "BreachesSummary",
            "BreachMetrics",
            "PastesSummary",
        }
        assert expected_sections <= set(body.keys())

    def test_analytics_summary_and_metrics_have_content(self, breach_analytics):
        """Summary and metrics sections are populated for a breached email."""
        body = breach_analytics.json()
        summary = body["BreachesSummary"]
        assert isinstance(summary.get("site"), str) and summary["site"]
        metrics = body["BreachMetrics"]
        assert "industry" in metrics
        assert "risk" in metrics

    def test_missing_email_returns_not_found(self, client):
        """Omitting the email parameter returns 404."""
        response = _live_get(client, "/v1/breach-analytics")
        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}


class TestFeeds:
    """Contract tests for GET /v1/rss and GET /v1/xon-pulse."""

    def test_rss_returns_valid_feed(self, rss):
        """The RSS feed is well-formed XML with the expected channel title."""
        assert rss.status_code == 200
        assert rss.headers["content-type"].startswith("application/rss+xml")
        root = ET.fromstring(rss.content)
        assert root.tag == "rss"
        title = root.findtext("./channel/title")
        assert title == "XposedOrNot Data Breaches"

    def test_rss_has_breach_items(self, rss):
        """The RSS feed contains at least one breach item with title and link."""
        root = ET.fromstring(rss.content)
        items = root.findall("./channel/item")
        assert items
        first_item = items[0]
        assert first_item.findtext("title")
        assert first_item.findtext("link")

    def test_xon_pulse_returns_news_items(self, xon_pulse):
        """The pulse feed returns news items with the documented fields."""
        assert xon_pulse.status_code == 200
        body = xon_pulse.json()
        assert body["status"] == "success"
        news_items = body["data"]
        assert isinstance(news_items, list) and news_items
        expected_fields = {"title", "date", "summary", "url"}
        assert expected_fields <= set(news_items[0].keys())
