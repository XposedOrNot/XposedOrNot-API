"""Tests for the X-Robots-Tag header set by the security-headers middleware.

Runs the real ``add_security_headers`` middleware on a minimal app so the
check does not depend on the Datastore and Redis bootstrap of ``main``.
"""

# pylint: disable=redefined-outer-name

import os
import sys

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.middleware import (  # noqa: E402  pylint: disable=wrong-import-position
    ROBOTS_EXEMPT_PATHS,
    setup_security_headers,
)


@pytest.fixture
def client():
    """Minimal app with one route per path class the middleware distinguishes."""
    app = FastAPI()
    setup_security_headers(app)

    @app.get("/")
    @app.get("/docs")
    @app.get("/v1/help/")
    async def html_page():
        return HTMLResponse("<html></html>")

    @app.get("/v1/breaches")
    @app.get("/openapi.json")
    @app.get("/robots.txt")
    @app.get("/v1/check-email/{email}")
    async def api_route():
        return {"ok": True}

    @app.get("/v1/boom")
    async def failing_route():
        raise HTTPException(status_code=429, detail="slow down")

    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("path", sorted(ROBOTS_EXEMPT_PATHS))
def test_html_pages_are_indexable(client, path):
    """The landing page, Swagger UI and help page carry no robots header."""
    response = client.get(path)
    assert response.status_code == 200
    assert "x-robots-tag" not in response.headers


@pytest.mark.parametrize(
    "path",
    ["/v1/breaches", "/openapi.json", "/robots.txt", "/v1/check-email/a@b.com"],
)
def test_api_responses_are_noindex(client, path):
    """Every non-exempt 200 response is marked noindex, nofollow."""
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["x-robots-tag"] == "noindex, nofollow"


def test_error_responses_are_noindex(client):
    """Handled errors and unknown paths are marked noindex, nofollow too."""
    assert client.get("/v1/boom").headers["x-robots-tag"] == "noindex, nofollow"
    assert client.get("/nope").headers["x-robots-tag"] == "noindex, nofollow"


def test_cached_304_keeps_noindex(client):
    """The ETag short-circuit for public cacheable paths preserves the header."""
    first = client.get("/v1/breaches")
    etag = first.headers["etag"]
    second = client.get("/v1/breaches", headers={"If-None-Match": etag})
    assert second.status_code == 304
    assert second.headers["x-robots-tag"] == "noindex, nofollow"
