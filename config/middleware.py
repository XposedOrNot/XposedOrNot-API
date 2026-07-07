"""Middleware configurations for the application."""

# Standard library imports
import asyncio
import hashlib
from typing import Optional

# Third-party imports
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

# Local imports
from services.globe import process_request_for_globe
from utils.request import get_client_ip

PUBLIC_CACHEABLE_PATHS = frozenset(
    {
        "/v1/breaches",
        "/v1/metrics",
        "/v1/metrics/detailed",
        "/v1/analytics/metrics",
        "/v1/xon-pulse",
        "/v1/analytics/pulse",
        "/v1/rss",
    }
)
PUBLIC_CACHE_CONTROL = "public, max-age=3600"


def setup_middleware(app: FastAPI) -> None:
    """Configure middleware for the FastAPI application."""

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,  # Not needed for token-based auth (uses query params & headers)
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
        expose_headers=["*"],
        max_age=600,
    )


def setup_security_headers(app: FastAPI) -> None:
    """Configure security headers middleware."""

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        csp_value = (
            "default-src 'self';"
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://cdnjs.cloudflare.com https://maxcdn.bootstrapcdn.com "
            "https://www.googletagmanager.com https://*.googletagmanager.com "
            "https://www.google-analytics.com https://*.cloudflareinsights.com;"
            "style-src 'self' 'unsafe-inline' "
            "https://cdnjs.cloudflare.com https://fonts.googleapis.com "
            "https://xposedornot.com https://maxcdn.bootstrapcdn.com;"
            "img-src 'self' https://xposedornot.com https://fastapi.tiangolo.com data: "
            "https://www.googletagmanager.com https://*.google-analytics.com "
            "https://*.googletagmanager.com;"
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com;"
            "object-src 'none';"
            "base-uri 'self';"
            "connect-src 'self' https://xposedornot.com https://api.xposedornot.com "
            "https://cdnjs.cloudflare.com https://maxcdn.bootstrapcdn.com "
            "https://*.google-analytics.com https://*.analytics.google.com "
            "https://*.googletagmanager.com https://*.cloudflareinsights.com;"
            "worker-src 'self' blob:;"
        )

        response.headers["Content-Security-Policy"] = csp_value
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), "
            "microphone=(), midi=(), payment=(), usb=()"
        )
        cacheable = request.url.path in PUBLIC_CACHEABLE_PATHS and (
            response.status_code in (200, 304)
        )
        if cacheable:
            response.headers["Cache-Control"] = PUBLIC_CACHE_CONTROL
        else:
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["X-Content-Type-Options"] = "nosniff"

        if cacheable and response.status_code == 200:
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            etag = f'"{hashlib.sha256(body).hexdigest()[:32]}"'

            if_none_match = request.headers.get("if-none-match", "")
            client_etags = {t.strip() for t in if_none_match.split(",") if t.strip()}
            if etag in client_etags:
                headers = dict(response.headers)
                headers.pop("content-length", None)
                headers.pop("content-type", None)
                headers["ETag"] = etag
                return Response(status_code=304, headers=headers)

            full = Response(
                content=body,
                status_code=response.status_code,
                headers=dict(response.headers),
            )
            full.headers["ETag"] = etag
            return full

        return response


_globe_tasks: "set[asyncio.Task]" = set()


async def process_globe_request_background(
    client_ip: str,
    city: Optional[str] = None,
    lat: Optional[str] = None,
    lon: Optional[str] = None,
) -> None:
    """Process the globe request in the background."""
    try:
        await process_request_for_globe(client_ip, city, lat, lon)
    except (ValueError, KeyError) as e:
        pass
    except Exception as e:
        pass


def setup_globe_middleware(app: FastAPI) -> None:
    """Configure globe visualization middleware."""

    @app.middleware("http")
    async def globe_request_middleware(request: Request, call_next):
        """Process request for globe visualization before processing the request."""
        try:
            client_ip = get_client_ip(request)

            city = request.headers.get("cf-ipcity")
            lat = request.headers.get("cf-iplatitude")
            lon = request.headers.get("cf-iplongitude")

            task = asyncio.create_task(
                process_globe_request_background(client_ip, city, lat, lon)
            )
            _globe_tasks.add(task)
            task.add_done_callback(_globe_tasks.discard)
        except (ValueError, KeyError) as e:
            pass
        except Exception as e:
            pass

        response = await call_next(request)
        return response
