"""Middleware configurations for the application."""

# Standard library imports
import asyncio

# Third-party imports
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

# Local imports
from services.globe import process_request_for_globe
from utils.request import get_client_ip


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
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["X-Content-Type-Options"] = "nosniff"

        return response


async def process_globe_request_background(client_ip: str) -> None:
    """Process the globe request in the background."""
    try:
        await process_request_for_globe(client_ip)
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

            asyncio.create_task(process_globe_request_background(client_ip))
        except (ValueError, KeyError) as e:
            pass
        except Exception as e:
            pass

        response = await call_next(request)
        return response
