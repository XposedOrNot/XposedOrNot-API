"""Middleware configurations for the application."""

# Standard library imports
import asyncio
import logging

# Third-party imports
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address

# Local imports
from services.globe import process_request_for_globe
from utils.request import get_client_ip

# Configure logging
logger = logging.getLogger(__name__)


def setup_middleware(app: FastAPI) -> None:
    """Configure middleware for the FastAPI application."""

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
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
            "https://cdnjs.cloudflare.com https://maxcdn.bootstrapcdn.com;"
            "style-src 'self' 'unsafe-inline' "
            "https://cdnjs.cloudflare.com https://fonts.googleapis.com "
            "https://xposedornot.com https://maxcdn.bootstrapcdn.com;"
            "img-src 'self' https://xposedornot.com https://fastapi.tiangolo.com data:;"
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com;"
            "object-src 'none';"
            "base-uri 'self';"
            "connect-src 'self' https://xposedornot.com https://api.xposedornot.com https://cdnjs.cloudflare.com;"
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
        logger.error("Error in globe background task (value/key error): %s", str(e))
    except Exception as e:
        logger.error("Unexpected error in globe background task: %s", str(e))


def setup_globe_middleware(app: FastAPI) -> None:
    """Configure globe visualization middleware."""

    @app.middleware("http")
    async def globe_request_middleware(request: Request, call_next):
        """Process request for globe visualization before processing the request."""
        try:
            # Extract client IP using the existing utility
            client_ip = get_client_ip(request)

            # Create a background task for processing the globe request
            # This ensures the request is non-blocking
            asyncio.create_task(process_globe_request_background(client_ip))
        except (ValueError, KeyError) as e:
            # Log the error but don't block the request
            logger.error("Error extracting client IP: %s", str(e))
        except Exception as e:
            # Log the error but don't block the request
            logger.error("Unexpected error in globe middleware: %s", str(e))

        # Continue with the request
        response = await call_next(request)
        return response


def setup_rate_limiter(app: FastAPI) -> Limiter:
    """Configure rate limiter for the application."""
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
    )
    app.state.limiter = limiter
    return limiter
