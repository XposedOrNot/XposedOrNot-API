"""Centralized rate limiter configuration."""

from datetime import datetime, timedelta
from typing import Tuple, Optional, Dict

from slowapi import Limiter
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi.util import get_remote_address

# Local imports
from utils.helpers import get_client_ip
from config.settings import REDIS_URL


def get_key_func(request: Request) -> str:
    """
    Enhanced key function that combines IP and endpoint for more granular rate limiting.
    """
    client_ip = get_client_ip(request)
    endpoint = request.url.path
    return f"{client_ip}:{endpoint}"


# Initialize the rate limiter with enhanced key function and Redis storage
limiter = Limiter(
    key_func=get_key_func,  # Use our enhanced key function
    default_limits=["2 per second;5 per hour;100 per day"],
    storage_uri=REDIS_URL,  # Use Redis URL from settings
    strategy="fixed-window",  # Use fixed window strategy for more predictable rate limiting
)

# Define specific rate limits for different types of routes
RATE_LIMIT_HELP = "50 per day;10 per hour"  # For help/documentation routes
RATE_LIMIT_UNBLOCK = "24 per day;2 per hour;2 per second"  # For unblock operations
RATE_LIMIT_BREACHES = "2 per second;5 per hour;100 per day"  # For breach listing
RATE_LIMIT_CHECK_EMAIL = "2 per second;5 per hour;100 per day"  # For email checks
RATE_LIMIT_ANALYTICS = (
    "5 per minute;100 per hour;500 per day"  # For analytics endpoints
)
RATE_LIMIT_DOMAIN = (
    "2 per second;10 per hour;50 per day"  # For domain-related endpoints
)
RATE_LIMIT_INVALID_ROUTE = (
    "5 per minute;20 per hour"  # Stricter limit for invalid routes
)

# Initialize a set to store valid routes
_valid_routes = set()


def register_route(route: str) -> None:
    """
    Register a valid route in the application.

    Args:
        route: The route path to register
    """
    _valid_routes.add(route)


def is_valid_route(route: str) -> bool:
    """
    Check if a route exists in the application.

    Args:
        route: The route path to check

    Returns:
        bool: True if the route exists, False otherwise
    """
    return route in _valid_routes


def _parse_rate_limit(limit_str: str) -> Tuple[int, str]:
    """
    Parse a rate limit string into a tuple of (limit, period).

    Args:
        limit_str: String in format "X per Y" (e.g., "2 per second")

    Returns:
        Tuple of (limit, period)
    """
    try:
        limit, _, period = limit_str.strip().split()
        return int(limit), period
    except ValueError:
        return 2, "second"  # Default fallback


def get_rate_limit_key(request: Request) -> str:
    """
    Get a unique key for rate limiting based on the request.

    Args:
        request: FastAPI request object

    Returns:
        String key for rate limiting
    """
    client_ip = get_remote_address(request)  # Use slowapi's built-in IP detection
    endpoint = request.url.path
    return f"{client_ip}:{endpoint}"


def rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceeded
) -> JSONResponse:
    """
    Custom handler for rate limit exceeded exceptions.
    Includes retry-after header and detailed response.
    """
    # Calculate retry after time based on the rate limit that was exceeded
    retry_after = 1  # Default to 1 second
    if hasattr(exc, "retry_after"):
        retry_after = exc.retry_after
    reset_time = datetime.now() + timedelta(seconds=retry_after)

    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded",
            "detail": str(exc),
            "retry_after": retry_after,
            "reset_time": reset_time.isoformat(),
        },
        headers={"Retry-After": str(retry_after)},
    )


def setup_limiter(app: FastAPI) -> None:
    """
    Set up rate limiting for the FastAPI application.

    Args:
        app: FastAPI application instance
    """
    # Add the limiter to the app state
    app.state.limiter = limiter

    # Add the SlowAPI middleware
    app.add_middleware(SlowAPIMiddleware)

    # Add custom rate limit exceeded handler
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
