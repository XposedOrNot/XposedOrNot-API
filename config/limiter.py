"""Centralized rate limiter configuration."""

from datetime import datetime, timedelta
from typing import Tuple, Optional

from slowapi import Limiter
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from utils.helpers import get_client_ip

# Create a single limiter instance to be used across the application
limiter = Limiter(key_func=get_client_ip)


def _parse_rate_limit(rate_limit: str) -> Tuple[int, str]:
    """
    Parse rate limit string into count and period.
    Example: "2 per second" -> (2, "second")
    """
    count, _, period = rate_limit.partition(" per ")
    return int(count), period.strip()


def _calculate_retry_after(rate_limit: str, reset_time: datetime) -> int:
    """
    Calculate retry-after value in seconds based on rate limit and reset time.
    """
    now = datetime.utcnow()
    if reset_time <= now:
        return 0

    # Get the period from rate limit string
    _, period = _parse_rate_limit(rate_limit)

    # Calculate seconds based on period
    if period == "second":
        return 1
    elif period == "minute":
        return 60
    elif period == "hour":
        return 3600
    elif period == "day":
        return 86400

    # Default to 1 second if period is unknown
    return 1


def rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceeded
) -> JSONResponse:
    """
    Custom handler for rate limit exceeded exceptions.
    Includes retry-after header and detailed response.
    """
    retry_after = _calculate_retry_after(exc.rate_limit, exc.reset_time)

    # Get all rate limits for this endpoint
    rate_limits = exc.rate_limit.split(";")
    retry_after_values = []

    for limit in rate_limits:
        count, period = _parse_rate_limit(limit)
        if period == "second":
            retry_after_values.append(1)
        elif period == "minute":
            retry_after_values.append(60)
        elif period == "hour":
            retry_after_values.append(3600)
        elif period == "day":
            retry_after_values.append(86400)

    # Use the smallest retry-after value
    retry_after = min(retry_after_values) if retry_after_values else 1

    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded",
            "detail": f"Rate limit of {exc.rate_limit} exceeded",
            "retry_after": retry_after,
            "reset_time": exc.reset_time.isoformat() if exc.reset_time else None,
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
