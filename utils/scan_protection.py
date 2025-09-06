"""Custom 404 handler with path-based scanning protection."""

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.status import HTTP_429_TOO_MANY_REQUESTS
from datetime import datetime, timedelta

from utils.custom_limiter import (
    get_healthy_redis_connection,
    is_rate_limited,
    parse_rate_limit,
    get_violation_count,
    increment_violation,
    get_drop_percentage,
)
from utils.helpers import get_client_ip

# Rate limits for scanning protection - strict limits for non-API paths
SCAN_404_RATE_LIMIT = "5 per minute;15 per hour;50 per day"

# Known legitimate paths that might return 404
LEGITIMATE_PATH_PREFIXES = {
    "/v1/",  # All API endpoints
    "/static/",  # Static files
    "/docs",  # Documentation
    "/openapi.json",  # OpenAPI spec
    "/robots.txt",  # Robots file
    "/mcp",  # MCP endpoints
    "/_health",  # Health check
}


def is_legitimate_path(path: str) -> bool:
    """Check if the path is a legitimate API endpoint or known path."""
    path = path.lower()

    # Check exact matches
    if path in {"/docs", "/openapi.json", "/robots.txt", "/mcp", "/_health", "/"}:
        return True

    # Check prefixes
    for prefix in LEGITIMATE_PATH_PREFIXES:
        if path.startswith(prefix):
            return True

    return False


async def handle_404_with_protection(request: Request, exc: HTTPException):
    """
    Custom 404 handler that applies rate limiting to scanning attempts
    while allowing legitimate API 404s to pass through normally.
    """
    path = request.url.path

    if is_legitimate_path(path):
        return JSONResponse(
            status_code=404,
            content={"detail": exc.detail if hasattr(exc, "detail") else "Not Found"},
        )

    client_ip = get_client_ip(request)

    try:
        redis_conn = await get_healthy_redis_connection()

        # Create rate limit key for scanning protection
        key = f"scan-404:{client_ip}"
        rate_limits = parse_rate_limit(SCAN_404_RATE_LIMIT)

        # Check violation history and apply progressive dropping
        violation_count = await get_violation_count(client_ip, redis_conn)
        drop_percentage = get_drop_percentage(violation_count)

        # Apply progressive request dropping for repeat violators
        if violation_count > 0:
            import random

            if random.random() < drop_percentage:
                return JSONResponse(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "error": "Request dropped",
                        "path": path,
                        "violation_count": violation_count,
                        "drop_percentage": f"{drop_percentage * 100:.0f}%",
                        "detail": f"Request dropped due to previous violations.",
                    },
                    headers={
                        "X-Dropped": "true",
                        "X-Protection-Type": "scan-404",
                        "X-Violation-Count": str(violation_count),
                        "X-Drop-Percentage": f"{drop_percentage * 100:.0f}%",
                    },
                )

        # Check rate limits
        limited, retry_after = await is_rate_limited(key, rate_limits, redis_conn)

        if limited:
            # Increment violation count for this IP
            await increment_violation(client_ip, redis_conn)

            reset_time = datetime.now() + timedelta(seconds=retry_after)

            return JSONResponse(
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "type": "scanning_protection",
                    "path": path,
                    "detail": f"Rate limit exceeded for unknown endpoint requests. Stop scanning behavior.",
                    "retry_after": retry_after,
                    "reset_time": reset_time.isoformat(),
                    "warning": "Automated scanning is not permitted.",
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-Protection-Type": "scan-404",
                    "X-Rate-Limit-Type": "scanning",
                },
            )

        return JSONResponse(
            status_code=404,
            content={"detail": "Not Found"},
            headers={"X-Protection-Type": "scan-404-allowed"},
        )

    except Exception as e:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
