"""Middleware for handling invalid routes with stricter rate limiting."""

from typing import Callable
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from config.limiter import (
    limiter,
    RATE_LIMIT_INVALID_ROUTE,
    is_valid_route,
    get_key_func,
)


class InvalidRouteMiddleware:
    """Middleware to handle invalid routes with stricter rate limiting."""

    def __init__(self, app: FastAPI):
        """Initialize the middleware with the FastAPI app."""
        self.app = app
        # Create a separate limiter for invalid routes
        self.invalid_route_limiter = Limiter(
            key_func=get_key_func,
            default_limits=[RATE_LIMIT_INVALID_ROUTE],
            storage_uri=app.state.limiter.storage_uri,
            strategy="fixed-window",
        )

    async def __call__(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and apply rate limiting for invalid routes.

        Args:
            request: The incoming request
            call_next: The next middleware/route handler

        Returns:
            Response: The response to send back
        """
        # Get the route path
        route_path = request.url.path

        # Check if it's a valid route
        if is_valid_route(route_path):
            # Let the normal rate limiting and routing take over
            return await call_next(request)

        # For invalid routes, apply stricter rate limiting
        try:
            # Use the invalid route limiter
            await self.invalid_route_limiter.check(request)

            # If rate limit not exceeded, return a generic 404
            return JSONResponse(
                status_code=404,
                content={"detail": "Not found"},
            )

        except Exception as e:
            # If rate limit exceeded, return a 429 with a generic message
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests",
                    "error": "rate_limit_exceeded",
                },
                headers={"Retry-After": "60"},
            )


def setup_invalid_route_middleware(app: FastAPI) -> None:
    """
    Set up the invalid route middleware for the FastAPI application.

    Args:
        app: FastAPI application instance
    """
    app.add_middleware(InvalidRouteMiddleware)
