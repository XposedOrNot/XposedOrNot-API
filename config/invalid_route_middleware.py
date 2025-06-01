"""Middleware for handling invalid routes with stricter rate limiting."""

from typing import Callable, Optional, Any, Dict
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.types import ASGIApp, Receive, Scope, Send

from config.limiter import (
    limiter,
    RATE_LIMIT_INVALID_ROUTE,
    is_valid_route,
    get_key_func,
)


def normalize_path(path: str) -> str:
    """
    Normalize a path by replacing path parameters with their pattern.

    Args:
        path: The path to normalize

    Returns:
        str: The normalized path
    """

    parts = path.split("/")
    normalized_parts = []

    for part in parts:

        if "." in part and not any(c in part for c in ["{", "}"]):
            normalized_parts.append("{domain}")

        elif len(part) > 20 and not any(c in part for c in ["{", "}"]):
            normalized_parts.append("{token}")
        else:
            normalized_parts.append(part)

    return "/".join(normalized_parts)


class InvalidRouteMiddleware:
    """Middleware to handle invalid routes with stricter rate limiting."""

    def __init__(self, app: ASGIApp):
        """Initialize the middleware with the FastAPI app."""
        self.app = app
        self._invalid_route_limiter: Optional[Limiter] = None

    @property
    def invalid_route_limiter(self) -> Limiter:
        """Lazily initialize and return the invalid route limiter."""
        if self._invalid_route_limiter is None:

            app = self.app.app if hasattr(self.app, "app") else self.app
            if not hasattr(app, "state") or not hasattr(app.state, "limiter"):
                raise RuntimeError("FastAPI app state or limiter not initialized")

            self._invalid_route_limiter = Limiter(
                key_func=get_key_func,
                default_limits=[RATE_LIMIT_INVALID_ROUTE],
                storage_uri=app.state.limiter.storage_uri,
                strategy="fixed-window",
            )
        return self._invalid_route_limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        Process the request and apply rate limiting for invalid routes.

        Args:
            scope: The ASGI scope
            receive: The ASGI receive callable
            send: The ASGI send callable
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        route_path = request.url.path

        normalized_path = normalize_path(route_path)

        is_valid = is_valid_route(route_path) or is_valid_route(normalized_path)

        if is_valid:

            await self.app(scope, receive, send)
            return

        response = JSONResponse(
            status_code=404,
            content={"detail": "Not found"},
        )
        await response(scope, receive, send)


def setup_invalid_route_middleware(app: FastAPI) -> None:
    """
    Set up the invalid route middleware for the FastAPI application.

    Args:
        app: FastAPI application instance
    """
    app.add_middleware(InvalidRouteMiddleware)
