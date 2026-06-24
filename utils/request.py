"""Request-related utility functions."""

import ipaddress
from typing import Dict, Optional
from fastapi import Request
from user_agents import parse


def get_client_ip(request: Request) -> str:
    """
    Get the client IP address for rate limiting and logging.

    All legitimate traffic reaches us through Cloudflare, which sets
    ``CF-Connecting-IP`` and a caller cannot forge it *through* Cloudflare, so
    we trust ONLY that header. The other forwarding headers
    (``X-Forwarded-For``, ``True-Client-IP``, ``X-Real-IP``) are
    caller-controlled on our topology — trusted proxies append the real client
    on the right while the left is whatever the caller prepended — so keying on
    them would let a caller mint a fresh rate-limit key per request and bypass
    limiting. Requests without ``CF-Connecting-IP`` did not come through
    Cloudflare; collapse them into a single bucket so that path is throttled
    collectively (until the origin is locked to Cloudflare).
    """
    cf_ip = (request.headers.get("CF-Connecting-IP") or "").strip()
    if cf_ip:
        try:
            ipaddress.ip_address(cf_ip)
            return cf_ip
        except ValueError:
            pass

    return "non-cloudflare"


def get_user_agent_info(request: Request) -> tuple[str, str]:
    """
    Extract browser and platform information from the request.
    """
    user_agent_string = request.headers.get("User-Agent")
    user_agent = parse(user_agent_string)
    browser_type = f"{user_agent.browser.family} {user_agent.browser.version_string}"
    client_platform = user_agent.os.family
    return browser_type, client_platform
