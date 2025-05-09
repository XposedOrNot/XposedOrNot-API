"""Request-related utility functions."""

from typing import Dict, Optional
from fastapi import Request
from user_agents import parse


def get_client_ip(request: Request) -> str:
    """
    Get the client IP address from the request headers.
    Prioritizes Cloudflare headers, then falls back to standard headers.
    """
    headers = request.headers
    ip_headers = {
        "CF-Connecting-IP": headers.get("CF-Connecting-IP"),
        "X-Forwarded-For": headers.get("X-Forwarded-For"),
        "X-Real-IP": headers.get("X-Real-IP"),
        "True-Client-IP": headers.get("True-Client-IP"),
        "Remote-Addr": getattr(request.client, "host", None),
        "X-Original-Forwarded-For": headers.get("X-Original-Forwarded-For"),
    }
    # Try to get IP from various headers in order of reliability
    client_ip = None

    # 1. Try Cloudflare headers first
    if headers.get("CF-Connecting-IP"):
        client_ip = headers["CF-Connecting-IP"].strip()

        return client_ip

    # 2. Try True-Client-IP
    if headers.get("True-Client-IP"):
        client_ip = headers["True-Client-IP"].strip()

        return client_ip

    # 3. Try X-Forwarded-For
    if headers.get("X-Forwarded-For"):
        # Get the leftmost IP which is typically the client
        ips = [ip.strip() for ip in headers["X-Forwarded-For"].split(",")]
        # Filter out private and reserved IPs
        public_ips = [ip for ip in ips if not ipaddress.ip_address(ip).is_private]
        if public_ips:
            client_ip = public_ips[0]

            return client_ip
        client_ip = ips[0]

        return client_ip

    # 4. Try X-Real-IP
    if headers.get("X-Real-IP"):
        client_ip = headers["X-Real-IP"].strip()

        return client_ip

    # Fallback to remote address
    client_ip = request.client.host if request.client else "0.0.0.0"

    # Basic IP validation
    if not client_ip or client_ip == "0.0.0.0":
        return "0.0.0.0"

    return client_ip


def get_user_agent_info(request: Request) -> tuple[str, str]:
    """
    Extract browser and platform information from the request.
    """
    user_agent_string = request.headers.get("User-Agent")
    user_agent = parse(user_agent_string)
    browser_type = f"{user_agent.browser.family} {user_agent.browser.version_string}"
    client_platform = user_agent.os.family
    return browser_type, client_platform
