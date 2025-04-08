"""Request handling utilities."""

import logging
import ipaddress
from fastapi import Request
from user_agents import parse


def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP address from request headers.
    Handles various proxy and load balancer scenarios.
    """
    headers = request.headers

    # Log all headers for debugging
    logging.debug("All request headers: %s", dict(headers))

    # Log specific IP-related headers
    ip_headers = {
        "CF-Connecting-IP": headers.get("CF-Connecting-IP"),
        "X-Forwarded-For": headers.get("X-Forwarded-For"),
        "X-Real-IP": headers.get("X-Real-IP"),
        "True-Client-IP": headers.get("True-Client-IP"),
        "Remote-Addr": getattr(request.client, "host", None),
        "X-Original-Forwarded-For": headers.get("X-Original-Forwarded-For"),
    }
    logging.info("IP-related headers: %s", ip_headers)

    # Try to get IP from various headers in order of reliability
    client_ip = None

    # 1. Try Cloudflare headers first
    if headers.get("CF-Connecting-IP"):
        client_ip = headers["CF-Connecting-IP"].strip()
        logging.info("Using CF-Connecting-IP: %s", client_ip)
        return client_ip

    # 2. Try True-Client-IP
    if headers.get("True-Client-IP"):
        client_ip = headers["True-Client-IP"].strip()
        logging.info("Using True-Client-IP: %s", client_ip)
        return client_ip

    # 3. Try X-Forwarded-For
    if headers.get("X-Forwarded-For"):
        # Get the leftmost IP which is typically the client
        ips = [ip.strip() for ip in headers["X-Forwarded-For"].split(",")]
        # Filter out private and reserved IPs
        public_ips = [ip for ip in ips if not ipaddress.ip_address(ip).is_private]
        if public_ips:
            client_ip = public_ips[0]
            logging.info("Using X-Forwarded-For (public IP): %s", client_ip)
            return client_ip
        client_ip = ips[0]
        logging.info("Using X-Forwarded-For (first IP): %s", client_ip)
        return client_ip

    # 4. Try X-Real-IP
    if headers.get("X-Real-IP"):
        client_ip = headers["X-Real-IP"].strip()
        logging.info("Using X-Real-IP: %s", client_ip)
        return client_ip

    # 5. Fallback to direct client address
    client_ip = getattr(request.client, "host", "unknown")
    logging.info("Using fallback client IP: %s", client_ip)

    if client_ip == "unknown" or client_ip.startswith("169.254"):
        logging.warning("Potentially invalid IP address detected: %s", client_ip)
        # Try to get any other available IP information
        logging.warning("All available headers: %s", dict(headers))

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
