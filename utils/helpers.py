"""General utility functions for the application."""

# Standard library imports
import hashlib
import ipaddress
import re
import logging
from typing import Optional, Dict, Any

# Third-party imports
import requests
from fastapi import Request
from user_agents import parse

# Local imports
from utils.validation import validate_url, validate_variables, validate_email_with_tld

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP address from request headers.
    Handles various proxy and load balancer scenarios.
    """
    headers = request.headers

    # Log specific IP-related headers
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

    # 5. Fallback to direct client address
    client_ip = getattr(request.client, "host", "unknown")

    if client_ip == "unknown" or client_ip.startswith("169.254"):
        logger.warning(f"Potentially invalid IP address detected: {client_ip}")
        # Try to get any other available IP information
        logger.warning(f"All available headers: {dict(headers)}")

    return client_ip


def validate_domain(domain: str) -> bool:
    """Returns True if the domain is valid, False otherwise."""
    if not domain:
        return False
    domain_pattern = (
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$"
    )

    parts = domain.split(".")
    if len(parts) < 2 or len(parts[-1]) < 2:
        return False

    return bool(re.match(domain_pattern, domain))


def is_valid_domain_name(domain: str) -> bool:
    """Check if a domain name is valid."""
    return validate_domain(domain)


def is_valid_ip(ip_address: str) -> bool:
    """Check if an IP address is valid."""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def get_preferred_ip_address(x_forwarded_for: str) -> Optional[str]:
    """Get the preferred IP address from X-Forwarded-For header."""
    if not x_forwarded_for:
        return None

    # Split the string into individual IP addresses
    ip_addresses = x_forwarded_for.split(",")

    # Return the first IP address that is valid
    for ip in ip_addresses:
        ip = ip.strip()
        if is_valid_ip(ip):
            return ip

    return None


def fetch_location_by_ip(ip_address: str) -> str:
    """Fetch location information for an IP address."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return data.get("isp", "Unknown ISP")
    except requests.RequestException:
        # Log the error if needed
        pass
    return "Unknown ISP"


def generate_request_hash(data: Dict[str, Any]) -> str:
    """Generate a hash for the request data."""
    data_str = str(sorted(data.items()))
    return hashlib.sha256(data_str.encode()).hexdigest()


def get_client_info(request: Request) -> Dict[str, str]:
    """Get client information from the request."""
    user_agent_string = request.headers.get("user-agent", "")
    user_agent = parse(user_agent_string)

    return {
        "ip_address": request.client.host if request.client else "unknown",
        "browser_type": f"{user_agent.browser.family} {user_agent.browser.version_string}",
        "client_platform": f"{user_agent.os.family} {user_agent.os.version_string}",
    }


def string_to_boolean(value: str) -> bool:
    """Convert a string to a boolean value."""
    return value.lower() in ("true", "t", "yes", "y", "1")
