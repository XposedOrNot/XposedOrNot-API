"""General utility functions for the application."""

import socket
import hashlib
import ipaddress
from typing import Optional, Dict, Any
import requests
from requests.exceptions import RequestException
from user_agents import parse
from fastapi import Request
from utils.validation import validate_url, validate_variables, validate_email_with_tld


def validate_domain(domain: str) -> bool:
    """Returns True if the domain is valid, False otherwise."""
    if not is_valid_domain_name(domain):
        return False
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def is_valid_domain_name(domain: str) -> bool:
    """Check if a domain name is valid."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


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
    except RequestException:
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
