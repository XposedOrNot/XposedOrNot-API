"""
Safe encoding utilities for preventing XSS and URL injection vulnerabilities.

This module provides standardized functions for:
- HTML escaping (prevent XSS in displayed content)
- URL encoding (prevent parameter injection in URLs)
- RSS content escaping (prevent XSS in feed readers)

Usage:
    from utils.safe_encoding import escape_html, build_safe_url, escape_html_attr

    # For displaying user data in HTML text:
    f"Hello, {escape_html(username)}"

    # For building URLs with parameters:
    url = build_safe_url("https://example.com/page.html", {"email": email, "token": token})

    # For HTML attributes (src, href with user data):
    f"<img src='{escape_html_attr(logo_url)}' />"

    # For fragment identifiers:
    f"<a href='https://example.com/#{escape_url_fragment(breach_name)}'>"
"""

import html
from urllib.parse import urlencode, quote
from typing import Optional, Dict, Any


def escape_html(value: Any) -> str:
    """
    Escape HTML special characters for safe display in HTML content.

    Converts: < > & " ' to their HTML entity equivalents.
    Use for: Text content displayed to users in HTML.

    Args:
        value: The value to escape (will be converted to string)

    Returns:
        HTML-escaped string safe for display

    Example:
        escape_html("<script>alert('xss')</script>")
        → "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def escape_html_attr(value: Any) -> str:
    """
    Escape value for use in HTML attributes (src, href, etc.).

    Use for: Dynamic values in img src, anchor href, style attributes, etc.

    Args:
        value: The value to escape (will be converted to string)

    Returns:
        HTML-escaped string safe for use in attributes

    Example:
        f"<img src='{escape_html_attr(logo_url)}' />"
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def escape_url_fragment(value: Any) -> str:
    """
    Escape value for use in URL fragment identifiers (#anchor).

    Use for: Anchor links with dynamic values like breach names.

    Args:
        value: The value to escape (will be converted to string)

    Returns:
        URL-encoded string safe for use in fragments

    Example:
        f"<a href='https://example.com/page#{escape_url_fragment(section_name)}'>"
    """
    if value is None:
        return ""
    # Quote everything except alphanumerics and safe chars
    return quote(str(value), safe="")


def build_safe_url(base_url: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Build a URL with properly encoded query parameters.

    Use for: Any URL construction with dynamic query parameters.

    Args:
        base_url: The base URL (e.g., "https://example.com/page.html")
        params: Dictionary of query parameters to encode

    Returns:
        Complete URL with properly encoded query string

    Example:
        build_safe_url("https://example.com/dashboard", {"email": "user@test.com"})
        → "https://example.com/dashboard?email=user%40test.com"
    """
    if not params:
        return base_url

    query_string = urlencode(params)
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}{query_string}"


def escape_rss_content(value: Any) -> str:
    """
    Escape content for RSS feed descriptions.

    RSS readers may render HTML, so we escape to prevent XSS.
    Uses quote=False to avoid escaping quotes in text content.

    Args:
        value: The value to escape (will be converted to string)

    Returns:
        XML-escaped string safe for RSS content

    Example:
        escape_rss_content(breach_description)
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=False)
