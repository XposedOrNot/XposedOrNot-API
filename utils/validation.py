"""Validation utilities for the application."""

import re
from urllib.parse import urlparse
from fastapi import Request


def validate_variables(variables_to_validate: list) -> bool:
    """Validate input variables to ensure they contain only valid characters."""
    pattern = r"^[a-zA-Z0-9@._:/-]*$"
    return all(
        value and not value.isspace() and re.match(pattern, value)
        for value in variables_to_validate
    )


def validate_url(request: Request) -> bool:
    """Returns True if the url is a valid url, False otherwise."""
    try:
        url = str(request.url)
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except (ValueError, AttributeError):
        return False


def validate_email_with_tld(email: str) -> bool:
    """Validate email with a basic format check."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))
