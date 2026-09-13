"""Security helpers for notification-channel webhooks.

Fernet encryption of stored webhook URLs / secrets, Slack and Teams URL
allowlists, an SSRF guard for owner-supplied URLs, and custom-header
validation. The cipher is built lazily because FERNET_KEY is optional in
the settings module.
"""

import ipaddress
import logging
import re
import socket
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from cryptography.fernet import Fernet

from config.settings import FERNET_KEY

logger = logging.getLogger(__name__)

_cipher: Optional[Fernet] = None


def get_cipher() -> Fernet:
    """Return the process-wide Fernet cipher built from ENCRYPTION_KEY.

    Raised lazily (not at import) so the rest of the API still boots when the
    key is absent; every channel operation that touches a stored webhook will
    then fail with a clear message instead of an AttributeError.
    """
    global _cipher
    if _cipher is None:
        if not FERNET_KEY:
            raise ValueError(
                "ENCRYPTION_KEY is not set; it is required for notification channels"
            )
        _cipher = Fernet(FERNET_KEY)
    return _cipher


def encrypt_webhook(webhook_url: str) -> str:
    """
    Encrypt webhook URL using Fernet cipher.

    Args:
        webhook_url: The webhook URL to encrypt

    Returns:
        str: Encrypted webhook URL as a string

    Raises:
        ValueError: If webhook_url is empty or encryption fails
    """
    try:
        if not webhook_url or not isinstance(webhook_url, str):
            raise ValueError("Webhook URL must be a non-empty string")

        encrypted_bytes = get_cipher().encrypt(webhook_url.encode())
        encrypted_str = encrypted_bytes.decode()
        logger.debug("Successfully encrypted webhook URL")
        return encrypted_str

    except Exception as e:
        logger.error(f"Failed to encrypt webhook URL: {str(e)}")
        raise ValueError(f"Webhook encryption failed: {str(e)}") from e


def decrypt_webhook(encrypted_webhook: str) -> str:
    """
    Decrypt webhook URL using Fernet cipher.

    Args:
        encrypted_webhook: The encrypted webhook URL

    Returns:
        str: Decrypted webhook URL

    Raises:
        ValueError: If encrypted_webhook is invalid or decryption fails
    """
    try:
        if not encrypted_webhook or not isinstance(encrypted_webhook, str):
            raise ValueError("Encrypted webhook must be a non-empty string")

        decrypted_bytes = get_cipher().decrypt(encrypted_webhook.encode())
        decrypted_str = decrypted_bytes.decode()
        logger.debug("Successfully decrypted webhook URL")
        return decrypted_str

    except Exception as e:
        logger.error(f"Failed to decrypt webhook URL: {str(e)}")
        raise ValueError(f"Webhook decryption failed: {str(e)}") from e


def validate_slack_webhook_url(webhook_url: str) -> bool:
    """
    Validate Slack webhook URL format.

    Args:
        webhook_url: The webhook URL to validate

    Returns:
        bool: True if valid Slack webhook URL
    """
    if not webhook_url:
        return False

    slack_webhook_pattern = (
        r"^https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+$"
    )

    return bool(re.match(slack_webhook_pattern, webhook_url))


def validate_teams_webhook_url(webhook_url: str) -> bool:
    """
    Validate Microsoft Teams webhook URL format.

    Args:
        webhook_url: The webhook URL to validate

    Returns:
        bool: True if valid Teams webhook URL
    """
    if not webhook_url:
        return False

    try:
        parsed = urlparse(webhook_url)
    except ValueError:
        return False

    if parsed.scheme != "https":
        return False

    host = (parsed.hostname or "").lower()
    path = parsed.path or ""

    if host == "outlook.office.com":
        return path.startswith("/webhook/")
    if host.endswith(".webhook.office.com"):
        return path.startswith("/webhookb2/")
    if host.endswith(".api.powerplatform.com"):
        return True
    return False


MAX_WEBHOOK_URL_LENGTH = 2048

MAX_CUSTOM_HEADERS = 10

MAX_HEADER_NAME_LENGTH = 128

MAX_HEADER_VALUE_LENGTH = 1024

MAX_CUSTOM_HEADERS_TOTAL_BYTES = 4096

BLOCKED_CUSTOM_HEADERS = {
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
}

RESERVED_HEADER_PREFIX = "x-xon-"

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


def is_safe_public_url(url: str) -> Tuple[bool, str]:
    """
    SSRF guard: ensure a URL is HTTPS and resolves only to public addresses.

    Resolves the host and rejects loopback / private / link-local / reserved /
    multicast / unspecified addresses (incl. the cloud metadata IP). Re-run this
    on every outbound attempt to mitigate DNS-rebinding.

    Returns:
        Tuple[bool, str]: (is_safe, reason_if_not_safe)
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed webhook URL"

    if parsed.scheme != "https":
        return False, "Webhook URL must use HTTPS"

    host = parsed.hostname
    if not host:
        return False, "Webhook URL must include a valid host"

    try:
        addrinfos = socket.getaddrinfo(
            host, parsed.port or 443, proto=socket.IPPROTO_TCP
        )
    except Exception:
        return False, "Webhook host could not be resolved"

    if not addrinfos:
        return False, "Webhook host could not be resolved"

    for info in addrinfos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, "Webhook host resolved to an invalid address"

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False, "Webhook URL resolves to a disallowed (internal) address"

    return True, ""


def validate_generic_webhook_url(webhook_url: str) -> Tuple[bool, str]:
    """
    Validate a owner-supplied webhook URL (format + HTTPS + SSRF guard).

    Returns:
        Tuple[bool, str]: (is_valid, reason_if_invalid)
    """
    if not webhook_url:
        return False, "Webhook URL is required"

    if len(webhook_url) > MAX_WEBHOOK_URL_LENGTH:
        return False, "Webhook URL is too long"

    return is_safe_public_url(webhook_url)


def validate_custom_headers(
    headers: Optional[Dict[str, str]],
) -> Tuple[bool, str, Dict[str, str]]:
    """
    Validate optional owner-supplied custom headers for webhook delivery.

    Enforces a count cap, per-name/value length caps, a total-size cap, an RFC
    token charset on names, a CR/LF injection guard on values, and a blocklist
    of hop-by-hop / framing / reserved (X-XON-*) headers.

    Returns:
        Tuple[bool, str, Dict[str, str]]: (is_valid, reason_if_invalid, normalized_headers)
    """
    if not headers:
        return True, "", {}

    if not isinstance(headers, dict):
        return False, "Custom headers must be a key/value object", {}

    if len(headers) > MAX_CUSTOM_HEADERS:
        return False, f"At most {MAX_CUSTOM_HEADERS} custom headers are allowed", {}

    normalized: Dict[str, str] = {}
    total_bytes = 0
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            return False, "Custom header names and values must be strings", {}

        if not name or len(name) > MAX_HEADER_NAME_LENGTH:
            return False, f"Invalid custom header name: {name[:32]}", {}

        if len(value) > MAX_HEADER_VALUE_LENGTH:
            return False, f"Custom header value too long for: {name}", {}

        if not _HEADER_NAME_RE.match(name):
            return False, f"Invalid characters in custom header name: {name}", {}

        if any(c in value for c in ("\r", "\n")) or any(
            c in name for c in ("\r", "\n")
        ):
            return False, f"Illegal newline in custom header: {name}", {}

        lowered = name.lower()
        if lowered in BLOCKED_CUSTOM_HEADERS or lowered.startswith(
            RESERVED_HEADER_PREFIX
        ):
            return False, f"Custom header not allowed: {name}", {}

        total_bytes += len(name.encode()) + len(value.encode())
        if total_bytes > MAX_CUSTOM_HEADERS_TOTAL_BYTES:
            return False, "Custom headers exceed the total size limit", {}

        normalized[name] = value

    return True, "", normalized
