"""Redaction helpers for keeping PII and secrets out of logs.

Used to scrub exception/log payloads before they are persisted to Datastore
or emailed to admins. Emails are masked to their local-part initial
(``a***@example.com``) and token-like values are dropped entirely.
"""

import re

# Matches an email; group(1) is the first local-part char, group(2) is "@domain".
_EMAIL_RE = re.compile(
    r"([a-zA-Z0-9._%+\-])[a-zA-Z0-9._%+\-]*(@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"
)

# Matches "token=<value>" (and *_token=) but leaves already-redacted markers alone.
_TOKEN_KV_RE = re.compile(
    r"\b(\w*token)=(?!provided\b|not_provided\b|missing\b)[^\s,&]+",
    re.IGNORECASE,
)


def mask_email(email):
    """Mask the local part of an email: ``user@example.com`` -> ``u***@example.com``."""
    if not email or "@" not in str(email):
        return email
    local, _, domain = str(email).partition("@")
    masked_local = (local[0] + "***") if local else "***"
    return f"{masked_local}@{domain}"


def sanitize_log_text(text):
    """Mask emails and redact token values in a free-form log string."""
    if not text:
        return text
    text = _EMAIL_RE.sub(lambda m: m.group(1) + "***" + m.group(2), str(text))
    text = _TOKEN_KV_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    return text
