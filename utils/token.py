"""Token generation and verification utilities."""

import datetime
import logging
from typing import Optional

from fastapi import HTTPException
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from config.settings import SECRET_APIKEY, SECURITY_SALT
from utils.redaction import mask_email

# Configure logging
logger = logging.getLogger(__name__)

DASHBOARD_SESSION_MAX_AGE_HOURS = 12


def validate_dashboard_session(datastore_client, email: str, token: str) -> bool:
    """
    Validate a dashboard magic-link session token for an email.

    Accepts the session created by the domain-alert/domain-verify flow
    (xon_domains_session) and enforces the same 12-hour expiry as the
    dashboard data routes.
    """
    if not email or not token:
        return False
    try:
        session_key = datastore_client.key("xon_domains_session", email)
        session_record = datastore_client.get(session_key)
        if not session_record or session_record.get("domain_magic") != token:
            return False
        magic_timestamp = session_record.get("magic_timestamp")
        if magic_timestamp is None:
            return False
        age = datetime.datetime.utcnow() - magic_timestamp.replace(tzinfo=None)
        return age <= datetime.timedelta(hours=DASHBOARD_SESSION_MAX_AGE_HOURS)
    except Exception:  # pylint: disable=broad-except
        return False


async def generate_confirmation_token(email: str) -> str:
    """
    Generate a secure confirmation token for email verification.
    """
    try:
        logger.debug(
            "[TOKEN] Generating confirmation token for email: %s", mask_email(email)
        )
        serializer = URLSafeTimedSerializer(SECRET_APIKEY)
        token = serializer.dumps(email, salt=SECURITY_SALT)
        logger.debug(
            "[TOKEN] Successfully generated token for email: %s", mask_email(email)
        )
        return token
    except Exception as e:
        logger.error(
            "[TOKEN] Error generating confirmation token: %s", str(e), exc_info=True
        )
        raise HTTPException(
            status_code=500, detail="Error generating confirmation token"
        ) from e


async def confirm_token(token: str, expiration: int = 86400) -> Optional[str]:
    """
    Verify and decode a confirmation token.

    Args:
        token: The token to verify
        expiration: Token expiration in seconds (default: 24 hours)
    """
    try:
        logger.debug("[TOKEN] Verifying token with expiration: %s", expiration)
        serializer = URLSafeTimedSerializer(SECRET_APIKEY)
        email = serializer.loads(token, salt=SECURITY_SALT, max_age=expiration)
        logger.debug(
            "[TOKEN] Successfully verified token for email: %s", mask_email(email)
        )
        return email
    except SignatureExpired:
        logger.warning("[TOKEN] Token expired")
        return None
    except BadSignature:
        logger.error("[TOKEN] Invalid token signature", exc_info=True)
        return None
    except Exception as e:
        logger.error("[TOKEN] Error verifying token: %s", str(e), exc_info=True)
        return None
