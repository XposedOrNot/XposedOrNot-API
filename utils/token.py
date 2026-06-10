"""Token generation and verification utilities."""

from typing import Optional
import logging
from fastapi import HTTPException
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from config.settings import SECRET_APIKEY, SECURITY_SALT
from utils.redaction import mask_email

# Configure logging
logger = logging.getLogger(__name__)


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
