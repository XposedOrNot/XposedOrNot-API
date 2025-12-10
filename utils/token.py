"""Token generation and verification utilities."""

from typing import Optional
import logging
from fastapi import HTTPException
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from config.settings import SECRET_APIKEY, SECURITY_SALT

# Configure logging
logger = logging.getLogger(__name__)


async def generate_confirmation_token(email: str) -> str:
    """
    Generate a secure confirmation token for email verification.
    """
    try:
        logger.debug("[TOKEN] Generating confirmation token for email: %s", email)
        serializer = URLSafeTimedSerializer(SECRET_APIKEY)
        token = serializer.dumps(email, salt=SECURITY_SALT)
        logger.debug("[TOKEN] Successfully generated token for email: %s", email)
        return token
    except Exception as e:
        logger.error(
            "[TOKEN] Error generating confirmation token: %s", str(e), exc_info=True
        )
        raise HTTPException(
            status_code=500, detail="Error generating confirmation token"
        ) from e


async def confirm_token(token: str, expiration: int = 604800) -> Optional[str]:
    """
    Verify and decode a confirmation token.

    Args:
        token: The token to verify
        expiration: Token expiration in seconds (default: 7 days)
    """
    try:
        logger.debug("[TOKEN] Verifying token with expiration: %s", expiration)
        serializer = URLSafeTimedSerializer(SECRET_APIKEY)
        email = serializer.loads(token, salt=SECURITY_SALT, max_age=expiration)
        logger.debug("[TOKEN] Successfully verified token for email: %s", email)
        return email
    except SignatureExpired:
        logger.error("[TOKEN] Token expired", exc_info=True)
        return None
    except BadSignature:
        logger.error("[TOKEN] Invalid token signature", exc_info=True)
        return None
    except Exception as e:
        logger.error("[TOKEN] Error verifying token: %s", str(e), exc_info=True)
        return None
