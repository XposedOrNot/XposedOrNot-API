"""Token generation and verification utilities."""

from typing import Optional
import logging
from fastapi import HTTPException
from itsdangerous import URLSafeTimedSerializer

from config.settings import SECRET_APIKEY, SECURITY_SALT

# Configure logging
logger = logging.getLogger(__name__)


async def generate_confirmation_token(email: str) -> str:
    """
    Generate a secure confirmation token for email verification.
    """
    try:
        logger.debug(f"[TOKEN] Generating confirmation token for email: {email}")
        serializer = URLSafeTimedSerializer(SECRET_APIKEY)
        token = serializer.dumps(email, salt=SECURITY_SALT)
        logger.debug(f"[TOKEN] Successfully generated token for email: {email}")
        return token
    except Exception as e:
        logger.error(
            f"[TOKEN] Error generating confirmation token: {str(e)}", exc_info=True
        )
        raise HTTPException(
            status_code=500, detail="Error generating confirmation token"
        ) from e


async def confirm_token(token: str, expiration: int = 1296000) -> Optional[str]:
    """
    Verify and decode a confirmation token.
    """
    try:
        logger.debug(f"[TOKEN] Verifying token with expiration: {expiration}")
        serializer = URLSafeTimedSerializer(SECRET_APIKEY)
        email = serializer.loads(token, salt=SECURITY_SALT, max_age=expiration)
        logger.debug(f"[TOKEN] Successfully verified token for email: {email}")
        return email
    except Exception as e:
        logger.error(f"[TOKEN] Error verifying token: {str(e)}", exc_info=True)
        return None
