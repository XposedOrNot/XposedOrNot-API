"""Security utilities for the application."""

from cryptography.fernet import Fernet
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from config.settings import FERNET_KEY, SECRET_APIKEY, SECURITY_SALT

# Initialize Fernet cipher suite
CIPHER_SUITE = Fernet(FERNET_KEY)


def encrypt_data(data: str) -> bytes:
    """Encrypts the given data using a predefined cipher suite."""
    return CIPHER_SUITE.encrypt(data.encode())


def decrypt_data(data: bytes) -> str:
    """Decrypts the given data using a predefined cipher suite."""
    return CIPHER_SUITE.decrypt(data).decode()


def generate_confirmation_token(email: str) -> str:
    """Returns confirmation token generated for validation."""
    serializer = URLSafeTimedSerializer(SECRET_APIKEY)
    return serializer.dumps(email, salt=SECURITY_SALT)


def confirm_token(token: str, expiration: int = 604800) -> str:
    """Returns status of confirmation used for validation (default: 7 days)."""
    try:
        serializer = URLSafeTimedSerializer(SECRET_APIKEY)
        return serializer.loads(token, salt=SECURITY_SALT, max_age=expiration)
    except (SignatureExpired, BadSignature, ValueError):
        return False
