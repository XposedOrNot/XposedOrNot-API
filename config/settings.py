"""Configuration settings for the application."""

import os
from typing import Optional

# Environment Variables
AUTH_EMAIL: str = os.environ["AUTH_EMAIL"]
AUTHKEY: str = os.environ["AUTHKEY"]
CF_MAGIC: str = os.environ["CF_MAGIC"]
CF_UNBLOCK_MAGIC: str = os.environ["CF_UNBLOCK_MAGIC"]
FERNET_KEY: Optional[str] = os.environ.get("ENCRYPTION_KEY")
PROJECT_ID: Optional[str] = os.environ.get("PROJECT_ID")
SECRET_APIKEY: str = os.environ["SECRET_APIKEY"]
SECURITY_SALT: str = os.environ["SECURITY_SALT"]
TOPIC_ID: Optional[str] = os.environ.get("TOPIC_ID")
WTF_CSRF_SECRET_KEY: str = os.environ["WTF_CSRF_SECRET_KEY"]
XMLAPI_KEY: str = os.environ["XMLAPI_KEY"]
BASE_URL: str = os.environ.get("BASE_URL", "https://api.xposedornot.com")

# Redis Configuration
REDIS_HOST: str = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT: int = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_DB: int = int(os.environ.get("REDIS_DB", "0"))
REDIS_PASSWORD: Optional[str] = os.environ.get("REDIS_PASSWORD")

# Redis URL for rate limiter
REDIS_URL: str = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
if REDIS_PASSWORD:
    REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

# Constants
MAX_EMAIL_LENGTH: int = 254
DEFAULT_TIMEOUT: int = 20

"""API configuration settings."""

# API Configuration
API_TITLE = "XON API"
API_VERSION = "2.0.0"
API_DESCRIPTION = """
The XON API provides comprehensive data breach detection and monitoring services. Use our API to:
* Check if email addresses have been exposed in data breaches
* Monitor domain-level breaches
* Access detailed breach analytics
* Get real-time breach metrics

## Documentation Access

| Interface | Features | Rate Limits |
|-----------|----------|-------------|
| **Swagger UI** - Interactive documentation at `/docs` | • Try out API endpoints directly<br>• View request/response examples<br>• Interactive testing | • 2 requests/second<br>• 50-100/hour<br>• 100-1000/day |
| **OpenAPI JSON** - Raw spec at `/openapi.json` | • Import into other tools<br>• Use for automated testing<br>• Generate client code |  |

> Most endpoints are publicly accessible. Domain-specific endpoints may require authentication.
"""

# Rate Limiting
RATE_LIMIT_DEFAULT = "2 per second;50 per hour;100 per day"
RATE_LIMIT_ANALYTICS = "5 per minute;100 per hour;500 per day"
RATE_LIMIT_DOMAIN = "2 per second;10 per hour;50 per day"

# Security
MAX_EMAIL_LENGTH = 254
MAX_DOMAIN_LENGTH = 253
MAX_TOKEN_LENGTH = 100

# Cache Settings
CACHE_TTL = 3600  # 1 hour
CACHE_MAX_SIZE = 1000

# API Endpoints
API_PREFIX = "/v1"
API_DOCS_URL = "/docs"
API_OPENAPI_URL = "/openapi.json"

# OpenAPI Server Configurations
OPENAPI_SERVERS = [{"url": BASE_URL, "description": "Production server"}]
