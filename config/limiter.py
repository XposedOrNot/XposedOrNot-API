"""Centralized rate limiter configuration."""

# Define specific rate limits for different types of routes
RATE_LIMIT_HELP = "50 per day;25 per hour"  # For help/documentation routes
RATE_LIMIT_UNBLOCK = "24 per day;2 per hour;2 per second"  # For unblock operations
RATE_LIMIT_BREACHES = "2 per second;5 per hour;100 per day"  # For breach listing
RATE_LIMIT_CHECK_EMAIL = "2 per second;5 per hour;100 per day"  # For email checks
RATE_LIMIT_ANALYTICS = (
    "5 per minute;100 per hour;500 per day"  # For analytics endpoints
)
RATE_LIMIT_DOMAIN = (
    "2 per second;25 per hour;50 per day"  # For domain-related endpoints
)
