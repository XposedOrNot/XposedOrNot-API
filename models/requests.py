"""Request models for the application."""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr


class WebhookSetupRequest(BaseModel):
    """Request model for webhook setup.

    This model represents the data required to set up, verify, or delete a webhook
    for domain notifications. It includes fields for authentication, domain information,
    and webhook configuration.
    """

    token: str
    domain: str
    webhook: str = Field(alias="webhook_url")
    secret: str
    action: str
    verify_token: Optional[str] = None

    class Config:
        validate_by_name = True
        json_schema_extra = {
            "example": {
                "token": "your_token",
                "domain": "example.com",
                "webhook_url": "https://example.com/webhook",
                "secret": "your_secret",
                "action": "setup",
                "verify_token": "optional_verify_token",
            }
        }

    def is_setup_action(self) -> bool:
        """Check if the request is for setting up a webhook."""
        return self.action == "setup"

    def is_verify_action(self) -> bool:
        """Check if the request is for verifying a webhook."""
        return self.action == "verify"

    def get_action_type(self) -> str:
        """Return the action type."""
        return self.action


class ChannelSetupRequest(BaseModel):
    """Request model for Slack/Teams channel setup.

    This model represents the data required to set up, verify, or delete a Slack/Teams
    channel for domain notifications. It includes fields for authentication, domain
    information, and channel configuration.
    """

    token: str
    domain: str
    webhook: str
    action: str
    verify_token: Optional[str] = None
    tokens: Optional[Dict[str, Any]] = None

    class Config:
        validate_by_name = True
        json_schema_extra = {
            "example": {
                "token": "your_token",
                "domain": "example.com",
                "webhook": "https://example.com/webhook",
                "action": "setup",
                "verify_token": "optional_verify_token",
                "tokens": {"key": "value"},
            }
        }

    def is_setup_action(self) -> bool:
        """Check if the request is for setting up a channel."""
        return self.action == "setup"

    def is_verify_action(self) -> bool:
        """Check if the request is for verifying a channel."""
        return self.action == "verify"

    def get_action_type(self) -> str:
        """Return the action type."""
        return self.action


class EmailVerificationRequest(BaseModel):
    """Request model for email verification.

    This model represents the data required to verify an email address for a domain.
    It includes fields for the email address, domain, and verification token.
    """

    email: EmailStr
    domain: str
    token: str

    class Config:
        validate_by_name = True
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "domain": "example.com",
                "token": "verification_token",
            }
        }

    def get_domain_from_email(self) -> str:
        """Extract domain from email address."""
        return self.email.split("@")[1]

    def is_domain_match(self) -> bool:
        """Check if email domain matches the specified domain."""
        return self.get_domain_from_email() == self.domain


class DomainVerificationRequest(BaseModel):
    """Request model for domain verification.

    This model represents the data required to verify domain ownership through various
    methods (DNS, HTML, or email). It includes fields for the domain, verification type,
    and verification token.
    """

    domain: str
    verification_type: str = Field(
        ..., description="Type of verification: dns, html, or email"
    )
    token: str

    class Config:
        validate_by_name = True
        json_schema_extra = {
            "example": {
                "domain": "example.com",
                "verification_type": "dns",
                "token": "verification_token",
            }
        }

    def is_valid_verification_type(self) -> bool:
        """Check if the verification type is valid."""
        return self.verification_type in ["dns", "html", "email"]

    def is_dns_verification(self) -> bool:
        """Check if the verification type is DNS."""
        return self.verification_type == "dns"


class ApiKeyRequest(BaseModel):
    """Request model for API key operations.

    This model represents the data required for API key operations, including
    authentication token and associated email address.
    """

    token: str
    email: EmailStr

    class Config:
        validate_by_name = True
        json_schema_extra = {
            "example": {"token": "your_token", "email": "user@example.com"}
        }

    def get_domain_from_email(self) -> str:
        """Extract domain from email address."""
        return self.email.split("@")[1]

    def is_valid_email(self) -> bool:
        """Check if the email address is valid."""
        return "@" in self.email and "." in self.email.split("@")[1]
