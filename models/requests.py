"""Request models for the application."""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr


class EmailVerificationRequest(BaseModel):
    """Request model for email verification.

    This model represents the data required to verify an email address for a domain.
    It includes fields for the email address, domain, and verification token.
    """

    email: EmailStr
    domain: str
    token: str

    class Config:  # pylint: disable=too-few-public-methods
        """Configuration class for EmailVerificationRequest.

        Defines validation settings and provides example data for API documentation.
        """

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

    class Config:  # pylint: disable=too-few-public-methods
        """Configuration class for DomainVerificationRequest.

        Defines validation settings and provides example data for API documentation.
        """

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
        """Configuration class for ApiKeyRequest.

        Defines validation settings and provides example data for API documentation.
        """

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
