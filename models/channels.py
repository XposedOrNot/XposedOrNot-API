"""Request/response models for notification channels (Slack, Teams, webhook).

Channels are account-wide (one per platform per verified owner), so requests
carry no domain. Authentication fields (`email` + `token` for a dashboard
session) are optional because an `x-api-key` header is an equally valid way
to prove ownership. Config retrieval is a POST with a request body so
session tokens never appear in URLs or access logs.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field

from models.base import BaseResponse


class ChannelSetupRequest(BaseModel):
    """Request model for channel setup operations."""

    action: str = Field(
        ...,
        description="Action to perform: setup / verify / delete "
        "(webhook channel also accepts rotate_secret)",
    )
    webhook: Optional[str] = Field(
        None,
        description="Webhook URL for the channel (required for setup; stored encrypted)",
    )
    verify_token: Optional[str] = Field(
        None, description="Verification code delivered to the channel (verify action)"
    )
    custom_headers: Optional[Dict[str, str]] = Field(
        None,
        description="Optional custom HTTP headers sent on webhook delivery "
        "(generic webhook channel only)",
    )
    email: Optional[EmailStr] = Field(
        None, description="Domain owner email (dashboard session auth)"
    )
    token: Optional[str] = Field(
        None, description="Dashboard session token (dashboard session auth)"
    )


class ChannelConfigRequest(BaseModel):
    """Request model for channel configuration retrieval."""

    email: Optional[EmailStr] = Field(
        None, description="Domain owner email (dashboard session auth)"
    )
    token: Optional[str] = Field(
        None, description="Dashboard session token (dashboard session auth)"
    )


class ChannelSetupResponse(BaseResponse):
    """Response model for channel setup operations."""


class ChannelConfigResponse(BaseResponse):
    """Response model for Slack/Teams channel configuration retrieval."""

    email: Optional[str] = Field(None, description="Domain owner email")
    created_by: Optional[str] = Field(
        None, description="Email of user who created the channel"
    )
    webhook: Optional[str] = Field(None, description="Webhook URL (decrypted)")
    verified: Optional[bool] = Field(None, description="Whether channel is verified")
    active: Optional[bool] = Field(None, description="Whether channel is active")
    created_at: Optional[str] = Field(None, description="Creation timestamp")
    updated_at: Optional[str] = Field(None, description="Last update timestamp")
    verified_at: Optional[str] = Field(None, description="Verification timestamp")


class WebhookSetupResponse(BaseResponse):
    """Response model for generic webhook channel setup operations."""

    signing_secret: Optional[str] = Field(
        None,
        description="HMAC signing secret; returned ONCE on setup/rotation only",
    )


class WebhookConfigResponse(BaseResponse):
    """Response model for generic webhook channel configuration retrieval."""

    email: Optional[str] = Field(None, description="Domain owner email")
    scope: Optional[str] = Field(None, description="Channel scope (always 'owner')")
    created_by: Optional[str] = Field(
        None, description="Email of user who created the channel"
    )
    webhook: Optional[str] = Field(None, description="Webhook URL (decrypted)")
    verified: Optional[bool] = Field(None, description="Whether channel is verified")
    active: Optional[bool] = Field(None, description="Whether channel is active")
    signing_secret_set: Optional[bool] = Field(
        None, description="Whether a signing secret is provisioned (value redacted)"
    )
    custom_header_keys: Optional[List[str]] = Field(
        None, description="Names of configured custom headers (values redacted)"
    )
    consecutive_failures: Optional[int] = Field(
        None, description="Consecutive delivery failures recorded by the sender"
    )
    last_verification_error: Optional[str] = Field(
        None, description="Last verification/delivery error, if any"
    )
    created_at: Optional[str] = Field(None, description="Creation timestamp")
    updated_at: Optional[str] = Field(None, description="Last update timestamp")
    verified_at: Optional[str] = Field(None, description="Verification timestamp")
    secret_rotated_at: Optional[str] = Field(
        None, description="Timestamp of the last signing-secret rotation"
    )
    disabled_at: Optional[str] = Field(
        None, description="When the sender auto-disabled the channel, if ever"
    )
