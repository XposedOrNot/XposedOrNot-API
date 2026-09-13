"""Slack channel API endpoints (verified domain owners).

Ownership is proven via ``utils.channel_auth`` (API key or dashboard
session + verified domain). Config retrieval is a POST so session tokens
never appear in URLs or access logs.
"""

from fastapi import APIRouter, HTTPException, Request

from models.channels import (
    ChannelConfigRequest,
    ChannelConfigResponse,
    ChannelSetupRequest,
    ChannelSetupResponse,
)
from services.send_email import send_exception_email
from services.slack import (
    delete_slack_channel,
    get_slack_channel_config,
    setup_slack_channel,
    verify_slack_channel,
)
from utils.channel_auth import resolve_domain_owner, verify_domain_ownership
from utils.custom_limiter import custom_rate_limiter
from utils.helpers import validate_domain
from utils.validation import validate_url

router = APIRouter()

RATE_LIMIT_CHANNEL_SETUP = "5 per second;100 per hour;500 per day"
RATE_LIMIT_CHANNEL_CONFIG = "10 per second;100 per hour"


@router.post("/slack/setup", response_model=ChannelSetupResponse)
@custom_rate_limiter(RATE_LIMIT_CHANNEL_SETUP)
async def setup_slack_channel_endpoint(
    request: Request, channel_data: ChannelSetupRequest
) -> ChannelSetupResponse:
    """Set up, verify or delete the Slack channel of a verified domain."""
    try:
        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        domain = (channel_data.domain or "").strip().lower()
        if not validate_domain(domain):
            raise HTTPException(status_code=400, detail="Invalid domain")
        channel_data.domain = domain

        email = await resolve_domain_owner(
            request, channel_data.email, channel_data.token
        )

        if not await verify_domain_ownership(email, domain):
            raise HTTPException(
                status_code=403,
                detail="Domain must be verified before setting up notification channels",
            )

        if channel_data.action == "setup":
            if not channel_data.webhook:
                raise HTTPException(status_code=400, detail="Webhook URL required")
            success, _ = await setup_slack_channel(channel_data, email)
            if not success:
                raise HTTPException(
                    status_code=400, detail="Slack channel setup failed"
                )
            return ChannelSetupResponse(
                status="success",
                message=(
                    "Verification code sent to your Slack channel. Please check "
                    "the channel and submit the code with action=verify to complete "
                    "verification."
                ),
            )

        if channel_data.action == "verify":
            if not channel_data.verify_token:
                raise HTTPException(
                    status_code=400, detail="Verification token required"
                )
            success = await verify_slack_channel(channel_data, email)
            if not success:
                raise HTTPException(
                    status_code=400, detail="Slack channel verification failed"
                )
            return ChannelSetupResponse(
                status="success", message="Slack channel verified successfully"
            )

        if channel_data.action == "delete":
            success = await delete_slack_channel(channel_data, email)
            if not success:
                raise HTTPException(
                    status_code=400, detail="Slack channel deletion failed"
                )
            return ChannelSetupResponse(
                status="success", message="Slack channel deleted successfully"
            )

        raise HTTPException(status_code=400, detail="Invalid action")

    except HTTPException:
        raise
    except Exception as exc:  # pylint: disable=broad-except
        await send_exception_email(
            api_route="POST /v1/slack/setup",
            error_message=str(exc),
            exception_type=type(exc).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"domain={channel_data.domain}, action={channel_data.action}",
        )
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@router.post("/slack/config", response_model=ChannelConfigResponse)
@custom_rate_limiter(RATE_LIMIT_CHANNEL_CONFIG)
async def get_slack_channel_config_endpoint(
    request: Request, config_data: ChannelConfigRequest
) -> ChannelConfigResponse:
    """Get the Slack channel configuration for a verified domain."""
    try:
        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        domain = (config_data.domain or "").strip().lower()
        if not validate_domain(domain):
            raise HTTPException(status_code=400, detail="Invalid domain")

        owner = await resolve_domain_owner(
            request, config_data.email, config_data.token
        )
        if not await verify_domain_ownership(owner, domain):
            raise HTTPException(
                status_code=403,
                detail="User is not authorized to access this domain's configuration.",
            )

        config = await get_slack_channel_config(domain, owner)
        if not config:
            raise HTTPException(status_code=404, detail="Configuration not found")

        return ChannelConfigResponse(
            status="success", message="Configuration retrieved successfully", **config
        )
    except HTTPException:
        raise
    except Exception as exc:  # pylint: disable=broad-except
        await send_exception_email(
            api_route="POST /v1/slack/config",
            error_message=str(exc),
            exception_type=type(exc).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"domain={config_data.domain}",
        )
        raise HTTPException(status_code=500, detail="Internal server error") from exc
