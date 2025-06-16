"""Slack channel-related API endpoints."""

from fastapi import APIRouter, HTTPException, Request

from utils.custom_limiter import custom_rate_limiter
from models.requests import ChannelSetupRequest
from models.responses import ChannelConfigResponse, ChannelSetupResponse
from services.slack import (
    setup_slack_channel,
    verify_slack_channel,
    delete_slack_channel,
    get_slack_channel_config,
)
from utils.helpers import validate_url, validate_variables

router = APIRouter()


@router.post("/slack/setup", response_model=ChannelSetupResponse)
@custom_rate_limiter("5 per minute;50 per hour;100 per day")
async def setup_slack_channel_endpoint(
    request: Request, channel_data: ChannelSetupRequest
) -> ChannelSetupResponse:
    """Setup Slack channel for domain notifications."""
    try:
        if not validate_variables(
            [channel_data.token, channel_data.domain, channel_data.webhook]
        ):
            raise HTTPException(status_code=400, detail="Invalid input parameters")

        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        if channel_data.action == "setup":
            success = await setup_slack_channel(channel_data)
            if not success:
                raise HTTPException(
                    status_code=400, detail="Slack channel setup failed"
                )
            return ChannelSetupResponse(
                status="success", message="Slack channel setup successful"
            )

        if channel_data.action == "verify":
            if not channel_data.verify_token:
                raise HTTPException(
                    status_code=400, detail="Verification token required"
                )

            success = await verify_slack_channel(channel_data)
            if not success:
                raise HTTPException(
                    status_code=400, detail="Slack channel verification failed"
                )
            return ChannelSetupResponse(
                status="success", message="Slack channel verified successfully"
            )

        if channel_data.action == "delete":
            success = await delete_slack_channel(channel_data)
            if not success:
                raise HTTPException(
                    status_code=400, detail="Slack channel deletion failed"
                )
            return ChannelSetupResponse(
                status="success", message="Slack channel deleted successfully"
            )

        raise HTTPException(status_code=400, detail="Invalid action")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/slack/config/{domain}", response_model=ChannelConfigResponse)
@custom_rate_limiter("5 per minute;50 per hour;100 per day")
async def get_slack_channel_config_endpoint(
    request: Request, domain: str, token: str
) -> ChannelConfigResponse:
    """Get Slack channel configuration for a domain."""
    try:
        if not validate_variables([domain, token]):
            raise HTTPException(status_code=400, detail="Invalid input parameters")

        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        config = await get_slack_channel_config(domain, token)
        if not config:
            raise HTTPException(
                status_code=404, detail="Slack channel configuration not found"
            )

        return ChannelConfigResponse(
            status="success",
            message="Slack channel configuration retrieved successfully",
            data=config,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
