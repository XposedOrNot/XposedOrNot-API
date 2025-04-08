"""Teams channel-related API endpoints."""

from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from models.requests import ChannelSetupRequest
from models.responses import ChannelConfigResponse, ChannelSetupResponse
from services.teams import (
    setup_teams_channel,
    verify_teams_channel,
    delete_teams_channel,
    get_teams_channel_config,
)
from utils.helpers import validate_url, validate_variables

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post("/teams/setup", response_model=ChannelSetupResponse)
@limiter.limit("5 per minute;50 per hour;100 per day")
async def setup_teams_channel_endpoint(
    request: Request, channel_data: ChannelSetupRequest
) -> ChannelSetupResponse:
    """Setup Teams channel for domain notifications."""
    try:
        if not validate_variables(
            [channel_data.token, channel_data.domain, channel_data.webhook]
        ):
            raise HTTPException(status_code=400, detail="Invalid input parameters")

        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        if channel_data.action == "setup":
            success = await setup_teams_channel(channel_data)
            if success:
                return ChannelSetupResponse(
                    status="success", message="Teams channel setup successful"
                )
            else:
                raise HTTPException(
                    status_code=400, detail="Teams channel setup failed"
                )
        elif channel_data.action == "verify":
            if not channel_data.verify_token:
                raise HTTPException(
                    status_code=400, detail="Verification token required"
                )

            success = await verify_teams_channel(channel_data)
            if success:
                return ChannelSetupResponse(
                    status="success", message="Teams channel verified successfully"
                )
            else:
                raise HTTPException(
                    status_code=400, detail="Teams channel verification failed"
                )
        elif channel_data.action == "delete":
            success = await delete_teams_channel(channel_data)
            if success:
                return ChannelSetupResponse(
                    status="success", message="Teams channel deleted successfully"
                )
            else:
                raise HTTPException(
                    status_code=400, detail="Teams channel deletion failed"
                )
        else:
            raise HTTPException(status_code=400, detail="Invalid action")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/teams/config/{domain}", response_model=ChannelConfigResponse)
@limiter.limit("5 per minute;50 per hour;100 per day")
async def get_teams_channel_config_endpoint(
    request: Request, domain: str, token: str
) -> ChannelConfigResponse:
    """Get Teams channel configuration for a domain."""
    try:
        if not validate_variables([domain, token]):
            raise HTTPException(status_code=400, detail="Invalid input parameters")

        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        config = await get_teams_channel_config(domain, token)
        if config:
            return ChannelConfigResponse(
                status="success",
                message="Teams channel configuration retrieved successfully",
                data=config,
            )
        else:
            raise HTTPException(
                status_code=404, detail="Teams channel configuration not found"
            )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
