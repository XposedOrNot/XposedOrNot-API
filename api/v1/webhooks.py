"""Webhook-related API endpoints."""

from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from models.requests import WebhookSetupRequest
from models.responses import WebhookConfigResponse, WebhookSetupResponse
from services.webhook import (
    setup_webhook,
    verify_webhook,
    delete_webhook,
    get_webhook_config,
)
from utils.helpers import validate_url, validate_variables

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post("/webhook/setup", response_model=WebhookSetupResponse)
@limiter.limit("5 per minute;50 per hour;100 per day")
async def setup_webhook_endpoint(
    request: Request, webhook_data: WebhookSetupRequest
) -> WebhookSetupResponse:
    """Setup webhook for domain notifications."""
    try:
        if not validate_variables(
            [webhook_data.token, webhook_data.domain, webhook_data.webhook]
        ):
            raise HTTPException(status_code=400, detail="Invalid input parameters")

        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        if webhook_data.action == "setup":
            verify_token = await setup_webhook(webhook_data)
            return WebhookSetupResponse(
                status="success",
                message="Webhook setup successful",
                verify_token=verify_token,
            )

        if webhook_data.action == "verify":
            if not webhook_data.verify_token:
                raise HTTPException(
                    status_code=400, detail="Verification token required"
                )

            success = await verify_webhook(webhook_data)
            if not success:
                raise HTTPException(
                    status_code=400, detail="Webhook verification failed"
                )
            return WebhookSetupResponse(
                status="success", message="Webhook verified successfully"
            )

        if webhook_data.action == "delete":
            success = await delete_webhook(webhook_data)
            if not success:
                raise HTTPException(status_code=400, detail="Webhook deletion failed")
            return WebhookSetupResponse(
                status="success", message="Webhook deleted successfully"
            )

        raise HTTPException(status_code=400, detail="Invalid action")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/webhook/config/{domain}", response_model=WebhookConfigResponse)
@limiter.limit("5 per minute;50 per hour;100 per day")
async def get_webhook_config_endpoint(
    request: Request, domain: str, token: str
) -> WebhookConfigResponse:
    """Get webhook configuration for a domain."""
    try:
        if not validate_variables([domain, token]):
            raise HTTPException(status_code=400, detail="Invalid input parameters")

        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        config = await get_webhook_config(domain, token)
        if not config:
            raise HTTPException(
                status_code=404, detail="Webhook configuration not found"
            )

        return WebhookConfigResponse(
            status="success",
            message="Webhook configuration retrieved successfully",
            data=config,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
