"""Generic (custom) webhook channel API endpoints (verified domain owners).

Channels are account-wide: one webhook channel per owner, receiving alerts
for every domain the owner has verified. Ownership is proven via
``utils.channel_auth`` (API key or dashboard session + at least one verified
domain). Config retrieval is a POST so session tokens never appear in URLs
or access logs.
"""

from fastapi import APIRouter, HTTPException, Request

from models.channels import (
    ChannelConfigRequest,
    ChannelSetupRequest,
    WebhookConfigResponse,
    WebhookSetupResponse,
)
from services.send_email import send_exception_email
from services.webhook import (
    delete_webhook_channel,
    get_webhook_channel_config,
    rotate_webhook_secret,
    setup_webhook_channel,
    verify_webhook_channel,
)
from utils.channel_auth import owns_any_verified_domain, resolve_domain_owner
from utils.custom_limiter import custom_rate_limiter
from utils.validation import validate_url

router = APIRouter()

RATE_LIMIT_CHANNEL_SETUP = "5 per second;100 per hour;500 per day"
RATE_LIMIT_CHANNEL_CONFIG = "10 per second;100 per hour"


@router.post(
    "/webhook/setup",
    response_model=WebhookSetupResponse,
    response_model_exclude_none=True,
)
@custom_rate_limiter(RATE_LIMIT_CHANNEL_SETUP)
async def setup_webhook_channel_endpoint(
    request: Request, channel_data: ChannelSetupRequest
) -> WebhookSetupResponse:
    """Set up, verify, rotate the secret of, or delete the owner's webhook channel."""
    try:
        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        email = await resolve_domain_owner(
            request, channel_data.email, channel_data.token
        )

        if not await owns_any_verified_domain(email):
            raise HTTPException(
                status_code=403,
                detail=(
                    "At least one verified domain is required before setting "
                    "up notification channels"
                ),
            )

        if channel_data.action == "setup":
            if not channel_data.webhook:
                raise HTTPException(status_code=400, detail="Webhook URL required")
            success, signing_secret = await setup_webhook_channel(channel_data, email)
            if not success:
                raise HTTPException(
                    status_code=400, detail="Webhook channel setup failed"
                )
            if signing_secret:
                return WebhookSetupResponse(
                    status="success",
                    message=(
                        "Verification payload sent to your webhook endpoint. Store "
                        "the signing_secret now; it is shown only once and is used "
                        "to verify the HMAC signature on delivered notifications. "
                        "Submit the verification_code with action=verify to finish."
                    ),
                    signing_secret=signing_secret,
                )
            return WebhookSetupResponse(
                status="success",
                message=(
                    "Webhook channel updated. If the destination URL changed, a new "
                    "verification payload was sent; submit the verification_code "
                    "with action=verify to re-activate."
                ),
            )

        if channel_data.action == "verify":
            if not channel_data.verify_token:
                raise HTTPException(
                    status_code=400, detail="Verification token required"
                )
            success = await verify_webhook_channel(channel_data, email)
            if not success:
                raise HTTPException(
                    status_code=400, detail="Webhook channel verification failed"
                )
            return WebhookSetupResponse(
                status="success", message="Webhook channel verified successfully"
            )

        if channel_data.action == "rotate_secret":
            new_secret = await rotate_webhook_secret(email)
            return WebhookSetupResponse(
                status="success",
                message=(
                    "Signing secret rotated. Store the new signing_secret now; it "
                    "is shown only once. The previous secret stays valid during the "
                    "rotation grace window to allow a zero-downtime cutover."
                ),
                signing_secret=new_secret,
            )

        if channel_data.action == "delete":
            success = await delete_webhook_channel(email)
            if not success:
                raise HTTPException(
                    status_code=400, detail="Webhook channel deletion failed"
                )
            return WebhookSetupResponse(
                status="success", message="Webhook channel deleted successfully"
            )

        raise HTTPException(status_code=400, detail="Invalid action")

    except HTTPException:
        raise
    except Exception as exc:  # pylint: disable=broad-except
        await send_exception_email(
            api_route="POST /v1/webhook/setup",
            error_message=str(exc),
            exception_type=type(exc).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"action={channel_data.action}",
        )
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@router.post(
    "/webhook/config",
    response_model=WebhookConfigResponse,
    response_model_exclude_none=True,
)
@custom_rate_limiter(RATE_LIMIT_CHANNEL_CONFIG)
async def get_webhook_channel_config_endpoint(
    request: Request, config_data: ChannelConfigRequest
) -> WebhookConfigResponse:
    """Get the owner's webhook channel configuration (secret and header values masked)."""
    try:
        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        owner = await resolve_domain_owner(
            request, config_data.email, config_data.token
        )
        if not await owns_any_verified_domain(owner):
            raise HTTPException(
                status_code=403,
                detail="User is not authorized to access this configuration.",
            )

        config = await get_webhook_channel_config(owner)
        if not config:
            raise HTTPException(status_code=404, detail="Configuration not found")

        return WebhookConfigResponse(
            status="success", message="Configuration retrieved successfully", **config
        )
    except HTTPException:
        raise
    except Exception as exc:  # pylint: disable=broad-except
        await send_exception_email(
            api_route="POST /v1/webhook/config",
            error_message=str(exc),
            exception_type=type(exc).__name__,
            user_agent=request.headers.get("User-Agent"),
        )
        raise HTTPException(status_code=500, detail="Internal server error") from exc
