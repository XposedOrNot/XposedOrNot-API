"""Teams-specific service functions."""

# Standard library imports
from typing import Dict, Optional

# Third-party imports
import httpx
from fastapi import HTTPException

# Local imports
from models.requests import ChannelSetupRequest
from services.messaging import (
    setup_messaging_channel,
    verify_messaging_channel,
    get_channel_config,
    delete_messaging_channel,
)

# Constants
MAX_CARDS = 10  # Teams' maximum number of cards per message
MAX_CARD_SIZE = 28000  # Teams' maximum card size in bytes


async def setup_teams_channel(channel_data: ChannelSetupRequest) -> bool:
    """Set up a Teams channel for notifications."""
    return await setup_messaging_channel(channel_data, "teams")


async def verify_teams_channel(channel_data: ChannelSetupRequest) -> bool:
    """Verify a Teams channel setup."""
    return await verify_messaging_channel(channel_data, "teams")


async def delete_teams_channel(channel_data: ChannelSetupRequest) -> bool:
    """Delete a Teams channel configuration."""
    return await delete_messaging_channel(channel_data, "teams")


async def get_teams_channel_config(domain: str, token: str) -> Optional[Dict]:
    """Get Teams channel configuration."""
    return await get_channel_config(domain, token, "teams")


async def send_teams_notification(domain: str, data: Dict) -> bool:
    """
    Send a notification to a Teams channel.

    Args:
        domain: The domain to send notification for
        data: The notification data to send

    Returns:
        bool: True if notification was sent successfully
    """
    try:
        config = await get_teams_channel_config(domain, data.get("token", ""))
        if not config:
            raise HTTPException(
                status_code=404, detail=f"Teams channel not found for domain {domain}"
            )

        webhook_url = config.get("webhook_url")
        if not webhook_url:
            raise HTTPException(status_code=400, detail="Webhook URL not configured")

        # Convert data to Teams-specific format if needed
        teams_data = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": data,
                }
            ],
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=teams_data)
            response.raise_for_status()

        return True

    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=500, detail=f"Error sending Teams notification: {str(e)}"
        ) from e
