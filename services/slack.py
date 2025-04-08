"""Slack-specific service functions."""

from typing import Dict, Optional
import httpx
from fastapi import HTTPException
from models.requests import ChannelSetupRequest
from services.messaging import (
    setup_messaging_channel,
    verify_messaging_channel,
    get_channel_config,
    delete_messaging_channel,
)


async def setup_slack_channel(channel_data: ChannelSetupRequest) -> bool:
    """Set up a Slack channel for notifications."""
    return await setup_messaging_channel(channel_data, "slack")


async def verify_slack_channel(channel_data: ChannelSetupRequest) -> bool:
    """Verify a Slack channel setup."""
    return await verify_messaging_channel(channel_data, "slack")


async def delete_slack_channel(channel_data: ChannelSetupRequest) -> bool:
    """Delete a Slack channel configuration."""
    return await delete_messaging_channel(channel_data, "slack")


async def get_slack_channel_config(domain: str, token: str) -> Optional[Dict]:
    """Get Slack channel configuration."""
    return await get_channel_config(domain, token, "slack")


async def send_slack_notification(domain: str, data: Dict) -> bool:
    """
    Send a notification to a Slack channel.

    Args:
        domain: The domain to send notification for
        data: The notification data to send

    Returns:
        bool: True if notification was sent successfully
    """
    try:
        config = await get_slack_channel_config(domain, data.get("token", ""))
        if not config:
            raise HTTPException(
                status_code=404, detail=f"Slack channel not found for domain {domain}"
            )

        webhook_url = config.get("webhook_url")
        if not webhook_url:
            raise HTTPException(status_code=400, detail="Webhook URL not configured")

        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=data)
            response.raise_for_status()

        return True

    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=500, detail=f"Error sending Slack notification: {str(e)}"
        ) from e
