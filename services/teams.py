"""Microsoft Teams channel service: onboarding wrappers plus the alert sender.

The onboarding functions are thin wrappers over ``services.messaging``.
``send_teams_alert`` posts an Adaptive Card to the owner's verified Teams
channel, wrapped in the ``message``/``attachments`` envelope Teams and
Power Automate expect.
"""

import logging
from typing import Dict, List, Optional, Tuple

import httpx

from models.channels import ChannelSetupRequest
from services.messaging import (
    SERVICE_NAME,
    delete_messaging_channel,
    get_channel_config,
    setup_messaging_channel,
    verify_messaging_channel,
)
from utils.http_client import shared_http_client

logger = logging.getLogger(__name__)


async def setup_teams_channel(
    channel_data: ChannelSetupRequest, email: str
) -> Tuple[bool, str]:
    """Set up a Teams channel for notifications."""
    return await setup_messaging_channel(channel_data, "teams", email)


async def verify_teams_channel(channel_data: ChannelSetupRequest, email: str) -> bool:
    """Verify a Teams channel setup."""
    return await verify_messaging_channel(channel_data, "teams", email)


async def delete_teams_channel(channel_data: ChannelSetupRequest, email: str) -> bool:
    """Delete a Teams channel configuration."""
    return await delete_messaging_channel(channel_data, "teams", email)


async def get_teams_channel_config(domain: str, email: str) -> Optional[Dict]:
    """Get Teams channel configuration (webhook decrypted)."""
    return await get_channel_config(domain, email, "teams")


def build_teams_breach_card(
    domain: str,
    breach_name: str,
    breach_date: str,
    exposed_records: int,
    exposed_data: List[str],
    affected_emails: int,
    dashboard_url: Optional[str] = None,
) -> Dict:
    """Adaptive Card body for one new breach affecting ``domain``.

    Pass the result to ``send_teams_alert``, which wraps it in the
    ``message`` / ``attachments`` envelope Teams and Power Automate expect.
    """
    card: Dict = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {
                "type": "TextBlock",
                "size": "Large",
                "weight": "Bolder",
                "text": f"🚨 New data breach affecting {domain}",
                "wrap": True,
            },
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Breach", "value": breach_name},
                    {"title": "Breach date", "value": breach_date},
                    {"title": "Records exposed", "value": f"{exposed_records:,}"},
                    {"title": "Your domain's emails", "value": f"{affected_emails:,}"},
                    {
                        "title": "Exposed data",
                        "value": ", ".join(exposed_data) or "n/a",
                    },
                ],
            },
            {
                "type": "TextBlock",
                "size": "Small",
                "isSubtle": True,
                "text": f"Sent by {SERVICE_NAME} data breach alerts",
                "wrap": True,
            },
        ],
    }
    if dashboard_url:
        card["actions"] = [
            {
                "type": "Action.OpenUrl",
                "title": f"Open the {SERVICE_NAME} domain dashboard",
                "url": dashboard_url,
            }
        ]
    return card


async def send_teams_alert(domain: str, email: str, card: Dict) -> bool:
    """Post an Adaptive Card to the owner's verified Teams channel.

    Returns False (never raises) when the channel is missing, unverified,
    inactive, or Teams rejects the post, so a sender loop can continue.
    """
    config = await get_teams_channel_config(domain, email)
    if not config or not config.get("active") or not config.get("verified"):
        logger.info(f"No active Teams channel for {domain}; skipping")
        return False
    webhook_url = config.get("webhook")
    if not webhook_url:
        logger.warning(f"Teams channel for {domain} has no usable webhook URL")
        return False

    teams_data = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card,
            }
        ],
    }
    try:
        async with shared_http_client() as client:
            response = await client.post(webhook_url, json=teams_data)
            response.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        logger.error(f"Error sending Teams alert for {domain}: {exc}")
        return False
