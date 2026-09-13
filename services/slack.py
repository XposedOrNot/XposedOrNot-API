"""Slack channel service: onboarding wrappers plus the alert sender.

The onboarding functions are thin wrappers over ``services.messaging``.
``send_slack_alert`` posts a Block Kit breach message to the owner's
verified Slack channel.
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


async def setup_slack_channel(
    channel_data: ChannelSetupRequest, email: str
) -> Tuple[bool, str]:
    """Set up a Slack channel for notifications."""
    return await setup_messaging_channel(channel_data, "slack", email)


async def verify_slack_channel(channel_data: ChannelSetupRequest, email: str) -> bool:
    """Verify a Slack channel setup."""
    return await verify_messaging_channel(channel_data, "slack", email)


async def delete_slack_channel(email: str) -> bool:
    """Delete a Slack channel configuration."""
    return await delete_messaging_channel("slack", email)


async def get_slack_channel_config(email: str) -> Optional[Dict]:
    """Get Slack channel configuration (webhook decrypted)."""
    return await get_channel_config(email, "slack")


def build_slack_breach_message(
    domain: str,
    breach_name: str,
    breach_date: str,
    exposed_records: int,
    exposed_data: List[str],
    affected_emails: int,
    dashboard_url: Optional[str] = None,
) -> Dict:
    """Block Kit message for one new breach affecting ``domain``."""
    fields = [
        {"type": "mrkdwn", "text": f"*Breach:*\n{breach_name}"},
        {"type": "mrkdwn", "text": f"*Breach date:*\n{breach_date}"},
        {"type": "mrkdwn", "text": f"*Records exposed:*\n{exposed_records:,}"},
        {"type": "mrkdwn", "text": f"*Your domain's emails:*\n{affected_emails:,}"},
    ]
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 New data breach affecting {domain}",
                "emoji": True,
            },
        },
        {"type": "section", "fields": fields},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Exposed data:* " + (", ".join(exposed_data) or "n/a"),
            },
        },
    ]
    if dashboard_url:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"<{dashboard_url}|Open the {SERVICE_NAME} domain dashboard>",
                },
            }
        )
    blocks.append(
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Sent by {SERVICE_NAME} data breach alerts"}
            ],
        }
    )
    return {"blocks": blocks}


async def send_slack_alert(domain: str, email: str, message: Dict) -> bool:
    """Post ``message`` (a Block Kit payload) to the owner's verified Slack channel.

    Returns False (never raises) when the channel is missing, unverified,
    inactive, or Slack rejects the post, so a sender loop can continue.

    ``domain`` identifies the breach being announced; the channel itself is
    account-wide and looked up by ``email``.
    """
    config = await get_slack_channel_config(email)
    if not config or not config.get("active") or not config.get("verified"):
        logger.info(f"No active Slack channel for owner={email}; skipping {domain}")
        return False
    webhook_url = config.get("webhook")
    if not webhook_url:
        logger.warning(f"Slack channel for owner={email} has no usable webhook URL")
        return False
    try:
        async with shared_http_client() as client:
            response = await client.post(webhook_url, json=message)
            response.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        logger.error(f"Error sending Slack alert for {domain}: {exc}")
        return False
