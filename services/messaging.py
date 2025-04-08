"""Common messaging service functionality."""

from typing import Dict, Optional
from fastapi import HTTPException
from google.cloud import datastore
from models.requests import ChannelSetupRequest


async def setup_messaging_channel(
    channel_data: ChannelSetupRequest, platform: str
) -> bool:
    """
    Set up a messaging channel for a given platform (Slack or Teams).

    Args:
        channel_data: Channel setup data including domain, webhook, and tokens
        platform: The messaging platform ('slack' or 'teams')

    Returns:
        bool: True if setup was successful
    """
    try:
        datastore_client = datastore.Client()
        channel_key = datastore_client.key(
            f"xon_{platform}_channel", f"{channel_data.domain}"
        )
        channel_entity = datastore.Entity(key=channel_key)
        channel_entity.update(
            {
                "domain": channel_data.domain,
                "webhook_url": channel_data.webhook,
                "tokens": channel_data.tokens or {},
                "verified": False,
                "active": False,
            }
        )

        datastore_client.put(channel_entity)
        return True

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error setting up {platform} channel: {str(e)}"
        ) from e


async def verify_messaging_channel(
    channel_data: ChannelSetupRequest, platform: str
) -> bool:
    """
    Verify a messaging channel for a given platform.

    Args:
        channel_data: Channel verification data
        platform: The messaging platform ('slack' or 'teams')

    Returns:
        bool: True if verification was successful
    """
    try:
        datastore_client = datastore.Client()
        channel_key = datastore_client.key(
            f"xon_{platform}_channel", f"{channel_data.domain}"
        )
        channel_entity = datastore_client.get(channel_key)

        if not channel_entity:
            detail = f"{platform.capitalize()} channel not found for domain {channel_data.domain}"
            raise HTTPException(status_code=404, detail=detail)

        channel_entity.update(
            {
                "verified": True,
                "active": True,
            }
        )

        datastore_client.put(channel_entity)
        return True

    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=500, detail=f"Error verifying {platform} channel: {str(e)}"
        ) from e


async def get_channel_config(domain: str, token: str, platform: str) -> Optional[Dict]:
    """
    Get channel configuration for a given platform.

    Args:
        domain: The domain to get configuration for
        token: Authentication token
        platform: The messaging platform ('slack' or 'teams')

    Returns:
        Optional[Dict]: Channel configuration if found
    """
    try:
        datastore_client = datastore.Client()
        channel_key = datastore_client.key(f"xon_{platform}_channel", domain)
        channel_entity = datastore_client.get(channel_key)

        if not channel_entity:
            return None

        if not channel_entity.get("tokens", {}).get(token):
            return None

        return dict(channel_entity)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching {platform} channel config: {str(e)}",
        ) from e


async def delete_messaging_channel(
    channel_data: ChannelSetupRequest, platform: str
) -> bool:
    """
    Delete a messaging channel for a given platform.

    Args:
        channel_data: Channel data for deletion
        platform: The messaging platform ('slack' or 'teams')

    Returns:
        bool: True if deletion was successful
    """
    try:
        datastore_client = datastore.Client()
        channel_key = datastore_client.key(
            f"xon_{platform}_channel", f"{channel_data.domain}"
        )
        datastore_client.delete(channel_key)
        return True

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error deleting {platform} channel: {str(e)}"
        ) from e
