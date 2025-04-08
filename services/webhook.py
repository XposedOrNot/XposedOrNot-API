"""Webhook-related service functions."""

import secrets
from typing import Dict, Optional
from google.cloud import datastore
from fastapi import HTTPException
from models.requests import WebhookSetupRequest


async def setup_webhook(webhook_data: WebhookSetupRequest) -> str:
    """Setup webhook for domain notifications."""
    try:
        datastore_client = datastore.Client()
        verify_token = secrets.token_urlsafe(32)

        # Create webhook entity
        webhook_key = datastore_client.key("xon_webhooks", webhook_data.domain)
        webhook_entity = datastore.Entity(key=webhook_key)
        webhook_entity.update(
            {
                "domain": webhook_data.domain,
                "webhook_url": webhook_data.webhook,
                "secret": webhook_data.secret,
                "verify_token": verify_token,
                "verified": False,
                "active": False,
            }
        )

        datastore_client.put(webhook_entity)
        return verify_token

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to setup webhook: {str(e)}",
        ) from e


async def verify_webhook(webhook_data: WebhookSetupRequest) -> bool:
    """Verify webhook for domain notifications."""
    try:
        datastore_client = datastore.Client()
        webhook_key = datastore_client.key("xon_webhooks", webhook_data.domain)
        webhook_entity = datastore_client.get(webhook_key)

        if not webhook_entity:
            return False

        if webhook_entity["verify_token"] != webhook_data.verify_token:
            return False

        webhook_entity["verified"] = True
        webhook_entity["active"] = True
        datastore_client.put(webhook_entity)
        return True

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to verify webhook: {str(e)}",
        ) from e


async def delete_webhook(webhook_data: WebhookSetupRequest) -> bool:
    """Delete webhook for domain notifications."""
    try:
        datastore_client = datastore.Client()
        webhook_key = datastore_client.key("xon_webhooks", webhook_data.domain)
        webhook_entity = datastore_client.get(webhook_key)

        if not webhook_entity:
            return False

        datastore_client.delete(webhook_key)
        return True

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete webhook: {str(e)}",
        ) from e


async def get_webhook_config(domain: str) -> Optional[Dict]:
    """Get webhook configuration for a domain."""
    try:
        datastore_client = datastore.Client()
        webhook_key = datastore_client.key("xon_webhooks", domain)
        webhook_entity = datastore_client.get(webhook_key)

        if not webhook_entity:
            return None

        return {
            "domain": webhook_entity["domain"],
            "webhook_url": webhook_entity["webhook_url"],
            "verified": webhook_entity["verified"],
            "active": webhook_entity["active"],
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get webhook config: {str(e)}",
        ) from e


async def send_webhook_notification(domain: str) -> bool:
    """Send notification to configured webhook."""
    try:
        datastore_client = datastore.Client()
        webhook_key = datastore_client.key("xon_webhooks", domain)
        webhook_entity = datastore_client.get(webhook_key)

        if (
            not webhook_entity
            or not webhook_entity["verified"]
            or not webhook_entity["active"]
        ):
            return False

        # Implement webhook notification logic here
        # This is a placeholder for the actual implementation
        return True

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send webhook notification: {str(e)}",
        ) from e
