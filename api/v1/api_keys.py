"""API key management endpoints."""

import secrets
import datetime
import logging
from typing import Optional
from fastapi import APIRouter, Request
from google.cloud import datastore
from slowapi import Limiter
from slowapi.util import get_remote_address
from models.base import BaseResponse
from utils.validation import validate_variables, validate_url

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


class APIKeyResponse(BaseResponse):
    """Response model for API key operations with status and optional API key."""
    api_key: Optional[str] = None


@router.get("/create-api-key/{token}", response_model=APIKeyResponse)
@limiter.limit("2 per second;10 per hour;50 per day")
async def create_api_key(token: str, request: Request):
    """Generates or renews an API key for a user identified by a provided token."""
    try:
        if not token or not validate_variables([token]) or not validate_url(request):
            return APIKeyResponse(
                status="error", message="Invalid token or URL", status_code=400
            )

        client = datastore.Client()
        query = client.query(kind="xon_domains_session")
        query.add_filter("domain_magic", "=", token)
        user = list(query.fetch())
        if not user:
            return APIKeyResponse(
                status="error", message="Invalid token", status_code=400
            )

        email = user[0].key.name
        api_key = secrets.token_hex(16)
        timestamp = datetime.datetime.utcnow()
        api_key_key = client.key("xon_api_key", email)
        api_key_entity = client.get(api_key_key)

        if api_key_entity:
            api_key_entity.update({"api_key": api_key, "updated_timestamp": timestamp})
        else:
            api_key_entity = datastore.Entity(key=api_key_key)
            api_key_entity.update(
                {
                    "api_key": api_key,
                    "insert_timestamp": timestamp,
                    "updated_timestamp": timestamp,
                }
            )

        client.put(api_key_entity)
        return APIKeyResponse(status="success", api_key=api_key, status_code=200)

    except Exception as exc:
        logging.error("Error creating API key: %s", str(exc))
        return APIKeyResponse(
            status="error",
            message="Unfortunately an error occurred while creating/renewing the API key",
            status_code=500,
        )


@router.get("/get-api-key/{token}", response_model=APIKeyResponse)
@limiter.limit("2 per second;50 per hour;100 per day")
async def get_api_key(token: str, request: Request):
    """Retrieves the existing API key for a user identified by a provided token."""
    try:
        if not token or not validate_variables([token]) or not validate_url(request):
            return APIKeyResponse(
                status="error", message="Invalid token or URL", status_code=400
            )

        client = datastore.Client()
        query = client.query(kind="xon_domains_session")
        query.add_filter("domain_magic", "=", token)
        user = list(query.fetch())
        if not user:
            return APIKeyResponse(
                status="error", message="Invalid token", status_code=400
            )

        email = user[0].key.name
        api_key_key = client.key("xon_api_key", email)
        api_key_entity = client.get(api_key_key)

        if api_key_entity:
            api_key = api_key_entity.get("api_key")
            return APIKeyResponse(status="success", api_key=api_key, status_code=200)
            
        return APIKeyResponse(
            status="error", message="API key not found", status_code=404
        )

    except Exception as exc:
        logging.error("Error retrieving API key: %s", str(exc))
        return APIKeyResponse(
            status="error", message="API key not found", status_code=404
        )
