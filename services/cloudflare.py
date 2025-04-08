#!/usr/bin/python
# -*- coding: utf-8 -*-

"""XposedOrNot Cloudflare API module."""

import json
import datetime
import time
import os
import hashlib
from typing import Optional, Dict, Any
import requests
import httpx
import dateutil.parser as dp
from google.cloud import datastore
from fastapi import HTTPException
from pydantic import BaseModel, Field

# Environment variables
AUTH_EMAIL = os.environ["AUTH_EMAIL"]
AUTH_KEY = os.environ["AUTHKEY"]


# Response Models
class CloudflareResponse(BaseModel):
    """Base model for Cloudflare responses."""

    status: str
    message: str
    details: Optional[Dict[str, Any]] = None

    class Config:
        """Configuration for CloudflareResponse model."""

        json_schema_extra = {
            "example": {
                "status": "success",
                "message": "Operation completed successfully",
                "details": {"rule_id": "123456"},
            }
        }


class CloudflareError(BaseModel):
    """Model for Cloudflare error responses."""

    status: str = "error"
    message: str
    error_code: Optional[str] = None

    class Config:
        """Configuration for CloudflareError model."""

        json_schema_extra = {
            "example": {
                "status": "error",
                "message": "Failed to block IP",
                "error_code": "CF_BLOCK_FAILED",
            }
        }


async def update_cf_trans(ip_address: str) -> None:
    """Update the Cloud Firestore transaction with the given IP address."""
    try:
        key = hashlib.sha256(ip_address.encode()).hexdigest()
        datastore_client = datastore.Client()
        task_cnt = datastore.Entity(
            datastore_client.key("xon_cf", key),
            exclude_from_indexes=["insrt_tmpstmp", "cf_data"],
        )
        task_cnt.update(
            {
                "insert_timestamp": datetime.datetime.now(),
                "release_timestamp": "",
                "cf_data": ip_address,
            }
        )
        datastore_client.put(task_cnt)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "status": "error",
                "message": f"Failed to update transaction: {str(e)}",
            },
        ) from e


async def get_isp_from_ip(ip_address: str) -> Optional[str]:
    """Fetch the ISP for a given IP address using the ipinfo.io API."""
    try:
        url = f"https://ipinfo.io/{ip_address}/org"
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10)
            if response.status_code == 200:
                return response.text.strip()
            raise HTTPException(
                status_code=response.status_code,
                detail={
                    "status": "error",
                    "message": f"Failed to fetch ISP info: {response.text}",
                },
            )
    except httpx.HTTPError as e:
        print(f"Error fetching ISP for IP {ip_address}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error fetching ISP for IP {ip_address}: {e}")
        return None


async def block_hour(ip_address: str) -> CloudflareResponse:
    """Block an IP address for one hour using the Cloudflare API."""
    try:
        isp_info = await get_isp_from_ip(ip_address)
        if isp_info and "Cloudflare" in isp_info:
            return CloudflareResponse(
                status="skipped",
                message="IP belongs to Cloudflare, skipping block",
                details={"ip": ip_address},
            )

        url = "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules"
        headers = {
            "X-Auth-Email": AUTH_EMAIL,
            "X-Auth-Key": AUTH_KEY,
            "Content-Type": "application/json",
        }
        payload = {
            "mode": "challenge",
            "configuration": {"target": "ip", "value": ip_address},
            "notes": "Hour block enforced",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload, timeout=20)

            if response.status_code in [200, 201]:
                await update_cf_trans(response.content)
                return CloudflareResponse(
                    status="success",
                    message=f"Successfully blocked IP {ip_address} for one hour",
                    details=response.json(),
                )

            raise HTTPException(
                status_code=response.status_code,
                detail={
                    "status": "error",
                    "message": f"Failed to block IP: {response.text}",
                },
            )

    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=500,
            detail={"status": "error", "message": f"HTTP error blocking IP: {str(e)}"},
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"status": "error", "message": f"Error blocking IP: {str(e)}"},
        ) from e


async def block_day(ip_address: str) -> CloudflareResponse:
    """Block an IP address for one day using the Cloudflare API."""
    try:
        isp_info = await get_isp_from_ip(ip_address)
        if isp_info and "Cloudflare" in isp_info:
            return CloudflareResponse(
                status="skipped",
                message="IP belongs to Cloudflare, skipping block",
                details={"ip": ip_address},
            )

        url = "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules"
        headers = {
            "X-Auth-Email": AUTH_EMAIL,
            "X-Auth-Key": AUTH_KEY,
            "Content-Type": "application/json",
        }
        payload = {
            "mode": "block",
            "configuration": {"target": "ip", "value": ip_address},
            "notes": "Day block enforced",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload, timeout=20)

            if response.status_code in [200, 201]:
                await update_cf_trans(response.content)
                return CloudflareResponse(
                    status="success",
                    message=f"Successfully blocked IP {ip_address} for one day",
                    details=response.json(),
                )

            raise HTTPException(
                status_code=response.status_code,
                detail={
                    "status": "error",
                    "message": f"Failed to block IP: {response.text}",
                },
            )

    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=500,
            detail={"status": "error", "message": f"HTTP error blocking IP: {str(e)}"},
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"status": "error", "message": f"Error blocking IP: {str(e)}"},
        ) from e


async def unblock() -> CloudflareResponse:
    """Unblocks IP addresses that have been blocked for over an hour."""
    try:
        base_url = (
            "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules/"
        )
        headers = {
            "X-Auth-Email": AUTH_EMAIL,
            "X-Auth-Key": AUTH_KEY,
            "Content-Type": "application/json",
        }

        datastore_client = datastore.Client()
        query = datastore_client.query(kind="xon_cf")
        query.add_filter("release_timestamp", "=", "")

        unblocked_count = 0
        async with httpx.AsyncClient() as client:
            for entity in query.fetch():
                config = json.loads(entity["cf_data"])
                firewall_rule_id = config["result"]["id"]
                created = config["result"]["created_on"]
                parsed_created = dp.parse(created)
                created_time_in_seconds = parsed_created.strftime("%s")

                if time.time() - float(created_time_in_seconds) > 3600:
                    url = base_url + firewall_rule_id
                    response = await client.delete(url, headers=headers, timeout=20)

                    if response.status_code != 200:
                        print(
                            f"Failed to delete rule {firewall_rule_id}: {response.text}"
                        )
                        continue

                    entity.update(
                        {"release_timestamp": datetime.datetime.utcnow().isoformat()}
                    )
                    datastore_client.put(entity)
                    unblocked_count += 1

        return CloudflareResponse(
            status="success",
            message="Unblock operation completed",
            details={"unblocked_count": unblocked_count},
        )

    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=500,
            detail={
                "status": "error",
                "message": f"HTTP error during unblock operation: {str(e)}",
            },
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "status": "error",
                "message": f"Error during unblock operation: {str(e)}",
            },
        ) from e
