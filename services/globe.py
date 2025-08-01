"""Globe visualization service.

This module handles the collection and publishing of IP-based location data
for the globe visualization feature. It captures client IP addresses,
retrieves geolocation information, and publishes the data to a PubSub topic.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, Optional

import httpx
from google.cloud import pubsub_v1

# Initialize PubSub constants
TOPIC_ID = os.environ.get("TOPIC_ID")
PROJECT_ID = os.environ.get("PROJECT_ID")

# Storage for recent requests to prevent duplicates
recent_requests = {}

# Initialize Google Cloud Pub/Sub client
publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(PROJECT_ID, TOPIC_ID)


async def get_geolocation(ip: str) -> Optional[Dict[str, Any]]:
    """Fetch city, latitude, and longitude for the given IP."""
    geolocation_api_url = f"http://ip-api.com/json/{ip}"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(geolocation_api_url, timeout=10.0)
            data = response.json()
            if data["status"] == "success":
                return {
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0),
                }
            return None
    except httpx.HTTPError:
        return None
    except Exception:
        return None


def generate_request_hash(data: Dict[str, Any]) -> str:
    """Generate a hash for deduplication of requests."""
    data_str = json.dumps(data, sort_keys=True)
    return hashlib.md5(data_str.encode()).hexdigest()


async def publish_to_pubsub(data: Dict[str, Any]) -> None:
    """Publish to Google Cloud Pub/Sub with hash-based deduplication."""
    try:
        # Check if PubSub is configured
        if not TOPIC_ID or not PROJECT_ID:
            return

        request_hash = generate_request_hash(data)
        current_time = time.time()

        # Clean up old entries from recent_requests
        for key in list(recent_requests.keys()):
            if current_time - recent_requests[key] > 60:  # 1 minute expiry
                del recent_requests[key]

        # Check if this request hash was already published
        if request_hash in recent_requests:
            return

        # Publish message - note: pubsub client is synchronous but we wrap it in async
        message = json.dumps(data).encode("utf-8")
        publisher.publish(topic_path, message)

        # Store request hash with timestamp
        recent_requests[request_hash] = current_time

    except Exception:
        pass


async def process_request_for_globe(client_ip: str) -> None:
    """Process a request for the globe visualization feature."""
    try:
        if not client_ip:
            return

        geo_data = await get_geolocation(client_ip)
        if not geo_data:
            return

        pubsub_data = {
            "ip": client_ip,
            "city": geo_data["city"],
            "lat": geo_data["lat"],
            "lon": geo_data["lon"],
        }

        await publish_to_pubsub(pubsub_data)

    except Exception:
        pass
