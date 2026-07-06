"""Globe visualization service.

This module handles the collection and publishing of IP-based location data
for the globe visualization feature. It captures client IP addresses, reads
geolocation from Cloudflare visitor-location headers (Managed Transform
"Add visitor location headers"), and publishes the data to a PubSub topic.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, Optional

from google.cloud import pubsub_v1

# Initialize PubSub constants
TOPIC_ID = os.environ.get("TOPIC_ID")
PROJECT_ID = os.environ.get("PROJECT_ID")

# Storage for recent requests to prevent duplicates
recent_requests = {}

# Initialize Google Cloud Pub/Sub client
publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(PROJECT_ID, TOPIC_ID)


_last_missing_geo_log = 0.0  # pylint: disable=invalid-name
_MISSING_GEO_LOG_INTERVAL = 300

_MAX_CITY_LENGTH = 80


def build_geo_from_headers(
    city: Optional[str], lat: Optional[str], lon: Optional[str]
) -> Optional[Dict[str, Any]]:
    """Build geolocation data from Cloudflare visitor-location headers."""
    if not city or not lat or not lon:
        return None
    try:
        return {
            "city": city[:_MAX_CITY_LENGTH],
            "lat": float(lat),
            "lon": float(lon),
        }
    except (TypeError, ValueError):
        return None


def _log_missing_geo_headers() -> None:
    """Log (throttled) when Cloudflare visitor-location headers are absent."""
    global _last_missing_geo_log  # pylint: disable=global-statement
    now = time.time()
    if now - _last_missing_geo_log > _MISSING_GEO_LOG_INTERVAL:
        _last_missing_geo_log = now
        print(
            "[GLOBE] cf visitor-location headers missing or invalid — "
            "check the 'Add visitor location headers' Managed Transform",
            flush=True,
        )


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
        future = publisher.publish(topic_path, message)

        def _log_publish_result(fut):
            try:
                fut.result()
            except Exception as exc:  # pylint: disable=broad-except
                print(
                    f"[GLOBE] publish FAILED ip={data.get('ip')}: "
                    f"{type(exc).__name__}: {exc}",
                    flush=True,
                )

        future.add_done_callback(_log_publish_result)

        # Store request hash with timestamp
        recent_requests[request_hash] = current_time

    except Exception:
        pass


async def process_request_for_globe(
    client_ip: str,
    city: Optional[str] = None,
    lat: Optional[str] = None,
    lon: Optional[str] = None,
) -> None:
    """Process a request for the globe visualization feature."""
    try:
        if not client_ip:
            return

        geo_data = build_geo_from_headers(city, lat, lon)
        if not geo_data:
            _log_missing_geo_headers()
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
