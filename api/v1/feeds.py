"""Feed endpoints for RSS and XON Pulse."""

import json
import logging
from datetime import timedelta
from typing import Dict, List, Optional

from fastapi import APIRouter, Request, Response
from feedgen.feed import FeedGenerator
from google.cloud import datastore
from pydantic import BaseModel
from redis import Redis

from config.settings import REDIS_DB, REDIS_HOST, REDIS_PORT
from models.base import BaseResponse
from services.send_email import send_exception_email
from utils.custom_limiter import custom_rate_limiter
from utils.safe_encoding import escape_rss_content, escape_url_fragment

router = APIRouter()

# Redis client for caching
redis_client = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True
)

# Cache TTL: 12 hours for feeds
FEEDS_CACHE_TTL_HOURS = 12


def get_cached_feed(cache_key: str) -> Optional[str]:
    """Retrieve cached feed from Redis."""
    try:
        return redis_client.get(cache_key)
    except Exception:
        pass
    return None


def cache_feed(
    cache_key: str, content: str, expiry_hours: int = FEEDS_CACHE_TTL_HOURS
) -> None:
    """Cache feed content in Redis."""
    try:
        redis_client.setex(cache_key, timedelta(hours=expiry_hours), content)
    except Exception:
        pass


class PulseNewsItem(BaseModel):
    """Model for individual news item."""

    title: str
    date: str
    summary: str
    url: str


class PulseNewsResponse(BaseResponse):
    """Response model for news feed."""

    data: List[PulseNewsItem]


@router.get("/xon-pulse", response_model=PulseNewsResponse)
@custom_rate_limiter("2 per second;50 per hour;100 per day")
async def get_pulse_data(request: Request):
    """Generate news feed for presenting all data breaches news."""
    try:
        # Check cache first
        cache_key = "feeds:xon-pulse"
        cached_result = get_cached_feed(cache_key)
        if cached_result:
            cached_data = json.loads(cached_result)
            return PulseNewsResponse(**cached_data)

        # Cache miss - fetch from Datastore
        client = datastore.Client()
        query = client.query(kind="xon-pulse")
        results = list(query.fetch())

        data = []
        for entity in results:
            item = PulseNewsItem(
                title=entity.get("title"),
                date=entity.get("date").strftime("%Y-%b-%d"),
                summary=entity.get("description"),
                url=entity.get("url"),
            )
            data.append(item)

        # Cache the response
        response_data = {
            "status": "success",
            "data": [item.model_dump() for item in data],
            "status_code": 200,
        }
        cache_feed(cache_key, json.dumps(response_data))

        return PulseNewsResponse(status="success", data=data, status_code=200)
    except Exception as exc:
        logging.error("Failed to fetch news feed: %s", str(exc))
        await send_exception_email(
            api_route="GET /v1/xon-pulse",
            error_message=str(exc),
            exception_type=type(exc).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params="None",
        )
        return PulseNewsResponse(
            status="error", message="Failed to fetch news feed", status_code=404
        )


@router.get("/rss")
@custom_rate_limiter("2 per second;50 per hour;100 per day")
async def rss_feed(request: Request):
    """Generate RSS feed for presenting all data breaches in XoN."""
    try:
        # Check cache first
        cache_key = "feeds:rss"
        cached_rss = get_cached_feed(cache_key)
        if cached_rss:
            return Response(content=cached_rss, media_type="application/rss+xml")

        # Cache miss - generate RSS feed
        feed_generator = FeedGenerator()
        feed_generator.title("XposedOrNot Data Breaches")
        feed_generator.description("Live updates of uploaded data breaches")
        feed_generator.link(href="https://xposedornot.com/xposed")
        feed_generator.contributor(
            name="Devanand Premkumar", email="deva@xposedornot.com"
        )

        datastore_client = datastore.Client()
        query = datastore_client.query(kind="xon_breaches")
        query_iter = query.fetch()

        for entity in query_iter:
            feed_entry = feed_generator.add_entry()
            entity_key = entity.key
            parts = str(entity_key).split(",")
            entity_key = parts[1][:-2][2:]

            feed_entry.id(entity_key)
            feed_entry.title(entity_key)
            feed_entry.link(
                href="https://xposedornot.com/xposed#" + escape_url_fragment(entity_key)
            )

            description = (
                escape_rss_content(entity["xposure_desc"])
                + ". Exposed data: "
                + escape_rss_content(entity["xposed_data"])
            )
            feed_entry.description(description=description)
            feed_entry.pubDate(entity["timestamp"])
            feed_entry.guid(guid=entity_key, permalink=True)

        rss_content = feed_generator.rss_str()

        # Cache the RSS content (decode bytes to string for Redis)
        cache_feed(
            cache_key,
            (
                rss_content.decode("utf-8")
                if isinstance(rss_content, bytes)
                else rss_content
            ),
        )

        return Response(content=rss_content, media_type="application/rss+xml")

    except Exception as exc:
        logging.error("Feed generation failed: %s", str(exc))
        await send_exception_email(
            api_route="GET /v1/rss",
            error_message=str(exc),
            exception_type=type(exc).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params="None",
        )
        return Response(content="Feed generation failed", status_code=404)
