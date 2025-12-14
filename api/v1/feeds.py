"""Feed endpoints for RSS and XON Pulse."""

import logging
from typing import List
from fastapi import APIRouter, Request, Response
from google.cloud import datastore
from pydantic import BaseModel
from feedgen.feed import FeedGenerator
from models.base import BaseResponse
from services.send_email import send_exception_email
from utils.custom_limiter import custom_rate_limiter
from utils.safe_encoding import escape_rss_content, escape_url_fragment

router = APIRouter()


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
