"""Feed endpoints for RSS and XON Pulse."""

from datetime import datetime
from typing import List
from fastapi import APIRouter, Request, Response
from google.cloud import datastore
from slowapi import Limiter
from slowapi.util import get_remote_address
from feedgen.feed import FeedGenerator
from models.base import BaseResponse
from pydantic import BaseModel

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


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
@limiter.limit("2 per second;100 per hour;1000 per day")
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
    except Exception as e:
        return PulseNewsResponse(
            status="error", message="Failed to fetch news feed", status_code=404
        )


@router.get("/rss")
@limiter.limit("2 per second;50 per hour;100 per day")
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
            feed_entry.link(href="https://xposedornot.com/xposed#" + entity_key)

            description = (
                str(entity["xposure_desc"])
                + ". Exposed data: "
                + str(entity["xposed_data"])
            )
            feed_entry.description(description=description)
            feed_entry.pubDate(entity["timestamp"])
            feed_entry.guid(guid=entity_key, permalink=True)

        rss_content = feed_generator.rss_str()
        return Response(content=rss_content, media_type="application/rss+xml")

    except Exception as e:
        return Response(content="Feed generation failed", status_code=404)
