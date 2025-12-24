"""Metrics-related API endpoints."""

import json
from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from redis import Redis

from config.settings import REDIS_DB, REDIS_HOST, REDIS_PORT
from models.responses import DetailedMetricsResponse, MetricsResponse
from services.analytics import get_detailed_metrics
from services.send_email import send_exception_email
from utils.custom_limiter import custom_rate_limiter
from utils.helpers import validate_url

router = APIRouter()

# Redis client for caching
redis_client = Redis(
    host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True
)

# Cache TTL: 24 hours
METRICS_CACHE_TTL_HOURS = 24


def get_cached_metrics(cache_key: str) -> Optional[Dict]:
    """Retrieve cached metrics from Redis."""
    try:
        cached_data = redis_client.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
    except Exception:
        pass
    return None


def cache_metrics(
    cache_key: str, result: Dict, expiry_hours: int = METRICS_CACHE_TTL_HOURS
) -> None:
    """Cache metrics in Redis."""
    try:
        redis_client.setex(cache_key, timedelta(hours=expiry_hours), json.dumps(result))
    except Exception:
        pass


@router.get("/metrics", response_model=MetricsResponse)
@custom_rate_limiter("5 per minute;50 per hour;100 per day")
async def get_metrics_endpoint(request: Request) -> MetricsResponse:
    """Returns basic metrics about breaches."""
    try:
        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        # Check cache first
        cache_key = "metrics:basic"
        cached_result = get_cached_metrics(cache_key)
        if cached_result:
            return MetricsResponse(**cached_result)

        # Cache miss - fetch from service
        metrics = await get_detailed_metrics()
        response_data = {
            "Breaches_Count": metrics["breaches_count"],
            "Breaches_Records": metrics["breaches_total_records"],
            "Pastes_Count": str(metrics["pastes_count"]),
            "Pastes_Records": metrics["pastes_total_records"],
        }
        cache_metrics(cache_key, response_data)

        return MetricsResponse(**response_data)

    except Exception as e:
        await send_exception_email(
            api_route="GET /v1/metrics",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params="None",
        )
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/metrics/detailed", response_model=DetailedMetricsResponse)
@custom_rate_limiter("500 per day;100 per hour")
async def get_detailed_metrics_endpoint(request: Request) -> DetailedMetricsResponse:
    """
    Returns detailed summary of data breaches including yearly count, top breaches,
    and recent breaches.
    """
    try:
        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        # Check cache first
        cache_key = "metrics:detailed"
        cached_result = get_cached_metrics(cache_key)
        if cached_result:
            return DetailedMetricsResponse(**cached_result)

        # Cache miss - fetch and process
        metrics = await get_detailed_metrics()

        # Process top breaches
        top_breaches = []
        for breach in metrics["top_breaches"]:
            top_breaches.append(
                {
                    "breachid": breach.key.id_or_name,
                    "logo": breach.get("logo"),
                    "description": breach.get("xposure_desc"),
                    "count": breach.get("xposed_records"),
                }
            )

        # Process recent breaches
        recent_breaches = []
        for breach in metrics["recent_breaches"]:
            timestamp = breach.get("timestamp")
            if isinstance(timestamp, datetime):
                formatted_timestamp = timestamp.strftime("%a, %d %b %Y %H:%M:%S GMT")
            else:
                formatted_timestamp = datetime.utcnow().strftime(
                    "%a, %d %b %Y %H:%M:%S GMT"
                )

            recent_breaches.append(
                {
                    "breachid": breach.key.id_or_name,
                    "timestamp": formatted_timestamp,
                    "logo": breach.get("logo"),
                    "description": breach.get("xposure_desc"),
                    "count": breach.get("xposed_records"),
                }
            )

        # Build response and cache it
        response_data = {
            "Breaches_Count": metrics["breaches_count"],
            "Breaches_Records": metrics["breaches_total_records"],
            "Pastes_Count": str(metrics["pastes_count"]),
            "Pastes_Records": metrics["pastes_total_records"],
            "Yearly_Breaches_Count": metrics["yearly_count"],
            "Industry_Breaches_Count": metrics["industry_breaches_count"],
            "Top_Breaches": top_breaches,
            "Recent_Breaches": recent_breaches,
        }
        cache_metrics(cache_key, response_data)

        return DetailedMetricsResponse(
            Breaches_Count=metrics["breaches_count"],
            Breaches_Records=metrics["breaches_total_records"],
            Pastes_Count=str(metrics["pastes_count"]),
            Pastes_Records=metrics["pastes_total_records"],
            Yearly_Breaches_Count=metrics["yearly_count"],
            Industry_Breaches_Count=metrics["industry_breaches_count"],
            Top_Breaches=top_breaches,
            Recent_Breaches=recent_breaches,
        )

    except Exception as e:
        await send_exception_email(
            api_route="GET /v1/metrics/detailed",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params="None",
        )
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/metrics/domain/{domain}", include_in_schema=False)
@custom_rate_limiter("5 per minute;50 per hour;100 per day")
async def get_domain_metrics(request: Request, domain: str) -> JSONResponse:
    """Returns metrics for a specific domain."""
    try:
        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        domain_metrics = {
            "status": "success",
            "message": "Domain metrics retrieved successfully",
            "data": {
                "domain": domain,
                "metrics": {
                    "total_breaches": 0,
                    "total_records": 0,
                    "last_breach": None,
                    "risk_score": 0,
                    "industry_breaches_count": {},
                },
            },
        }

        return JSONResponse(content=domain_metrics)

    except Exception as e:
        await send_exception_email(
            api_route=f"GET /v1/metrics/domain/{domain}",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"domain={domain}",
        )
        raise HTTPException(status_code=500, detail=str(e)) from e
