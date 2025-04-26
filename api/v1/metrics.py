"""Metrics-related API endpoints."""

from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from models.responses import MetricsResponse, DetailedMetricsResponse
from services.analytics import get_detailed_metrics
from utils.helpers import validate_url

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.get("/metrics", response_model=MetricsResponse)
@limiter.limit("5 per minute;50 per hour;100 per day")
async def get_metrics_endpoint(request: Request) -> MetricsResponse:
    """Returns basic metrics about breaches."""
    try:
        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

        metrics = await get_detailed_metrics()
        return MetricsResponse(
            Breaches_Count=metrics["breaches_count"],
            Breaches_Records=metrics["breaches_total_records"],
            Pastes_Count=str(metrics["pastes_count"]),
            Pastes_Records=metrics["pastes_total_records"],
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/metrics/detailed", response_model=DetailedMetricsResponse)
@limiter.limit("500 per day;100 per hour")
async def get_detailed_metrics_endpoint(request: Request) -> DetailedMetricsResponse:
    """Returns detailed summary of data breaches including yearly count, top breaches, and recent breaches."""
    try:
        if not validate_url(request):
            raise HTTPException(status_code=400, detail="Invalid request URL")

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
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/metrics/domain/{domain}", include_in_schema=False)
@limiter.limit("5 per minute;50 per hour;100 per day")
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
        raise HTTPException(status_code=500, detail=str(e)) from e
