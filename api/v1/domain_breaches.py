"""Domain breaches endpoint for retrieving breach data and metrics."""

from datetime import datetime
from collections import defaultdict
from typing import Dict, List
from operator import itemgetter

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from google.cloud import datastore
from pydantic import BaseModel, Field

from models.base import BaseResponse
from models.responses import DomainBreachesResponse
from utils.custom_limiter import custom_rate_limiter
from utils.validation import validate_url

router = APIRouter()


# CSRF exemption dependency
async def csrf_exempt():
    """Dependency to exempt from CSRF protection."""
    return True


class BreachDetail(BaseModel):
    """Model for detailed breach information."""

    breached_date: datetime
    logo: str
    password_risk: str
    searchable: bool
    xposed_data: List[str] = Field(default_factory=list)
    xposed_records: int
    xposure_desc: str

    @classmethod
    def from_datastore(cls, data: dict) -> "BreachDetail":
        """Create a BreachDetail instance from datastore data."""
        # Convert string xposed_data to list if needed
        if isinstance(data.get("xposed_data"), str):
            data["xposed_data"] = [
                item.strip() for item in data["xposed_data"].split(";")
            ]
        return cls(**data)


class BreachSummary(BaseModel):
    """Model for breach summary information."""

    email: str
    domain: str
    breach: str


class DomainBreachesResponse(BaseResponse):
    """Response model for domain breaches endpoint."""

    metrics: Dict = {
        "Yearly_Metrics": Dict[str, int],
        "Domain_Summary": Dict[str, int],
        "Breach_Summary": Dict[str, int],
        "Breaches_Details": List[BreachSummary],
        "Top10_Breaches": Dict[str, int],
        "Detailed_Breach_Info": Dict[str, Dict],
    }


@router.post(
    "/domain-breaches/",
    response_model=DomainBreachesResponse,
    dependencies=[Depends(csrf_exempt)],
)
@custom_rate_limiter("2 per second;10 per hour;50 per day")
async def protected(
    request: Request,
    x_api_key: str = Header(..., description="API key for authentication"),
):
    """Retrieves the data breaches and related metrics for an API-key"""
    try:
        if not x_api_key or x_api_key.strip() == "" or not validate_url(request):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

        # Instantiate a datastore client
        datastore_client = datastore.Client()

        # Create a query against the kind 'xon_api_key'
        query = datastore_client.query(kind="xon_api_key")
        query.add_filter("api_key", "=", x_api_key)
        results = list(query.fetch())

        if not results:
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

        # If the key is valid, return the associated email
        email = results[0].key.name

        # Additional operations
        query = datastore_client.query(kind="xon_domains")
        query.add_filter("email", "=", email)
        verified_domains = [entity["domain"] for entity in query.fetch()]

        current_year = datetime.utcnow().year
        yearly_summary = defaultdict(int)
        yearly_summary = {str(year): 0 for year in range(2007, current_year + 1)}
        yearly_breach_summary = {
            str(year): defaultdict(int) for year in range(2007, current_year + 1)
        }
        breach_summary = defaultdict(int)
        domain_summary = defaultdict(int)
        detailed_breach_info = {}
        breach_details = []

        for domain in verified_domains:
            query = datastore_client.query(kind="xon_domains_summary")
            query.add_filter("domain", "=", domain)
            domain_summary[domain] = 0

            for entity in query.fetch():
                if entity["breach"] == "No_Breaches":
                    continue

                breach_key = datastore_client.key("xon_breaches", entity["breach"])
                breach = datastore_client.get(breach_key)

                if breach:
                    breach_year = breach["breached_date"].strftime("%Y")
                    yearly_summary[breach_year] += entity["email_count"]
                    yearly_breach_summary[breach_year][entity["breach"]] += entity[
                        "email_count"
                    ]
                    breach_summary[entity["breach"]] += entity["email_count"]
                    domain_summary[domain] += entity["email_count"]

                    detailed_breach_info[entity["breach"]] = {
                        "breached_date": breach["breached_date"],
                        "logo": breach["logo"],
                        "password_risk": breach["password_risk"],
                        "searchable": breach["searchable"],
                        "xposed_data": breach["xposed_data"],
                        "xposed_records": breach["xposed_records"],
                        "xposure_desc": breach["xposure_desc"],
                    }

            query = datastore_client.query(kind="xon_domains_details")
            query.add_filter("domain", "=", domain)
            for entity in query.fetch():
                breach_details.append(
                    BreachSummary(
                        email=entity["email"],
                        domain=entity["domain"],
                        breach=entity["breach"],
                    )
                )

        top10_breaches = dict(
            sorted(breach_summary.items(), key=itemgetter(1), reverse=True)[:10]
        )

        metrics = {
            "Yearly_Metrics": dict(yearly_summary),
            "Domain_Summary": dict(domain_summary),
            "Breach_Summary": dict(breach_summary),
            "Breaches_Details": breach_details,
            "Top10_Breaches": dict(top10_breaches),
            "Detailed_Breach_Info": detailed_breach_info,
        }

        return DomainBreachesResponse(status="success", metrics=metrics)

    except HTTPException:
        raise
    except Exception as exception_details:
        raise HTTPException(
            status_code=500, detail="An error occurred during processing"
        ) from exception_details
