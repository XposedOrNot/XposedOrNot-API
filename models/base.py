"""Base models and utilities for the application."""

from typing import Optional
from pydantic import BaseModel


class BaseResponse(BaseModel):
    """Base response model with common fields."""

    status: str
    message: Optional[str] = None


class ErrorResponse(BaseModel):
    """Standard error response model."""

    status: str = "error"
    message: str


class BaseBreachInfo(BaseModel):
    """Base model for breach information."""

    breachid: str
    logo: Optional[str] = None
    description: Optional[str] = None
    count: int


class BaseMetrics(BaseModel):
    """Base model for metrics information."""

    Breaches_Count: int
    Breaches_Records: int
    Pastes_Count: str
    Pastes_Records: int


class BaseAnalytics(BaseModel):
    """Base model for analytics information."""

    total_breaches: int
    total_records: int
    first_breach: str
    last_breach: str
