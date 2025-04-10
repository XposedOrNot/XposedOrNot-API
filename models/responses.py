"""Response models for the application."""

from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime
from .base import BaseResponse, BaseBreachInfo, BaseMetrics, BaseAnalytics


class AlertMeResponse(BaseResponse):
    """Response model for alert-me endpoint."""

    pass


class VerificationResponse(BaseModel):
    """Response model for verification endpoints."""

    html_content: str


class EmailCheckResponse(BaseModel):
    """Response model for email check endpoint."""

    breaches: List[List[str]] = []
    email: str


class MetricsResponse(BaseMetrics):
    """Response model for metrics endpoint."""

    pass


class DomainVerificationResponse(BaseModel):
    """Response model for domain verification."""

    domainVerification: Optional[str | List[str]]


class DomainExposureResponse(BaseModel):
    """Response model for domain exposure."""

    sendDomains: Dict
    SearchStatus: str


class BreachSummary(BaseModel):
    """Model for breach summary."""

    site: str = ""


class PasteSummary(BaseModel):
    """Model for paste summary."""

    cnt: int = 0
    domain: str = ""
    tmpstmp: str = ""


class BreachEntity(BaseModel):
    """Model for breach entity details."""

    breachID: str
    breachedDate: str
    domain: str
    industry: str
    logo: str
    passwordRisk: str
    searchable: Optional[bool]
    sensitive: Optional[bool]
    verified: Optional[bool]
    exposedData: List[str]
    exposedRecords: int
    exposureDescription: str
    referenceURL: str = ""


class BreachesResponse(BaseResponse):
    """Response model for breaches endpoint."""

    exposedBreaches: Optional[List[BreachEntity]] = None


class BreachAnalyticsResponse(BaseModel):
    """Response model for breach analytics endpoint."""

    BreachMetrics: Optional[Dict] = None
    BreachesSummary: BreachSummary
    ExposedBreaches: Optional[Dict] = None
    ExposedPastes: Optional[Dict] = None
    PasteMetrics: Optional[Dict] = None
    PastesSummary: PasteSummary

    class Config:
        """Pydantic model configuration."""

        validate_by_name = True
        validate_assignment = True


class BreachAnalyticsV2Response(BaseModel):
    """Response model for breach analytics v2 endpoint."""

    AI_Summary: str


class EmptyBreachResponse(BaseModel):
    """Response model for empty breach results."""

    BreachesSummary: BreachSummary
    PastesSummary: PasteSummary


class DomainBreachDetails(BaseModel):
    """Model for domain breach details."""

    domain: str
    breach_pastes: int
    breach_emails: int
    breach_total: int
    breach_count: int
    breach_last_seen: Optional[str] = None


class DomainBreachSummaryResponse(BaseModel):
    """Response model for domain breach summary."""

    sendDomains: Dict[str, Dict[str, List[DomainBreachDetails]]]
    SearchStatus: str


class WebhookConfigResponse(BaseResponse):
    """Response model for webhook configuration."""

    data: Optional[Dict[str, str]] = None


class ChannelConfigResponse(BaseResponse):
    """Response model for channel configuration."""

    data: Optional[Dict[str, str]] = None


class WebhookSetupResponse(BaseResponse):
    """Response model for webhook setup."""

    verify_token: Optional[str] = None


class ChannelSetupResponse(BaseResponse):
    """Response model for channel setup."""

    pass


class DetailedMetricsResponse(BaseMetrics):
    """Response model for detailed metrics."""

    Yearly_Breaches_Count: Dict[int, int]
    Industry_Breaches_Count: Dict[str, int]
    Top_Breaches: List[BaseBreachInfo]
    Recent_Breaches: List[BaseBreachInfo]


class PulseNewsItem(BaseModel):
    """Model for individual news item."""

    title: str
    date: str
    summary: str
    url: str


class PulseNewsResponse(BaseResponse):
    """Response model for news feed."""

    data: List[PulseNewsItem]


class ApiKeyResponse(BaseResponse):
    """Response model for API key operations."""

    api_key: Optional[str] = None


class BreachDetailResponse(BaseModel):
    """Model for detailed breach information."""

    breachID: str
    breachedDate: str
    domain: str
    industry: str
    logo: str
    passwordRisk: str
    searchable: bool
    sensitive: bool
    verified: bool
    exposedData: List[str]
    exposedRecords: int
    exposureDescription: str
    referenceURL: str = ""


class BreachListResponse(BaseModel):
    """Response model for /v1/breaches endpoint."""

    status: str
    message: Optional[str] = None
    exposedBreaches: Optional[List[BreachDetailResponse]] = None


class EmailBreachResponse(BaseModel):
    """Response model for email breach check endpoint."""

    breaches: List[List[str]] = []
    email: str


class EmailBreachErrorResponse(BaseModel):
    """Response model for email breach check error."""

    Error: str
    email: Optional[str] = None


class DomainAlertResponse(BaseModel):
    """Response model for domain alert endpoint."""

    Success: str = "Domain Alert Successful"


class DomainAlertErrorResponse(BaseModel):
    """Error response model for domain alert endpoint."""

    Error: str
    email: Optional[str] = None


class DomainVerifyResponse(BaseModel):
    """Response model for domain verification."""

    status: str = "success"
    dashboard_link: str


class DomainVerifyErrorResponse(BaseModel):
    """Error response model for domain verification."""

    status: str = "error"
    message: str = "Invalid or expired verification token"


class BreachDetails(BaseModel):
    """Model for breach details."""

    email: str
    domain: str
    breach: str


class DetailedBreachInfo(BaseModel):
    """Model for detailed breach information."""

    breached_date: Optional[str] = None
    logo: str = ""
    password_risk: str = ""
    searchable: str = "No"
    xposed_data: str = ""
    xposed_records: Union[int, str] = 0
    xposure_desc: str = ""

    class Config:
        """Pydantic model configuration."""

        json_encoders = {
            datetime: lambda v: v.strftime("%a, %d %b %Y %H:%M:%S GMT") if v else None
        }


class DomainBreachesResponse(BaseModel):
    """Response model for domain breaches endpoint."""

    Yearly_Metrics: Dict[str, int]
    Domain_Summary: Dict[str, int]
    Breach_Summary: Dict[str, int]
    Breaches_Details: List[BreachDetails]
    Top10_Breaches: Dict[str, int]
    Detailed_Breach_Info: Dict[str, DetailedBreachInfo]
    Verified_Domains: List[str]
    Seniority_Summary: Dict[str, int]
    Yearly_Breach_Hierarchy: Dict[str, Any]


class DomainBreachesErrorResponse(BaseModel):
    """Error response model for domain breaches endpoint."""

    Error: str


class ShieldActivationResponse(BaseModel):
    """Response model for shield activation endpoint."""

    Success: str


class ShieldActivationErrorResponse(BaseModel):
    """Error response model for shield activation endpoint."""

    Error: str


class ShieldVerificationResponse(BaseModel):
    """Response model for shield verification endpoint."""

    html_content: str = ""
    status: str = "success"


class ShieldVerificationErrorResponse(BaseModel):
    """Error response model for shield verification endpoint."""

    html_content: str = ""
    status: str = "error"


class DomainBreachDetail(BaseModel):
    """Model for individual domain breach details"""

    domain: str = Field(..., description="Domain that was breached")
    breach_pastes: int = Field(..., description="Number of paste records found")
    breach_emails: int = Field(..., description="Number of unique emails found")
    breach_total: int = Field(..., description="Total number of breach records")
    breach_count: int = Field(..., description="Number of unique breaches")
    breach_last_seen: Optional[str] = Field(
        None, description="Date of the most recent breach (format: DD-Mon-YYYY)"
    )


class DomainBreachSummaryResponse(BaseModel):
    """Response model for domain breach summary endpoint"""

    sendDomains: Dict[str, List[DomainBreachDetail]] = Field(
        ..., description="Dictionary containing list of breach details"
    )
    SearchStatus: str = Field(..., description="Status of the search (Success/Error)")


class AlertResponse(BaseModel):
    status: str
    message: str


class VerificationResponse(BaseModel):
    status: str
    sensitive_breach_details: Optional[str] = None
    BreachMetrics: Optional[Dict] = None


class BreachHierarchyChild(BaseModel):
    """Model for breach hierarchy child items"""

    description: str
    children: List["BreachHierarchyChild"] = []
    tooltip: Optional[str] = None

    def dict(self, *args, **kwargs):
        """Custom dict serialization to exclude null values and handle emoji encoding"""
        d = super().dict(*args, **kwargs)
        # Only include non-null values and properly handle tooltip
        return {
            k: v
            for k, v in d.items()
            if v is not None and k != "tooltip" or k == "tooltip" and v is not None
        }


class BreachHierarchyResponse(BaseModel):
    """Model for breach hierarchy response"""

    description: str
    children: List[BreachHierarchyChild] = []

    def dict(self, *args, **kwargs):
        """Custom dict serialization to exclude null values"""
        d = super().dict(*args, **kwargs)
        return {k: v for k, v in d.items() if v is not None}


# Update forward references for nested models
BreachHierarchyChild.update_forward_refs()


class UnsubscribeResponse(BaseModel):
    """Response model for unsubscribe endpoint."""

    status: str
    message: str


class UnsubscribeVerifyResponse(BaseModel):
    """Response model for unsubscribe verification endpoint."""

    html_content: str
    status: str = "success"


class UnsubscribeVerifyErrorResponse(BaseModel):
    """Error response model for unsubscribe verification endpoint."""

    html_content: str
    status: str = "error"
