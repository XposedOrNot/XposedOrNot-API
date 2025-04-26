"""Main XON-API entry point."""

# Standard library imports
from typing import List

# Third-party imports
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# Local imports - Config
from config.middleware import (
    setup_middleware,
    setup_security_headers,
    setup_rate_limiter,
)
from config.settings import (
    API_VERSION,
    API_TITLE,
    API_DESCRIPTION,
    CF_UNBLOCK_MAGIC,
)

# Local imports - API Routers
from api.v1 import (
    alert,
    analytics,
    api_keys,
    breaches,
    domain_breaches,
    domain_verification,
    feeds,
    metrics,
    slack,
    teams,
    webhooks,
)

# Local imports - Services
from services.cloudflare import unblock

# Local imports - Models
from models.responses import AlertResponse

# Initialize FastAPI app
app = FastAPI(
    title=API_TITLE,
    description=API_DESCRIPTION,
    version=API_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json",
    openapi_tags=[
        {
            "name": "breaches",
            "description": "Core breach detection and monitoring endpoints",
        },
        {"name": "analytics", "description": "Advanced breach analysis and statistics"},
        {"name": "metrics", "description": "System-wide and breach-specific metrics"},
    ],
)

# Setup middleware and security
setup_middleware(app)
setup_security_headers(app)
limiter = setup_rate_limiter(app)

# Add rate limiter exception handler
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Include routers with include_in_schema=False for routes we don't want in docs
app.include_router(
    breaches.router, prefix="/v1", tags=["breaches"], include_in_schema=False
)
app.include_router(
    analytics.router, prefix="/v1", tags=["analytics"], include_in_schema=False
)
app.include_router(metrics.router, prefix="/v1", tags=["metrics"])
app.include_router(
    webhooks.router, prefix="/v1", tags=["webhooks"], include_in_schema=False
)
app.include_router(slack.router, prefix="/v1", tags=["slack"], include_in_schema=False)
app.include_router(teams.router, prefix="/v1", tags=["teams"], include_in_schema=False)
app.include_router(
    alert.router,
    prefix="/v1",
    tags=["alert"],
    include_in_schema=False,
    responses={
        "200": {"model": AlertResponse},
        "404": {"model": AlertResponse},
        "500": {"model": AlertResponse},
    },
)
app.include_router(
    api_keys.router, prefix="/v1", tags=["api_keys"], include_in_schema=False
)
app.include_router(feeds.router, prefix="/v1", tags=["feeds"], include_in_schema=False)
app.include_router(
    domain_verification.router,
    prefix="/v1",
    tags=["domain_verification"],
    include_in_schema=False,
)
app.include_router(
    domain_breaches.router,
    prefix="/v1",
    tags=["domain_breaches"],
    include_in_schema=False,
)


@app.get("/", include_in_schema=False)
async def index():
    """Returns default landing page"""
    return HTMLResponse(content=open("templates/index.html", encoding="utf-8").read())


@app.get("/v1/help/", include_in_schema=False)
@limiter.limit("500 per day;100 per hour")
async def helper(request: Request):  # pylint: disable=unused-argument
    """
    Provides basic guidance to the API documentation page.
    Returns an HTML response with the documentation landing page.
    """
    return HTMLResponse(content=open("templates/index.html", encoding="utf-8").read())


@app.get("/robots.txt", include_in_schema=False)
@limiter.limit("500 per day;100 per hour")
async def serve_robots_txt(request: Request):  # pylint: disable=unused-argument
    """Returns robots.txt file content."""
    return HTMLResponse(content=open("static/robots.txt", encoding="utf-8").read())


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html(request: Request):
    """Custom Swagger UI endpoint with enhanced styling."""
    swagger_js_url = "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui-bundle.min.js"
    swagger_css_url = (
        "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui.min.css"
    )

    return templates.TemplateResponse(
        "swagger/custom_swagger.html",
        {
            "request": request,
            "openapi_url": "/openapi.json",
            "title": f"{API_TITLE} - API Documentation",
            "swagger_js_url": swagger_js_url,
            "swagger_css_url": swagger_css_url,
        },
    )


@app.get("/openapi.json", include_in_schema=False)
async def get_openapi_json():
    """Custom OpenAPI JSON endpoint."""
    return get_openapi(
        title=API_TITLE,
        version=API_VERSION,
        description=API_DESCRIPTION,
        routes=app.routes,
    )


@app.get("/v1/unblock_cf/{token}", include_in_schema=False)
@limiter.limit("24 per day;2 per hour;2 per second")
async def unblock_cloudflare(
    token: str, request: Request
):  # pylint: disable=unused-argument
    """
    Returns status of unblock done at Cloudflare.
    Args:
        token: Authentication token for the unblock operation
        request: FastAPI request object (used by rate limiter)
    """
    try:
        if not token or token != CF_UNBLOCK_MAGIC:
            raise HTTPException(status_code=404, detail="Not found")

        result = await unblock()
        return result

    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


def custom_openapi():
    """
    Generate custom OpenAPI schema for the API documentation.

    Returns:
        dict: The customized OpenAPI schema.
    """
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=API_DESCRIPTION,
        routes=app.routes,
    )

    openapi_schema["openapi"] = "3.0.0"

    # Remove the components/schemas section
    if "components" in openapi_schema:
        del openapi_schema["components"]

    if "paths" in openapi_schema:
        # Filter out utility routes
        paths_to_keep = {
            path: methods
            for path, methods in openapi_schema["paths"].items()
            if not any(
                route in path
                for route in [
                    "/",
                    "/v1/help",
                    "/robots.txt",
                    "/docs",
                    "/openapi.json",
                    "/v1/unblock_cf",
                ]
            )
        }
        openapi_schema["paths"] = paths_to_keep

        for path in openapi_schema["paths"].values():
            for method in path.values():
                if "parameters" in method:
                    method["parameters"] = [
                        param
                        for param in method["parameters"]
                        if not (
                            isinstance(param, dict)
                            and "schema" in param
                            and "$ref" in param["schema"]
                        )
                    ]
                # Remove operationId and function name from all methods
                if "operationId" in method:
                    del method["operationId"]
                if "x-function-name" in method:
                    del method["x-function-name"]

    if "paths" not in openapi_schema:
        openapi_schema["paths"] = {}

    # Add the paths with actual supported features
    openapi_schema["paths"]["/v1/breaches"] = {
        "get": {
            "summary": "Get List Of Breaches",
            "description": (
                "Retrieves a list of all known data breaches in the system. "
                "This endpoint provides information about each breach including "
                "its name, title, breach date, and when it was added to the system."
            ),
            "tags": ["breaches"],
            "parameters": [
                {
                    "name": "domain",
                    "in": "query",
                    "description": "Filter breaches by domain",
                    "required": False,
                    "schema": {"type": "string"},
                },
                {
                    "name": "breach_id",
                    "in": "query",
                    "description": "Get specific breach by ID",
                    "required": False,
                    "schema": {"type": "string"},
                },
                {
                    "name": "if-modified-since",
                    "in": "header",
                    "description": "Return 304 if no changes since this date",
                    "required": False,
                    "schema": {"type": "string", "format": "date-time"},
                },
            ],
            "responses": {
                "200": {
                    "description": "Successfully retrieved list of breaches",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "status": {
                                        "type": "string",
                                        "description": "Response status",
                                    },
                                    "exposedBreaches": {
                                        "type": "array",
                                        "description": "List of breach objects",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "breachID": {
                                                    "type": "string",
                                                    "description": "Unique identifier for the breach",
                                                },
                                                "breachedDate": {
                                                    "type": "string",
                                                    "description": "Date when the breach occurred",
                                                },
                                                "domain": {
                                                    "type": "string",
                                                    "description": "Domain associated with the breach",
                                                },
                                                "industry": {
                                                    "type": "string",
                                                    "description": "Industry of the breached organization",
                                                },
                                                "logo": {
                                                    "type": "string",
                                                    "description": "URL to organization logo",
                                                },
                                                "passwordRisk": {
                                                    "type": "string",
                                                    "description": "Password risk level",
                                                },
                                                "searchable": {
                                                    "type": "boolean",
                                                    "description": "Whether the breach is searchable",
                                                },
                                                "sensitive": {
                                                    "type": "boolean",
                                                    "description": "Whether the breach contains sensitive data",
                                                },
                                                "verified": {
                                                    "type": "boolean",
                                                    "description": "Whether the breach has been verified",
                                                },
                                                "exposedData": {
                                                    "type": "array",
                                                    "items": {"type": "string"},
                                                    "description": "Types of data exposed in the breach",
                                                },
                                                "exposedRecords": {
                                                    "type": "integer",
                                                    "description": "Number of records affected",
                                                },
                                                "exposureDescription": {
                                                    "type": "string",
                                                    "description": "Detailed description of the breach",
                                                },
                                                "referenceURL": {
                                                    "type": "string",
                                                    "description": "URL to breach reference",
                                                },
                                            },
                                        },
                                    },
                                },
                            }
                        }
                    },
                },
                "304": {
                    "description": "Not Modified - No changes since the specified date"
                },
                "404": {
                    "description": "Not Found - No breaches found for the provided criteria"
                },
            },
        }
    }

    openapi_schema["paths"]["/v1/check-email/{email}"] = {
        "get": {
            "summary": "Check Email For Breaches",
            "description": (
                "Searches for any data breaches containing the specified email "
                "address. This endpoint provides information about breaches where "
                "the email was found."
            ),
            "tags": ["breaches"],
            "parameters": [
                {
                    "required": True,
                    "schema": {"type": "string", "format": "email"},
                    "name": "email",
                    "in": "path",
                    "description": "Email address to check for breaches",
                },
                {
                    "name": "include_details",
                    "in": "query",
                    "description": (
                        "Include detailed breach information in the response"
                    ),
                    "required": False,
                    "schema": {"type": "boolean", "default": False},
                },
            ],
            "responses": {
                "200": {
                    "description": (
                        "Successfully retrieved breach information for the email"
                    ),
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "breaches": {
                                        "type": "array",
                                        "description": (
                                            "List of breaches containing the email"
                                        ),
                                        "items": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                        },
                                    },
                                    "email": {
                                        "type": "string",
                                        "description": (
                                            "Email address that was checked"
                                        ),
                                    },
                                },
                            }
                        }
                    },
                },
                "404": {
                    "description": "Not Found - Email not found or invalid format",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "Error": {"type": "string"},
                                    "email": {"type": "string"},
                                },
                            }
                        }
                    },
                },
            },
        }
    }

    openapi_schema["paths"]["/v1/breach-analytics"] = {
        "get": {
            "summary": "Get Breach Analytics",
            "description": (
                "Retrieves analytics and statistics about breaches for a specific "
                "email address. This endpoint provides information about breaches "
                "and associated paste data."
            ),
            "tags": ["analytics"],
            "parameters": [
                {
                    "required": True,
                    "schema": {"type": "string", "format": "email"},
                    "name": "email",
                    "in": "query",
                    "description": "Email address to get analytics for",
                },
                {
                    "name": "token",
                    "in": "query",
                    "description": "Token for accessing sensitive data",
                    "required": False,
                    "schema": {"type": "string"},
                },
            ],
            "responses": {
                "200": {
                    "description": "Successfully retrieved breach analytics",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "ExposedBreaches": {
                                        "type": "array",
                                        "description": "List of breaches containing the email",
                                        "items": {"type": "object"},
                                    },
                                    "BreachesSummary": {
                                        "type": "object",
                                        "description": "Summary of breaches",
                                    },
                                    "BreachMetrics": {
                                        "type": "object",
                                        "description": "Metrics about breaches",
                                    },
                                    "PastesSummary": {
                                        "type": "object",
                                        "description": "Summary of pastes",
                                    },
                                    "ExposedPastes": {
                                        "type": "array",
                                        "description": "List of pastes containing the email",
                                        "items": {"type": "object"},
                                    },
                                    "PasteMetrics": {
                                        "type": "object",
                                        "description": "Metrics about pastes",
                                    },
                                },
                            }
                        }
                    },
                },
                "404": {"description": "Not Found - Email not found or invalid format"},
            },
        }
    }

    openapi_schema["paths"]["/v1/domain-breaches"] = {
        "post": {
            "summary": "Get Domain Breaches",
            "description": (
                "Retrieves information about data breaches associated with verified domains for an API key. "
                "This endpoint provides detailed metrics and statistics about breaches affecting the domains."
            ),
            "tags": ["domain_breaches"],
            "parameters": [
                {
                    "required": True,
                    "schema": {"type": "string"},
                    "name": "x-api-key",
                    "in": "header",
                    "description": "API key for authentication",
                }
            ],
            "responses": {
                "200": {
                    "description": "Successfully retrieved domain breaches",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "status": {
                                        "type": "string",
                                        "description": "Response status",
                                    },
                                    "metrics": {
                                        "type": "object",
                                        "description": "Detailed metrics about domain breaches",
                                        "properties": {
                                            "Yearly_Metrics": {
                                                "type": "object",
                                                "description": "Breach counts by year",
                                            },
                                            "Domain_Summary": {
                                                "type": "object",
                                                "description": "Summary of breaches by domain",
                                            },
                                            "Breach_Summary": {
                                                "type": "object",
                                                "description": "Summary of all breaches",
                                            },
                                            "Breaches_Details": {
                                                "type": "array",
                                                "description": "Detailed information about each breach",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "email": {"type": "string"},
                                                        "domain": {"type": "string"},
                                                        "breach": {"type": "string"},
                                                    },
                                                },
                                            },
                                            "Top10_Breaches": {
                                                "type": "object",
                                                "description": "Top 10 largest breaches",
                                            },
                                            "Detailed_Breach_Info": {
                                                "type": "object",
                                                "description": "Detailed information about each breach",
                                            },
                                        },
                                    },
                                },
                            }
                        }
                    },
                },
                "401": {"description": "Unauthorized - Invalid or missing API key"},
                "500": {
                    "description": "Internal Server Error - An error occurred during processing"
                },
            },
        }
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

if __name__ == "__main__":
    import uvicorn

    print("Connected and ready to serve the world!")
    uvicorn.run(app, host="0.0.0.0", port=1806)  # nosec B104
