"""Main XON-API entry point."""

# Third-party imports
import asyncio
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Local imports - Config
from config.middleware import (
    setup_middleware,
    setup_security_headers,
)
from config.settings import (
    API_VERSION,
    API_TITLE,
    API_DESCRIPTION,
    CF_UNBLOCK_MAGIC,
    OPENAPI_SERVERS,
)
from config.limiter import (
    RATE_LIMIT_HELP,
    RATE_LIMIT_UNBLOCK,
)

# Local imports - API Routers
from api.v1 import (
    alert,
    analytics,
    api_keys,
    breaches,
    domain_breaches,
    domain_phishing,
    domain_seniority,
    domain_verification,
    enterprise_validation,
    feeds,
    metrics,
    monthly_digest,
)

# Local imports - Services
from services.cloudflare import unblock

# Local imports - Models
from models.responses import AlertResponse

# Local imports - Utils
from utils.custom_limiter import custom_rate_limiter, redis_pool
from utils.scan_protection import handle_404_with_protection

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


# MCP Integration - Manual endpoint approach
@app.get("/mcp")
async def mcp_get_handler():
    """Handle MCP GET requests - return server info."""
    return {
        "jsonrpc": "2.0",
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "XON_MCP", "version": "1.0.0"},
        },
    }


@app.post("/mcp")
async def mcp_post_handler(fastapi_request: Request):
    """Handle MCP protocol requests manually."""
    # Get the JSON body from the request
    request_body = await fastapi_request.json()

    if request_body.get("method") == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_body.get("id"),
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "XON_MCP", "version": "1.0.0"},
            },
        }
    elif request_body.get("method") == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_body.get("id"),
            "result": {
                "tools": [
                    {
                        "name": "check_email_breaches",
                        "description": (
                            "Check if an email address appears in any known data breaches"
                        ),
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "email": {
                                    "type": "string",
                                    "description": "Email address to check for breaches",
                                }
                            },
                            "required": ["email"],
                        },
                    },
                    {
                        "name": "get_breach_analytics",
                        "description": (
                            "Get detailed analytics and statistics about breaches "
                            "for a specific email address"
                        ),
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "email": {
                                    "type": "string",
                                    "description": "Email address to get analytics for",
                                },
                                "token": {
                                    "type": "string",
                                    "description": "Optional token for accessing sensitive data",
                                    "default": "",
                                },
                            },
                            "required": ["email"],
                        },
                    },
                    {
                        "name": "list_breaches",
                        "description": "Get a list of all known data breaches in the system",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "domain": {
                                    "type": "string",
                                    "description": "Optional domain to filter breaches",
                                },
                                "breach_id": {
                                    "type": "string",
                                    "description": "Optional specific breach ID to get",
                                },
                            },
                            "required": [],
                        },
                    },
                ]
            },
        }
    elif request_body.get("method") == "tools/call":
        tool_name = request_body.get("params", {}).get("name")
        tool_args = request_body.get("params", {}).get("arguments", {})

        if tool_name == "check_email_breaches":
            email = tool_args.get("email")
            if email:
                try:
                    base_url = (
                        f"{fastapi_request.url.scheme}://{fastapi_request.url.netloc}"
                    )

                    response = httpx.get(
                        f"{base_url}/v1/check-email/{email}",
                        follow_redirects=True,
                        timeout=30.0,
                    )
                    response.raise_for_status()
                    result = response.json()

                    return {
                        "jsonrpc": "2.0",
                        "id": request_body.get("id"),
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"Breach check results for {email}: {result}",
                                }
                            ]
                        },
                    }
                except Exception as e:
                    print(f"MCP check_email_breach error: {e}")
                    return {
                        "jsonrpc": "2.0",
                        "id": request_body.get("id"),
                        "error": {
                            "code": -32603,
                            "message": "Internal error: Failed to check email breach",
                        },
                    }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_body.get("id"),
                    "error": {"code": -32602, "message": "Missing email parameter"},
                }

        elif tool_name == "get_breach_analytics":
            email = tool_args.get("email")
            token = tool_args.get("token", "")
            if email:
                try:
                    base_url = (
                        f"{fastapi_request.url.scheme}://{fastapi_request.url.netloc}"
                    )

                    params = {"email": email}
                    if token:
                        params["token"] = token

                    response = httpx.get(
                        f"{base_url}/v1/breach-analytics",
                        params=params,
                        follow_redirects=True,
                        timeout=30.0,
                    )
                    response.raise_for_status()
                    result = response.json()

                    return {
                        "jsonrpc": "2.0",
                        "id": request_body.get("id"),
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"Breach analytics for {email}: {result}",
                                }
                            ]
                        },
                    }
                except Exception as e:
                    return {
                        "jsonrpc": "2.0",
                        "id": request_body.get("id"),
                        "error": {
                            "code": -32603,
                            "message": f"Internal error: {str(e)}",
                        },
                    }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_body.get("id"),
                    "error": {"code": -32602, "message": "Missing email parameter"},
                }

        elif tool_name == "list_breaches":
            try:
                base_url = (
                    f"{fastapi_request.url.scheme}://{fastapi_request.url.netloc}"
                )

                params = {}
                if tool_args.get("domain"):
                    params["domain"] = tool_args.get("domain")
                if tool_args.get("breach_id"):
                    params["breach_id"] = tool_args.get("breach_id")

                response = httpx.get(
                    f"{base_url}/v1/breaches",
                    params=params if params else None,
                    follow_redirects=True,
                    timeout=30.0,
                )
                response.raise_for_status()
                result = response.json()

                return {
                    "jsonrpc": "2.0",
                    "id": request_body.get("id"),
                    "result": {
                        "content": [{"type": "text", "text": f"Breach list: {result}"}]
                    },
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": request_body.get("id"),
                    "error": {"code": -32603, "message": f"Internal error: {str(e)}"},
                }

    # Default response for unsupported methods
    return {
        "jsonrpc": "2.0",
        "id": request_body.get("id"),
        "error": {"code": -32601, "message": "Method not found"},
    }


app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.include_router(
    breaches.router, prefix="/v1", tags=["breaches"], include_in_schema=False
)
app.include_router(
    analytics.router, prefix="/v1", tags=["analytics"], include_in_schema=False
)
app.include_router(metrics.router, prefix="/v1", tags=["metrics"])
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
app.include_router(
    enterprise_validation.router,
    prefix="/v1",
    tags=["enterprise_validation"],
    include_in_schema=False,
)
app.include_router(
    domain_phishing.router,
    prefix="/v1",
    tags=["domain_phishing"],
    include_in_schema=False,
)
app.include_router(
    domain_seniority.router,
    prefix="/v1",
    tags=["domain_seniority"],
    include_in_schema=False,
)
app.include_router(
    monthly_digest.router,
    prefix="/v1",
    tags=["monthly_digest"],
    include_in_schema=True,
)


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    # Scheduler disabled - using Google Cloud Scheduler + manual trigger instead
    # import os
    # if os.environ.get("DISABLE_SCHEDULER", "false").lower() != "true":
    #     start_scheduler()
    # else:
    #     print("Scheduler disabled via DISABLE_SCHEDULER environment variable")
    print("Scheduler disabled - using external Google Cloud Scheduler")


@app.get("/", include_in_schema=False)
async def index():
    """Returns default landing page."""
    return HTMLResponse(content=open("templates/index.html", encoding="utf-8").read())


@app.get("/v1/help/", include_in_schema=False)
@custom_rate_limiter(RATE_LIMIT_HELP)
async def helper(request: Request):  # pylint: disable=unused-argument
    """
    Provides basic guidance to the API documentation page.
    Returns an HTML response with the documentation landing page.
    """
    return HTMLResponse(content=open("templates/index.html", encoding="utf-8").read())


@app.get("/robots.txt", include_in_schema=False)
async def serve_robots_txt(request: Request):  # pylint: disable=unused-argument
    """Returns robots.txt file content."""
    return HTMLResponse(content=open("static/robots.txt", encoding="utf-8").read())


@app.get("/.well-known/security.txt", include_in_schema=False)
async def serve_security_txt(request: Request):  # pylint: disable=unused-argument
    """Returns security.txt file content."""
    return PlainTextResponse(
        content=open("static/.well-known/security.txt", encoding="utf-8").read()
    )


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html(request: Request):
    """Custom Swagger UI endpoint with enhanced styling."""
    swagger_js_url = (
        "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/"
        "swagger-ui-bundle.min.js"
    )
    swagger_css_url = (
        "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/" "swagger-ui.min.css"
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
@custom_rate_limiter(RATE_LIMIT_UNBLOCK)
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

    # Add server configurations
    openapi_schema["servers"] = OPENAPI_SERVERS

    if "components" in openapi_schema:
        del openapi_schema["components"]

    if "paths" in openapi_schema:

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

                if "operationId" in method:
                    del method["operationId"]
                if "x-function-name" in method:
                    del method["x-function-name"]

    if "paths" not in openapi_schema:
        openapi_schema["paths"] = {}

    openapi_schema["paths"]["/v1/breaches"] = {
        "get": {
            "operationId": "getBreaches",
            "summary": "Get List Of Breaches",
            "description": (
                "Retrieves a list of all known data breaches in the system. "
                "This endpoint provides information about each breach including "
                "its name, title, breach date, and when it was added to the "
                "system."
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
                    "description": ("Return 304 if no changes since this date"),
                    "required": False,
                    "schema": {"type": "string", "format": "date-time"},
                },
            ],
            "responses": {
                "200": {
                    "description": ("Successfully retrieved list of breaches"),
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
                                        "description": ("List of breach objects"),
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "breachID": {
                                                    "type": "string",
                                                    "description": (
                                                        "Unique identifier for the "
                                                        "breach"
                                                    ),
                                                },
                                                "breachedDate": {
                                                    "type": "string",
                                                    "description": (
                                                        "Date when the breach "
                                                        "occurred"
                                                    ),
                                                },
                                                "domain": {
                                                    "type": "string",
                                                    "description": (
                                                        "Domain associated with the "
                                                        "breach"
                                                    ),
                                                },
                                                "industry": {
                                                    "type": "string",
                                                    "description": (
                                                        "Industry of the breached "
                                                        "organization"
                                                    ),
                                                },
                                                "logo": {
                                                    "type": "string",
                                                    "description": (
                                                        "URL to organization logo"
                                                    ),
                                                },
                                                "passwordRisk": {
                                                    "type": "string",
                                                    "description": (
                                                        "Password risk level"
                                                    ),
                                                },
                                                "searchable": {
                                                    "type": "boolean",
                                                    "description": (
                                                        "Whether the breach is "
                                                        "searchable"
                                                    ),
                                                },
                                                "sensitive": {
                                                    "type": "boolean",
                                                    "description": (
                                                        "Whether the breach contains "
                                                        "sensitive data"
                                                    ),
                                                },
                                                "verified": {
                                                    "type": "boolean",
                                                    "description": (
                                                        "Whether the breach has been "
                                                        "verified"
                                                    ),
                                                },
                                                "exposedData": {
                                                    "type": "array",
                                                    "items": {"type": "string"},
                                                    "description": (
                                                        "Types of data exposed in "
                                                        "the breach"
                                                    ),
                                                },
                                                "exposedRecords": {
                                                    "type": "integer",
                                                    "description": (
                                                        "Number of records affected"
                                                    ),
                                                },
                                                "exposureDescription": {
                                                    "type": "string",
                                                    "description": (
                                                        "Detailed description of the "
                                                        "breach"
                                                    ),
                                                },
                                                "referenceURL": {
                                                    "type": "string",
                                                    "description": (
                                                        "URL to breach reference"
                                                    ),
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
                "304": {
                    "description": (
                        "Not Modified - No changes since the specified date"
                    )
                },
                "404": {
                    "description": (
                        "Not Found - No breaches found for the provided criteria"
                    )
                },
            },
        }
    }

    openapi_schema["paths"]["/v1/check-email/{email}"] = {
        "get": {
            "operationId": "checkEmailBreaches",
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
                    "description": ("Email address to check for breaches"),
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
                    "description": ("Not Found - Email not found or invalid format"),
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
            "operationId": "getBreachAnalytics",
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
                    "description": ("Email address to get analytics for"),
                },
                {
                    "name": "token",
                    "in": "query",
                    "description": ("Token for accessing sensitive data"),
                    "required": False,
                    "schema": {"type": "string"},
                },
            ],
            "responses": {
                "200": {
                    "description": ("Successfully retrieved breach analytics"),
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "ExposedBreaches": {
                                        "type": "array",
                                        "description": (
                                            "List of breaches containing the email"
                                        ),
                                        "items": {"type": "object"},
                                    },
                                    "BreachesSummary": {
                                        "type": "object",
                                        "description": ("Summary of breaches"),
                                    },
                                    "BreachMetrics": {
                                        "type": "object",
                                        "description": ("Metrics about breaches"),
                                    },
                                    "PastesSummary": {
                                        "type": "object",
                                        "description": ("Summary of pastes"),
                                    },
                                    "ExposedPastes": {
                                        "type": "array",
                                        "description": (
                                            "List of pastes containing the email"
                                        ),
                                        "items": {"type": "object"},
                                    },
                                    "PasteMetrics": {
                                        "type": "object",
                                        "description": ("Metrics about pastes"),
                                    },
                                },
                            }
                        }
                    },
                },
                "404": {
                    "description": ("Not Found - Email not found or invalid format")
                },
            },
        }
    }

    openapi_schema["paths"]["/v1/domain-breaches"] = {
        "post": {
            "operationId": "getDomainBreaches",
            "summary": "Get Domain Breaches",
            "description": (
                "Retrieves information about data breaches associated with "
                "verified domains for an API key. This endpoint provides "
                "detailed metrics and statistics about breaches affecting the "
                "domains."
            ),
            "tags": ["domain_breaches"],
            "parameters": [
                {
                    "required": True,
                    "schema": {"type": "string"},
                    "name": "x-api-key",
                    "in": "header",
                    "description": ("API key for authentication"),
                }
            ],
            "responses": {
                "200": {
                    "description": ("Successfully retrieved domain breaches"),
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "status": {
                                        "type": "string",
                                        "description": ("Response status"),
                                    },
                                    "metrics": {
                                        "type": "object",
                                        "description": (
                                            "Detailed metrics about domain " "breaches"
                                        ),
                                        "properties": {
                                            "Yearly_Metrics": {
                                                "type": "object",
                                                "description": (
                                                    "Breach counts by year"
                                                ),
                                            },
                                            "Domain_Summary": {
                                                "type": "object",
                                                "description": (
                                                    "Summary of breaches by domain"
                                                ),
                                            },
                                            "Breach_Summary": {
                                                "type": "object",
                                                "description": (
                                                    "Summary of all breaches"
                                                ),
                                            },
                                            "Breaches_Details": {
                                                "type": "array",
                                                "description": (
                                                    "Detailed information about "
                                                    "each breach"
                                                ),
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
                                                "description": (
                                                    "Top 10 largest breaches"
                                                ),
                                            },
                                            "Detailed_Breach_Info": {
                                                "type": "object",
                                                "description": (
                                                    "Detailed information about "
                                                    "each breach"
                                                ),
                                            },
                                        },
                                    },
                                },
                            }
                        }
                    },
                },
                "401": {"description": ("Unauthorized - Invalid or missing API key")},
                "500": {
                    "description": (
                        "Internal Server Error - An error occurred during " "processing"
                    )
                },
            },
        }
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Add custom 404 handler for scanning protection
@app.exception_handler(404)
async def custom_404_handler(request: Request, exc: HTTPException):
    """Custom 404 handler with scanning protection."""
    return await handle_404_with_protection(request, exc)


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup resources on application shutdown."""
    try:

        await asyncio.wait_for(redis_pool.close(), timeout=5.0)
        print("Redis connection pool closed successfully")
    except asyncio.TimeoutError:
        print("Redis connection pool close timed out during shutdown")
    except asyncio.CancelledError:
        print("Redis connection pool close was cancelled during shutdown")
    except Exception as e:
        print(f"Error closing Redis connection pool: {e}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=1806)  # nosec B104
