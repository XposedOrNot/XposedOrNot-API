"""Enterprise API key validation endpoint."""

from fastapi import APIRouter, Header, Request
from google.cloud import datastore
from pydantic import BaseModel

from services.send_email import send_exception_email
from utils.custom_limiter import custom_rate_limiter
from utils.validation import validate_token, validate_url


class EnterpriseValidationResponse(BaseModel):
    """Response model for enterprise key validation."""

    valid: bool
    reason: str | None = None


router = APIRouter()


@router.post("/validate-enterprise-key", response_model=EnterpriseValidationResponse)
@custom_rate_limiter("2 per second;25 per hour;50 per day")
async def validate_enterprise_key(
    request: Request,
    x_api_key: str = Header(..., description="Enterprise API key"),
):
    """
    Validates an enterprise API key through multi-step verification.

    Validation Flow:
    1. Input validation (format, URL)
    2. Check plus_api_key table (key exists and active)
    3. Validate product family is Enterprise (via plus_product_tiers)
    4. Verify product is assigned to customer (plus_customers_products)
    5. Confirm customer is active (plus_customers)

    Args:
        request: FastAPI request object
        x_api_key: Enterprise API key from header

    Returns:
        EnterpriseValidationResponse:
            Success: {"valid": true}
            Failure: {"valid": false, "reason": "..."}
    """
    # STEP 1: Enhanced Input Validation
    if not x_api_key or x_api_key.strip() == "":
        return EnterpriseValidationResponse(valid=False, reason="API key is required")

    if not validate_token(x_api_key):
        return EnterpriseValidationResponse(
            valid=False, reason="API key format is invalid"
        )

    if not validate_url(request):
        return EnterpriseValidationResponse(valid=False, reason="Invalid request URL")

    datastore_client = datastore.Client()

    try:
        # STEP 2: Check plus_api_key
        query = datastore_client.query(kind="plus_api_key")
        query.add_filter("api_key", "=", x_api_key)
        api_key_results = list(query.fetch())

        if not api_key_results:
            return EnterpriseValidationResponse(valid=False, reason="API key not found")

        api_key_entity = api_key_results[0]

        if not api_key_entity.get("is_active"):
            return EnterpriseValidationResponse(
                valid=False, reason="API key is not active"
            )

        custid = api_key_entity.get("custid")
        product_id = api_key_entity.get("product_id")

        if not custid:
            return EnterpriseValidationResponse(
                valid=False, reason="Invalid customer ID"
            )

        if not product_id:
            return EnterpriseValidationResponse(
                valid=False, reason="Invalid product ID"
            )

        # STEP 3: Validate Product Family via plus_product_tiers
        # Ensure product_id is an integer for key lookup
        try:
            product_id_int = int(product_id)
        except (ValueError, TypeError):
            return EnterpriseValidationResponse(
                valid=False, reason="Invalid product ID format"
            )

        product_tier_key = datastore_client.key("plus_product_tiers", product_id_int)
        product_tier = datastore_client.get(product_tier_key)

        if not product_tier:
            return EnterpriseValidationResponse(
                valid=False, reason="Product configuration not found"
            )

        product_family = product_tier.get("product")

        if not product_family or "enterprise" not in product_family.lower():
            return EnterpriseValidationResponse(
                valid=False, reason="Product is not an Enterprise tier"
            )

        # STEP 4: Check plus_customers_products
        # Note: custid and product_id are stored as strings in this table
        query = datastore_client.query(kind="plus_customers_products")
        query.add_filter("custid", "=", str(custid))
        query.add_filter("product_id", "=", str(product_id))
        customer_product_results = list(query.fetch())

        if not customer_product_results:
            return EnterpriseValidationResponse(
                valid=False, reason="Product not assigned to customer"
            )

        customer_product = customer_product_results[0]
        if customer_product.get("status") != "Active":
            return EnterpriseValidationResponse(
                valid=False, reason="Product assignment is not active"
            )

        # STEP 5: Check plus_customers
        customer_key = datastore_client.key("plus_customers", custid)
        customer = datastore_client.get(customer_key)

        if not customer:
            return EnterpriseValidationResponse(
                valid=False, reason="Customer not found"
            )

        if not customer.get("is_active"):
            return EnterpriseValidationResponse(
                valid=False, reason="Customer account is not active"
            )

        # STEP 6: Success Response
        return EnterpriseValidationResponse(valid=True)

    except Exception as e:
        await send_exception_email(
            api_route="POST /v1/validate-enterprise-key",
            error_message=str(e),
            exception_type=type(e).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"x_api_key={'provided' if x_api_key else 'not_provided'}",
        )
        return EnterpriseValidationResponse(valid=False, reason="Internal server error")
