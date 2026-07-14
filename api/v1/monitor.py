"""Monitor-on-behalf (My Circle) API endpoints."""

# Standard library imports
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, Union
import asyncio
import logging

# Third-party imports
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.templating import Jinja2Templates
from google.api_core import exceptions as google_exceptions
from google.cloud import datastore

# Local imports
from config.clients import ds_client
from config.settings import BASE_URL
from models.requests import MonitorRequest
from models.responses import (
    MonitorErrorResponse,
    MonitorItem,
    MonitorListErrorResponse,
    MonitorListResponse,
    MonitorManagement,
    MonitorResponse,
)
from services.analytics import get_breaches_analytics
from services.breach import get_breaches, get_exposure
from services.send_email import (
    send_exception_email,
    send_monitor_accepted,
    send_monitor_invite,
    send_monitor_requester_notice,
)
from utils.custom_limiter import (
    custom_rate_limiter,
    get_healthy_redis_connection,
    is_rate_limited,
    parse_rate_limit,
)
from utils.helpers import get_location_from_headers, get_preferred_ip_address
from utils.token import (
    confirm_monitor_token,
    generate_monitor_token,
    validate_dashboard_session,
)
from utils.validation import (
    validate_email_deliverable,
    validate_email_with_tld,
    validate_token,
    validate_url,
    validate_variables,
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger(__name__)

MONITOR_ENABLED = True
MAX_MONITORS_PER_USER = 25
MONITOR_INVITE_LIMIT = parse_rate_limit("1 per hour;2 per day")
REJECT_COOLDOWN_DAYS = 30
CONSENT_TOKEN_EXPIRY = 7 * 86400
WITHDRAW_TOKEN_EXPIRY = 365 * 86400
DASHBOARD_URL = "https://xposedornot.com/my-dashboard"
MONITOR_REMINDER_SCHEDULE_DAYS = {0: 2, 1: 6}
MONITOR_MAX_REMINDERS = 2

STATUS_PENDING = "pending"
STATUS_ACCEPTED = "accepted"
STATUS_REJECTED = "rejected"
STATUS_REVOKED = "revoked"

MONITOR_EXCLUDED_FIELDS = [
    "insert_timestamp",
    "verify_timestamp",
    "recent_timestamp",
    "responded_at",
    "verified",
    "unSubscribeOn",
    "shieldOn",
    "shield_timestamp",
    "reminder_eligible",
    "reminder_count",
    "last_reminder_at",
    "token",
    "unsub_token",
]


def _edge_key_name(requester_email: str, target_email: str) -> str:
    """Build the composite key name for a monitor edge."""
    return f"{requester_email}|{target_email}"


def _parse_edge_payload(payload: str) -> Tuple[Optional[str], Optional[str]]:
    """Split a signed token payload back into (requester_email, target_email)."""
    if not payload:
        return None, None
    parts = payload.split("|")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None, None
    return parts[0], parts[1]


def _iso(value: Optional[datetime]) -> Optional[str]:
    """Return a timezone-aware ISO string for a datetime, or None."""
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _client_context(request: Request) -> Tuple[str, str]:
    """Resolve the requester's preferred IP and location for the invite email."""
    if "X-Forwarded-For" in request.headers:
        client_ip = request.headers["X-Forwarded-For"].split(",")[0].strip()
    elif "X-Real-IP" in request.headers:
        client_ip = request.headers["X-Real-IP"].strip()
    else:
        client_ip = request.client.host
    return get_preferred_ip_address(client_ip), get_location_from_headers(request)


def _session_valid(email: str, token: str) -> bool:
    """Validate a dashboard session for the requester email."""
    if not validate_email_with_tld(email) or not validate_token(token):
        return False
    return validate_dashboard_session(ds_client, email, token)


def _target_shield_on(target_email: str) -> bool:
    """Return whether the target has Privacy Shield enabled."""
    try:
        alert_record = ds_client.get(ds_client.key("xon_alert", target_email))
        return bool(alert_record and alert_record.get("shieldOn", False))
    except google_exceptions.GoogleAPIError:
        return False


async def _fetch_target_breaches(target_email: str) -> Optional[Dict[str, Any]]:
    """Fetch the target's full breach details for an accepted monitor."""
    try:
        exposure = await get_exposure(target_email)
    except (google_exceptions.GoogleAPIError, ValueError, RuntimeError):
        exposure = {}

    site = str(exposure.get("site", "") or "")
    sensitive_site = str(exposure.get("sensitive_site", "") or "")
    all_breaches = ";".join([part for part in (site, sensitive_site) if part])
    if not all_breaches:
        return None

    try:
        details = get_breaches(all_breaches).get("breaches_details", [])
    except (HTTPException, google_exceptions.GoogleAPIError):
        details = []

    try:
        metrics = await get_breaches_analytics(all_breaches)
    except (google_exceptions.GoogleAPIError, ValueError, RuntimeError):
        metrics = {}

    return {
        "breaches_count": len(details),
        "breaches_details": details,
        "BreachMetrics": metrics,
    }


async def _flip_status(
    edge_key, expected_status: str, updates: Dict[str, Any]
) -> Optional[datastore.Entity]:
    """Transactionally flip an edge's status when it matches the precondition."""
    max_retries = 5
    retry_count = 0
    while retry_count < max_retries:
        try:
            with ds_client.transaction():
                edge = ds_client.get(edge_key)
                if not edge:
                    return None
                if edge.get("status") == expected_status:
                    for field, value in updates.items():
                        edge[field] = value
                    ds_client.put(edge)
                return edge
        except (google_exceptions.GoogleAPIError, ValueError, RuntimeError):
            retry_count += 1
            if retry_count >= max_retries:
                raise
            await asyncio.sleep(2**retry_count * 0.1)
    return None


def _existing_edge_blocks_invite(edge: datastore.Entity, now: datetime) -> bool:
    """Return True when an existing edge means no new invite should be sent."""
    status = edge.get("status")
    if status == STATUS_ACCEPTED:
        return True
    if status == STATUS_REJECTED:
        responded_at = edge.get("responded_at")
        if responded_at is not None:
            if responded_at.tzinfo is None:
                responded_at = responded_at.replace(tzinfo=timezone.utc)
            cooldown_days = (now - responded_at).total_seconds() / 86400
            if cooldown_days < REJECT_COOLDOWN_DAYS:
                return True
    return False


def _requester_at_cap(requester_email: str, key_name: str) -> bool:
    """Return True when the requester already has the max active monitors."""
    query = ds_client.query(kind="xon_monitor")
    query.add_filter("requester_email", "=", requester_email)
    active_count = sum(
        1
        for record in query.fetch()
        if record.get("status") in (STATUS_PENDING, STATUS_ACCEPTED)
        and record.key.name != key_name
    )
    return active_count >= MAX_MONITORS_PER_USER


def _create_pending_edge(
    edge_key, requester_email: str, target_email: str, now: datetime, token: str
) -> None:
    """Create the pending monitor edge for a fresh invite."""
    entity = datastore.Entity(edge_key, exclude_from_indexes=MONITOR_EXCLUDED_FIELDS)
    entity.update(
        {
            "requester_email": requester_email,
            "target_email": target_email,
            "status": STATUS_PENDING,
            "insert_timestamp": now,
            "verified": False,
            "unSubscribeOn": False,
            "shieldOn": False,
            "reminder_eligible": True,
            "reminder_count": 0,
            "token": token,
        }
    )
    ds_client.put(entity)


async def _send_invite(
    request: Request, target_email: str, requester_email: str, token: str
) -> None:
    """Send the consent invite email, subject to a per-recipient throttle."""
    redis_conn = await get_healthy_redis_connection()
    recipient_limited, _, _ = await is_rate_limited(
        f"monitor-invite:{target_email}", MONITOR_INVITE_LIMIT, redis_conn
    )
    if recipient_limited:
        return

    base_url = str(request.base_url)
    accept_url = f"{base_url}v1/monitor-accept/{token}"
    decline_url = f"{base_url}v1/monitor-decline/{token}"
    preferred_ip, location = _client_context(request)
    await send_monitor_invite(
        target_email,
        requester_email,
        accept_url,
        decline_url,
        _target_shield_on(target_email),
        preferred_ip,
        location,
    )


@router.post("/monitor", response_model=Union[MonitorResponse, MonitorErrorResponse])
@custom_rate_limiter("50 per day;25 per hour;2 per second")
async def create_monitor(
    request: Request,
    payload: MonitorRequest,
    email: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
):
    """Onboard a target for breach monitoring on behalf of the requester."""
    target_email = ""
    success = MonitorResponse(status="Success", message="Monitoring request sent")
    try:
        if not MONITOR_ENABLED:
            raise HTTPException(status_code=404, detail="Not found")

        if (
            not email
            or not token
            or not payload.target_email
            or not validate_url(request)
        ):
            raise HTTPException(
                status_code=400,
                detail=MonitorErrorResponse(Error="Invalid request").dict(),
            )

        requester_email = email.lower()
        if not _session_valid(requester_email, token):
            raise HTTPException(
                status_code=401,
                detail=MonitorErrorResponse(Error="Invalid or expired session").dict(),
            )

        is_deliverable, validated_email = validate_email_deliverable(
            str(payload.target_email).lower()
        )
        if not is_deliverable:
            raise HTTPException(
                status_code=400,
                detail=MonitorErrorResponse(Error=validated_email).dict(),
            )
        target_email = validated_email

        if target_email == requester_email:
            raise HTTPException(
                status_code=400,
                detail=MonitorErrorResponse(Error="You cannot monitor yourself").dict(),
            )

        key_name = _edge_key_name(requester_email, target_email)
        edge_key = ds_client.key("xon_monitor", key_name)
        now = datetime.now(timezone.utc)

        edge = ds_client.get(edge_key)
        if edge is not None and _existing_edge_blocks_invite(edge, now):
            return success

        if _requester_at_cap(requester_email, key_name):
            raise HTTPException(
                status_code=400,
                detail=MonitorErrorResponse(Error="Monitoring limit reached").dict(),
            )

        verification_token = await generate_monitor_token(key_name)
        _create_pending_edge(
            edge_key, requester_email, target_email, now, verification_token
        )
        await _send_invite(request, target_email, requester_email, verification_token)
        return success

    except HTTPException:
        raise
    except (ValueError, google_exceptions.GoogleAPIError) as exception_details:
        await send_exception_email(
            api_route="POST /v1/monitor",
            error_message=str(exception_details),
            exception_type=type(exception_details).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"target={target_email}",
        )
        raise HTTPException(status_code=404) from exception_details


async def _build_monitor_item(record: datastore.Entity) -> MonitorItem:
    """Build a MonitorItem for a single edge, with breaches only when accepted."""
    status = record.get("status")
    breaches = None
    if status == STATUS_ACCEPTED:
        breaches = await _fetch_target_breaches(record.get("target_email"))
    return MonitorItem(
        target_email=record.get("target_email", ""),
        status=status,
        requested_at=_iso(record.get("insert_timestamp")),
        responded_at=_iso(record.get("responded_at")),
        shield_override=bool(record.get("shieldOn", False)),
        breaches=breaches,
    )


@router.get(
    "/my-monitors",
    response_model=Union[MonitorListResponse, MonitorListErrorResponse],
)
@custom_rate_limiter("100 per day;50 per hour;2 per second")
async def my_monitors(
    request: Request,
    email: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
):
    """List the requester's monitored contacts grouped by status."""
    try:
        if not MONITOR_ENABLED:
            raise HTTPException(status_code=404, detail="Not found")

        if not email or not token or not validate_url(request):
            raise HTTPException(
                status_code=400,
                detail=MonitorListErrorResponse(Error="Invalid request").dict(),
            )

        requester_email = email.lower()
        if not _session_valid(requester_email, token):
            raise HTTPException(
                status_code=401,
                detail=MonitorListErrorResponse(
                    Error="Invalid or expired session"
                ).dict(),
            )

        query = ds_client.query(kind="xon_monitor")
        query.add_filter("requester_email", "=", requester_email)

        counts = {STATUS_PENDING: 0, STATUS_ACCEPTED: 0, STATUS_REJECTED: 0}
        items = []
        for record in query.fetch():
            status = record.get("status")
            if status not in counts:
                continue
            counts[status] += 1
            items.append(await _build_monitor_item(record))

        summary = {
            "total": sum(counts.values()),
            "pending_count": counts[STATUS_PENDING],
            "accepted_count": counts[STATUS_ACCEPTED],
            "rejected_count": counts[STATUS_REJECTED],
        }
        return MonitorListResponse(
            status="Success",
            Monitor_Management=MonitorManagement(summary=summary, monitors=items),
        )

    except HTTPException:
        raise
    except (ValueError, google_exceptions.GoogleAPIError) as exception_details:
        await send_exception_email(
            api_route="GET /v1/my-monitors",
            error_message=str(exception_details),
            exception_type=type(exception_details).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"email={email}",
        )
        raise HTTPException(
            status_code=500,
            detail=MonitorListErrorResponse(Error="Unable to load monitors").dict(),
        ) from exception_details


@router.post(
    "/monitor-revoke", response_model=Union[MonitorResponse, MonitorErrorResponse]
)
@custom_rate_limiter("20 per day;5 per hour;2 per second")
async def revoke_monitor(
    request: Request,
    payload: MonitorRequest,
    email: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
):
    """Requester stops monitoring a target."""
    target_email = ""
    try:
        if not MONITOR_ENABLED:
            raise HTTPException(status_code=404, detail="Not found")

        if (
            not email
            or not token
            or not payload.target_email
            or not validate_url(request)
        ):
            raise HTTPException(
                status_code=400,
                detail=MonitorErrorResponse(Error="Invalid request").dict(),
            )

        requester_email = email.lower()
        if not _session_valid(requester_email, token):
            raise HTTPException(
                status_code=401,
                detail=MonitorErrorResponse(Error="Invalid or expired session").dict(),
            )

        target_email = str(payload.target_email).lower()
        if not validate_email_with_tld(target_email):
            raise HTTPException(
                status_code=400,
                detail=MonitorErrorResponse(Error="Invalid email format").dict(),
            )

        edge_key = ds_client.key(
            "xon_monitor", _edge_key_name(requester_email, target_email)
        )
        now = datetime.now(timezone.utc)
        updates = {
            "status": STATUS_REVOKED,
            "unSubscribeOn": True,
            "recent_timestamp": now,
            "responded_at": now,
            "token": "",
            "unsub_token": "",
        }
        for expected in (STATUS_PENDING, STATUS_ACCEPTED):
            edge = await _flip_status(edge_key, expected, updates)
            if edge is not None and edge.get("status") == STATUS_REVOKED:
                break

        return MonitorResponse(status="Success", message="Monitoring stopped")

    except HTTPException:
        raise
    except (ValueError, google_exceptions.GoogleAPIError) as exception_details:
        await send_exception_email(
            api_route="POST /v1/monitor-revoke",
            error_message=str(exception_details),
            exception_type=type(exception_details).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params=f"target={target_email}",
        )
        raise HTTPException(status_code=404) from exception_details


async def _resolve_edge(
    monitor_token: str, expiration: int, token_field: str
) -> Tuple[Optional[datastore.Entity], Optional[str], Optional[str]]:
    """Validate a consent/withdraw token and fetch its matching edge."""
    payload = await confirm_monitor_token(monitor_token, expiration)
    if not payload:
        return None, None, None
    requester_email, target_email = _parse_edge_payload(payload)
    if not requester_email or not target_email:
        return None, None, None
    edge_key = ds_client.key(
        "xon_monitor", _edge_key_name(requester_email, target_email)
    )
    edge = ds_client.get(edge_key)
    if not edge or edge.get(token_field) != monitor_token:
        return None, requester_email, target_email
    return edge, requester_email, target_email


async def _resolve_valid_edge(
    monitor_token: str, request: Request, expiration: int, token_field: str
) -> Tuple[Optional[datastore.Entity], Optional[str], Optional[str]]:
    """Guard inputs then resolve a token's edge; returns Nones when invalid."""
    if (
        not MONITOR_ENABLED
        or not monitor_token
        or not validate_variables([monitor_token])
        or not validate_url(request)
    ):
        return None, None, None
    return await _resolve_edge(monitor_token, expiration, token_field)


def _error_page(request: Request):
    """Render the shared monitor error page."""
    return templates.TemplateResponse(request, "monitor_error.html", status_code=404)


def _confirm_page(request: Request, action: str, action_url: str, requester_email: str):
    """Render the interstitial confirm page for a consent action."""
    return templates.TemplateResponse(
        request,
        "monitor_confirm.html",
        context={
            "action": action,
            "action_url": action_url,
            "requester_email": requester_email,
        },
    )


def revoke_monitors_for_target(target_email: str) -> int:
    """Revoke inbound monitor edges when a target opts out of alerts globally."""
    if not target_email:
        return 0
    now = datetime.now(timezone.utc)
    query = ds_client.query(kind="xon_monitor")
    query.add_filter("target_email", "=", target_email)
    revoked = 0
    for record in query.fetch():
        if record.get("status") in (STATUS_PENDING, STATUS_ACCEPTED):
            record["status"] = STATUS_REVOKED
            record["unSubscribeOn"] = True
            record["recent_timestamp"] = now
            record["responded_at"] = now
            record["token"] = ""
            record["unsub_token"] = ""
            ds_client.put(record)
            revoked += 1
    return revoked


async def process_monitor_reminders():
    """Send consent reminders for pending monitor invites."""
    now = datetime.now(timezone.utc)
    query = ds_client.query(kind="xon_monitor")
    query.add_filter("reminder_eligible", "=", True)
    candidates = list(query.fetch())

    reminders_sent = 0
    for record in candidates:
        try:
            if not _monitor_reminder_due(record, now):
                continue
            requester_email = record.get("requester_email")
            target_email = record.get("target_email")
            fresh_token = await generate_monitor_token(
                _edge_key_name(requester_email, target_email)
            )
            await send_monitor_invite(
                target_email,
                requester_email,
                f"{BASE_URL}/v1/monitor-accept/{fresh_token}",
                f"{BASE_URL}/v1/monitor-decline/{fresh_token}",
                _target_shield_on(target_email),
                "",
                "",
            )
            _record_monitor_reminder(record, fresh_token)
            reminders_sent += 1
        except (
            google_exceptions.GoogleAPIError,
            ValueError,
            RuntimeError,
            HTTPException,
        ) as exc:
            logger.error(
                "[MONITOR-REMINDER] Failed for %s: %s", record.key.name, str(exc)
            )
            continue

    logger.info(
        "[MONITOR-REMINDER] Completed: %s reminders sent across %s candidates",
        reminders_sent,
        len(candidates),
    )
    return {
        "status": "success",
        "reminders_sent": reminders_sent,
        "candidates": len(candidates),
    }


def _monitor_reminder_due(record: datastore.Entity, now: datetime) -> bool:
    """Return True when a pending invite is due for its next reminder."""
    if record.get("status") != STATUS_PENDING:
        return False
    reminder_count = record.get("reminder_count", 0) or 0
    if reminder_count >= MONITOR_MAX_REMINDERS:
        return False
    insert_ts = record.get("insert_timestamp")
    if not insert_ts:
        return False
    if insert_ts.tzinfo is None:
        insert_ts = insert_ts.replace(tzinfo=timezone.utc)
    age_days = (now - insert_ts).total_seconds() / 86400
    due_after = MONITOR_REMINDER_SCHEDULE_DAYS.get(reminder_count)
    return due_after is not None and age_days >= due_after


def _record_monitor_reminder(record: datastore.Entity, fresh_token: str) -> None:
    """Persist an incremented reminder count and refreshed token for an invite."""
    with ds_client.transaction():
        fresh = ds_client.get(record.key)
        if fresh and fresh.get("status") == STATUS_PENDING:
            fresh["reminder_count"] = (fresh.get("reminder_count", 0) or 0) + 1
            fresh["last_reminder_at"] = datetime.now(timezone.utc)
            fresh["token"] = fresh_token
            ds_client.put(fresh)


@router.get("/monitor-accept/{monitor_token}")
@custom_rate_limiter("50 per day;25 per hour;2 per second")
async def monitor_accept_page(monitor_token: str, request: Request):
    """Render the accept interstitial (no state change)."""
    edge, requester_email, _ = await _resolve_valid_edge(
        monitor_token, request, CONSENT_TOKEN_EXPIRY, "token"
    )
    if not edge or edge.get("status") != STATUS_PENDING:
        return _error_page(request)
    return _confirm_page(
        request,
        "accept",
        f"{request.base_url}v1/monitor-accept/{monitor_token}",
        requester_email,
    )


@router.post("/monitor-accept/{monitor_token}")
@custom_rate_limiter("50 per day;25 per hour;2 per second")
async def monitor_accept_confirm(monitor_token: str, request: Request):
    """Finalize a target's acceptance of a monitoring request."""
    try:
        edge, requester_email, target_email = await _resolve_valid_edge(
            monitor_token, request, CONSENT_TOKEN_EXPIRY, "token"
        )
        if not edge:
            return _error_page(request)
        if edge.get("status") == STATUS_ACCEPTED:
            return templates.TemplateResponse(request, "monitor_accepted.html")
        if edge.get("status") != STATUS_PENDING:
            return _error_page(request)

        now = datetime.now(timezone.utc)
        key_name = _edge_key_name(requester_email, target_email)
        withdraw_token = await generate_monitor_token(key_name)
        shield_on = _target_shield_on(target_email)
        updates = {
            "status": STATUS_ACCEPTED,
            "verified": True,
            "verify_timestamp": now,
            "responded_at": now,
            "recent_timestamp": now,
            "reminder_eligible": False,
            "token": "",
            "unsub_token": withdraw_token,
            "shieldOn": shield_on,
        }
        if shield_on:
            updates["shield_timestamp"] = now

        flipped = await _flip_status(
            ds_client.key("xon_monitor", key_name), STATUS_PENDING, updates
        )
        if not flipped or flipped.get("status") != STATUS_ACCEPTED:
            return _error_page(request)

        await send_monitor_accepted(
            target_email,
            requester_email,
            f"{request.base_url}v1/monitor-withdraw/{withdraw_token}",
        )
        await send_monitor_requester_notice(
            requester_email, target_email, "accepted", DASHBOARD_URL
        )
        return templates.TemplateResponse(request, "monitor_accepted.html")

    except (ValueError, google_exceptions.GoogleAPIError) as exception_details:
        await send_exception_email(
            api_route="POST /v1/monitor-accept/{token}",
            error_message=str(exception_details),
            exception_type=type(exception_details).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params="token=provided" if monitor_token else "token=missing",
        )
        return _error_page(request)


@router.get("/monitor-decline/{monitor_token}")
@custom_rate_limiter("50 per day;25 per hour;2 per second")
async def monitor_decline_page(monitor_token: str, request: Request):
    """Render the decline interstitial (no state change)."""
    edge, requester_email, _ = await _resolve_valid_edge(
        monitor_token, request, CONSENT_TOKEN_EXPIRY, "token"
    )
    if not edge or edge.get("status") != STATUS_PENDING:
        return _error_page(request)
    return _confirm_page(
        request,
        "decline",
        f"{request.base_url}v1/monitor-decline/{monitor_token}",
        requester_email,
    )


@router.post("/monitor-decline/{monitor_token}")
@custom_rate_limiter("50 per day;25 per hour;2 per second")
async def monitor_decline_confirm(monitor_token: str, request: Request):
    """Finalize a target's decline of a monitoring request."""
    try:
        edge, requester_email, target_email = await _resolve_valid_edge(
            monitor_token, request, CONSENT_TOKEN_EXPIRY, "token"
        )
        if not edge:
            return _error_page(request)
        if edge.get("status") == STATUS_REJECTED:
            return templates.TemplateResponse(request, "monitor_declined.html")
        if edge.get("status") != STATUS_PENDING:
            return _error_page(request)

        now = datetime.now(timezone.utc)
        key_name = _edge_key_name(requester_email, target_email)
        flipped = await _flip_status(
            ds_client.key("xon_monitor", key_name),
            STATUS_PENDING,
            {
                "status": STATUS_REJECTED,
                "responded_at": now,
                "recent_timestamp": now,
                "reminder_eligible": False,
                "token": "",
            },
        )
        if not flipped or flipped.get("status") != STATUS_REJECTED:
            return _error_page(request)

        await send_monitor_requester_notice(
            requester_email, target_email, "declined", DASHBOARD_URL
        )
        return templates.TemplateResponse(request, "monitor_declined.html")

    except (ValueError, google_exceptions.GoogleAPIError) as exception_details:
        await send_exception_email(
            api_route="POST /v1/monitor-decline/{token}",
            error_message=str(exception_details),
            exception_type=type(exception_details).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params="token=provided" if monitor_token else "token=missing",
        )
        return _error_page(request)


@router.get("/monitor-withdraw/{monitor_token}")
@custom_rate_limiter("50 per day;25 per hour;2 per second")
async def monitor_withdraw_page(monitor_token: str, request: Request):
    """Render the withdraw interstitial (no state change)."""
    edge, requester_email, _ = await _resolve_valid_edge(
        monitor_token, request, WITHDRAW_TOKEN_EXPIRY, "unsub_token"
    )
    if not edge or edge.get("status") != STATUS_ACCEPTED:
        return _error_page(request)
    return _confirm_page(
        request,
        "withdraw",
        f"{request.base_url}v1/monitor-withdraw/{monitor_token}",
        requester_email,
    )


@router.post("/monitor-withdraw/{monitor_token}")
@custom_rate_limiter("50 per day;25 per hour;2 per second")
async def monitor_withdraw_confirm(monitor_token: str, request: Request):
    """Finalize a target's withdrawal of previously granted consent."""
    try:
        edge, requester_email, target_email = await _resolve_valid_edge(
            monitor_token, request, WITHDRAW_TOKEN_EXPIRY, "unsub_token"
        )
        if not edge:
            return _error_page(request)
        if edge.get("status") == STATUS_REVOKED:
            return templates.TemplateResponse(request, "monitor_withdrawn.html")
        if edge.get("status") != STATUS_ACCEPTED:
            return _error_page(request)

        now = datetime.now(timezone.utc)
        key_name = _edge_key_name(requester_email, target_email)
        flipped = await _flip_status(
            ds_client.key("xon_monitor", key_name),
            STATUS_ACCEPTED,
            {
                "status": STATUS_REVOKED,
                "unSubscribeOn": True,
                "responded_at": now,
                "recent_timestamp": now,
                "unsub_token": "",
            },
        )
        if not flipped or flipped.get("status") != STATUS_REVOKED:
            return _error_page(request)

        await send_monitor_requester_notice(
            requester_email, target_email, "withdrew", DASHBOARD_URL
        )
        return templates.TemplateResponse(request, "monitor_withdrawn.html")

    except (ValueError, google_exceptions.GoogleAPIError) as exception_details:
        await send_exception_email(
            api_route="POST /v1/monitor-withdraw/{token}",
            error_message=str(exception_details),
            exception_type=type(exception_details).__name__,
            user_agent=request.headers.get("User-Agent"),
            request_params="token=provided" if monitor_token else "token=missing",
        )
        return _error_page(request)
