import asyncio
import ipaddress
import logging
import random
import time
from datetime import datetime, timedelta
from functools import wraps
from typing import Callable, Dict, List, Tuple, Optional

import redis.asyncio as redis
from fastapi import Request, HTTPException
from starlette.status import HTTP_403_FORBIDDEN, HTTP_429_TOO_MANY_REQUESTS

from config.settings import (
    BOT_ENFORCEMENT_ENABLED,
    CF_BLOCK_DAY_THRESHOLD,
    CF_BLOCK_ENFORCEMENT_ENABLED,
    LIMITER_DEGRADED_ENABLED,
    REDIS_URL,
)
from utils.bot_detection import (
    BOT_FLAG_THRESHOLD,
    classify_request,
    request_fingerprint,
)
from utils.helpers import get_client_ip

logger = logging.getLogger(__name__)

# Redis health tracking — dedup alert logging
_last_redis_alert_time = 0.0
_REDIS_ALERT_INTERVAL = 300  # Log Redis failures at most once per 5 minutes

redis_pool = redis.from_url(
    REDIS_URL,
    encoding="utf-8",
    decode_responses=True,
    socket_keepalive=True,
    socket_keepalive_options={},
    socket_connect_timeout=1,
    socket_timeout=2,
    retry_on_timeout=True,
    health_check_interval=30,
    max_connections=20,
    retry_on_error=[redis.ConnectionError, redis.TimeoutError],
)

_REDIS_RETRY_COOLDOWN_SECONDS = 5.0
_FALLBACK_MAX_KEYS = 100_000

_redis_down_until = 0.0
_redis_degraded = False
_fallback_windows: Dict[str, List[float]] = {}


def _mark_redis_down(context: str, error: Exception) -> None:
    """Open the circuit for a cooldown and record the failure."""
    global _redis_down_until, _redis_degraded
    _redis_down_until = time.time() + _REDIS_RETRY_COOLDOWN_SECONDS
    if not _redis_degraded:
        _redis_degraded = True
        logger.error(
            "Rate limiter entering degraded mode: in-memory per-instance limits active"
        )
    _log_redis_failure(context, error)


def _mark_redis_recovered() -> None:
    """Close the circuit and discard fallback state after Redis returns."""
    global _redis_degraded
    if _redis_degraded:
        _redis_degraded = False
        _fallback_windows.clear()
        logger.info("Rate limiter recovered: Redis restored, shared limits active")


def _fallback_is_limited(
    key: str, rate_limits: List[Tuple[int, int]], now: float
) -> Tuple[bool, int]:
    """Per-process sliding-window check used while Redis is unavailable."""
    if len(_fallback_windows) > _FALLBACK_MAX_KEYS:
        _fallback_windows.clear()

    max_period = max(limit[1] for limit in rate_limits) if rate_limits else 86400
    cutoff = now - max_period
    timestamps = [t for t in _fallback_windows.get(key, []) if t > cutoff]
    timestamps.append(now)
    _fallback_windows[key] = timestamps

    for limit, period in rate_limits:
        window = [t for t in timestamps if t > now - period]
        if len(window) > limit:
            retry_after = max(1, int(period - (now - window[0])))
            return True, retry_after
    return False, 0


async def get_healthy_redis_connection():
    """
    Return the shared async Redis pool.

    Connection liveness is handled by the client itself: TCP keepalives,
    health_check_interval pings on idle connections, and retry_on_error
    reconnection for commands that hit a dead socket.
    """
    return redis_pool


_redis_alert_tasks: set = set()


def _log_redis_failure(context: str, error: Exception):
    """Log Redis failures with dedup and alert the admin via email."""
    global _last_redis_alert_time
    now = time.time()
    if now - _last_redis_alert_time > _REDIS_ALERT_INTERVAL:
        _last_redis_alert_time = now
        logger.error(
            "Redis failure in %s: %s — rate limiting bypassed", context, str(error)
        )
        try:
            from services.send_email import send_exception_email

            task = asyncio.get_running_loop().create_task(
                send_exception_email(
                    api_route=f"redis-failure:{context}",
                    error_message=str(error),
                    exception_type=type(error).__name__,
                    user_agent="internal",
                    request_params="rate limiting bypassed (fail-open)",
                )
            )
            _redis_alert_tasks.add(task)
            task.add_done_callback(_redis_alert_tasks.discard)
        except Exception:
            pass


def parse_rate_limit(rate_limit_str: str) -> List[Tuple[int, int]]:
    """
    Parses a rate limit string like "2 per second;5 per hour;100 per day"
    into a list of (limit, period_in_seconds).
    """
    limits = []
    for limit_str in rate_limit_str.split(";"):
        limit_str = limit_str.strip()
        if not limit_str:
            continue

        try:
            count, _, unit = limit_str.split()
            count = int(count)

            if unit.startswith("sec"):
                period = 1
            elif unit.startswith("min"):
                period = 60
            elif unit.startswith("hour"):
                period = 3600
            elif unit.startswith("day"):
                period = 86400
            else:
                continue

            limits.append((count, period))
        except ValueError:
            continue

    return limits


async def is_rate_limited(
    key: str, rate_limits: List[Tuple[int, int]], redis_conn: redis.Redis = None
) -> Tuple[bool, int, int]:
    """
    Checks if a given key has exceeded any of the specified rate limits using Redis.
    Returns a tuple of (is_limited, retry_after_seconds, limited_period_seconds).
    """
    if redis_conn is None:
        redis_conn = await get_healthy_redis_connection()

    now = time.time()

    try:
        async with redis_conn.pipeline(transaction=True) as pipe:
            pipe.zadd(key, {str(now): now})
            max_period = (
                max(limit[1] for limit in rate_limits) if rate_limits else 86400
            )
            pipe.zremrangebyscore(key, 0, now - max_period)

            for _, period in rate_limits:
                pipe.zcount(key, now - period, now)

            results = await pipe.execute()

        request_counts = results[2:]

        for i, (limit, period) in enumerate(rate_limits):
            count = request_counts[i]

            if count > limit:

                oldest_in_window_list = await redis_conn.zrange(
                    key, -count, -count, withscores=True
                )

                if oldest_in_window_list:
                    oldest_ts = oldest_in_window_list[0][1]
                    retry_after = int(period - (now - oldest_ts))
                    return True, max(1, retry_after), period

                return True, period, period

        return False, 0, 0
    except Exception as e:
        _log_redis_failure("is_rate_limited", e)
        return False, 0, 0


async def get_violation_count(client_ip: str, redis_conn: redis.Redis = None) -> int:
    """
    Get the number of rate limit violations for a client IP in the last hour.
    """
    if redis_conn is None:
        redis_conn = await get_healthy_redis_connection()

    violation_key = f"violations:{client_ip}"
    now = time.time()

    try:
        await redis_conn.zremrangebyscore(violation_key, 0, now - 3600)
        count = await redis_conn.zcard(violation_key)
        return count
    except Exception as e:
        _log_redis_failure("get_violation_count", e)
        return 0


async def increment_violation(client_ip: str, redis_conn: redis.Redis = None):
    """
    Increment the violation count for a client IP.
    """
    if redis_conn is None:
        redis_conn = await get_healthy_redis_connection()

    violation_key = f"violations:{client_ip}"
    now = time.time()

    try:
        async with redis_conn.pipeline(transaction=True) as pipe:
            pipe.zadd(violation_key, {str(now): now})
            pipe.expire(violation_key, 7200)
            await pipe.execute()
    except Exception as e:
        _log_redis_failure("increment_violation", e)


def get_drop_percentage(violation_count: int) -> float:
    """
    Determine the percentage of requests to drop based on violation count.
    """
    if violation_count <= 3:
        return 0.0
    elif violation_count <= 6:
        return 0.5
    elif violation_count <= 10:
        return 0.8
    else:
        return 0.95


async def _oldest_retry_after(
    redis_conn: redis.Redis, key: str, count: int, period: int, now: float
) -> Optional[int]:
    """Compute retry-after from the oldest request in the limited window.

    Returns period when the window is unexpectedly empty, and None on a
    Redis error so the caller fails open exactly like is_rate_limited.
    """
    try:
        oldest_in_window_list = await redis_conn.zrange(
            key, -count, -count, withscores=True
        )
    except Exception as e:
        _log_redis_failure("_oldest_retry_after", e)
        return None
    if oldest_in_window_list:
        oldest_ts = oldest_in_window_list[0][1]
        return max(1, int(period - (now - oldest_ts)))
    return period


async def _discard_window_member(
    redis_conn: redis.Redis, key: str, member: str
) -> None:
    """Remove the speculatively added window entry when a request is rejected early."""
    try:
        await redis_conn.zrem(key, member)
    except Exception as e:
        _log_redis_failure("_discard_window_member", e)


_BOT_FP_LIMITS = parse_rate_limit("5 per minute;100 per day")

CF_ESCALATION_ENDPOINTS = {"/v1/check-email/{email}", "/v1/breach-analytics"}
_CF_OVERAGE_TTL_SECONDS = 86400
_CF_OFFENSE_WINDOW_SECONDS = 7 * 86400
_cf_block_tasks: set = set()


async def _apply_cf_rule(client_ip: str, repeat_offender: bool) -> None:
    """Apply the Cloudflare edge rule for an escalated IP."""
    try:
        from services.cloudflare import block_day, challenge_day

        if repeat_offender:
            await block_day(client_ip)
        else:
            await challenge_day(client_ip)
    except Exception as e:
        logger.error("cf-escalation rule creation failed for %s: %s", client_ip, e)


async def escalate_day_limit_abuse(
    client_ip: str, endpoint: str, redis_conn: redis.Redis
) -> bool:
    """
    Escalate persistent rate-limit abusers to a Cloudflare edge rule.

    Counts rate-limited (429) requests per IP per endpoint over 24 hours;
    once an IP crosses CF_BLOCK_DAY_THRESHOLD it is escalated. The first
    offense gets a 24h managed challenge, a repeat offense within 7 days a
    24h block, both released by the scheduled unblock job. Returns True when
    the caller should respond 403 instead of 429.
    """
    try:
        ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    try:
        if await redis_conn.get(f"cf-escalated:{client_ip}"):
            return CF_BLOCK_ENFORCEMENT_ENABLED

        overage_key = f"cf-overage:{endpoint}:{client_ip}"
        overage = await redis_conn.incr(overage_key)
        if overage == 1:
            await redis_conn.expire(overage_key, _CF_OVERAGE_TTL_SECONDS)
        if overage < CF_BLOCK_DAY_THRESHOLD:
            return False

        newly_escalated = await redis_conn.set(
            f"cf-escalated:{client_ip}", "1", nx=True, ex=_CF_OVERAGE_TTL_SECONDS
        )
        if not newly_escalated:
            return CF_BLOCK_ENFORCEMENT_ENABLED

        offense_key = f"cf-offense:{client_ip}"
        repeat_offender = bool(await redis_conn.get(offense_key))
        action = "block" if repeat_offender else "challenge"

        if not CF_BLOCK_ENFORCEMENT_ENABLED:
            logger.warning(
                "cf-escalation SHADOW: would %s ip=%s endpoint=%s overage=%s",
                action,
                client_ip,
                endpoint,
                overage,
            )
            return False

        logger.warning(
            "cf-escalation ENFORCED: %s ip=%s endpoint=%s overage=%s",
            action,
            client_ip,
            endpoint,
            overage,
        )
        await redis_conn.set(offense_key, "1", ex=_CF_OFFENSE_WINDOW_SECONDS)
        task = asyncio.create_task(_apply_cf_rule(client_ip, repeat_offender))
        _cf_block_tasks.add(task)
        task.add_done_callback(_cf_block_tasks.discard)
        return True
    except Exception as e:
        _log_redis_failure("escalate_day_limit_abuse", e)
        return False


def custom_rate_limiter(rate_limit_str: str, message: Optional[str] = None):
    """
    A decorator for FastAPI routes to enforce custom rate limiting with request dropping.

    Args:
        rate_limit_str: A string defining the limits, e.g.,
                        "2 per second;5 per hour;100 per day"
        message: An optional custom message to include in the 429 response.
    """
    rate_limits = parse_rate_limit(rate_limit_str)

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request: Request = kwargs.get("request")
            if not isinstance(request, Request):

                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
                else:
                    raise ValueError("Request object not found in function arguments")

            client_ip = get_client_ip(request)
            endpoint = (
                request.scope.get("route").path
                if request.scope.get("route")
                else request.url.path
            )
            key = f"rate-limit:{endpoint}:{client_ip}"

            redis_conn = await get_healthy_redis_connection()

            bot = classify_request(request.headers)
            bot_flagged = bot["score"] >= BOT_FLAG_THRESHOLD
            bot_included = bot_flagged and BOT_ENFORCEMENT_ENABLED
            bot_key = None
            if bot_flagged:
                fingerprint = request_fingerprint(request.headers)
                bot_key = f"botnet-fp:{endpoint}:{fingerprint}"

            now = time.time()
            member = str(now)
            violation_key = f"violations:{client_ip}"
            max_period = (
                max(limit[1] for limit in rate_limits) if rate_limits else 86400
            )

            violation_count = 0
            request_counts = []
            bot_counts = []
            degraded = False
            if LIMITER_DEGRADED_ENABLED and now < _redis_down_until:
                degraded = True
            else:
                try:
                    async with redis_conn.pipeline(transaction=True) as pipe:
                        if bot_included:
                            bot_max = max(limit[1] for limit in _BOT_FP_LIMITS)
                            pipe.zadd(bot_key, {member: now})
                            pipe.zremrangebyscore(bot_key, 0, now - bot_max)
                            for _, period in _BOT_FP_LIMITS:
                                pipe.zcount(bot_key, now - period, now)
                            pipe.expire(bot_key, int(bot_max))
                        pipe.zremrangebyscore(violation_key, 0, now - 3600)
                        pipe.zcard(violation_key)
                        pipe.zadd(key, {member: now})
                        pipe.zremrangebyscore(key, 0, now - max_period)
                        for _, period in rate_limits:
                            pipe.zcount(key, now - period, now)
                        pipe.expire(key, int(max_period))
                        results = await pipe.execute()

                    _mark_redis_recovered()
                    base = (3 + len(_BOT_FP_LIMITS)) if bot_included else 0
                    if bot_included:
                        bot_counts = list(results[2 : 2 + len(_BOT_FP_LIMITS)])
                    violation_count = results[base + 1]
                    request_counts = list(
                        results[base + 4 : base + 4 + len(rate_limits)]
                    )
                except Exception as e:
                    if LIMITER_DEGRADED_ENABLED:
                        _mark_redis_down("custom_rate_limiter", e)
                        degraded = True
                    else:
                        _log_redis_failure("custom_rate_limiter", e)

            if degraded:
                limited, retry_after = _fallback_is_limited(key, rate_limits, now)
                if limited:
                    reset_time = datetime.now() + timedelta(seconds=retry_after)
                    error_detail = {
                        "error": "Rate limit exceeded",
                        "detail": (
                            f"Rate limit exceeded for endpoint {endpoint}. "
                            f"Please try again after {retry_after} seconds."
                        ),
                        "retry_after": retry_after,
                        "reset_time": reset_time.isoformat(),
                    }
                    if message:
                        error_detail["message"] = message
                    raise HTTPException(
                        status_code=HTTP_429_TOO_MANY_REQUESTS,
                        detail=error_detail,
                        headers={"Retry-After": str(retry_after)},
                    )
                return await func(*args, **kwargs)

            if bot_flagged:
                bot_limited, bot_retry = False, 0
                for i, (limit, period) in enumerate(_BOT_FP_LIMITS):
                    if bot_counts and bot_counts[i] > limit:
                        retry = await _oldest_retry_after(
                            redis_conn, bot_key, bot_counts[i], period, now
                        )
                        if retry is not None:
                            bot_limited, bot_retry = True, retry
                        break
                logger.info(
                    "bot-classify: verdict=%s endpoint=%s score=%s fp=%s "
                    "reasons=%s ip=%s ua=%s",
                    (
                        "THROTTLED"
                        if bot_limited
                        else (
                            "FLAG_ALLOWED" if BOT_ENFORCEMENT_ENABLED else "SHADOW_FLAG"
                        )
                    ),
                    endpoint,
                    bot["score"],
                    fingerprint,
                    ",".join(bot["reasons"]) or "-",
                    client_ip,
                    request.headers.get("User-Agent"),
                )
                if bot_limited:
                    await _discard_window_member(redis_conn, key, member)
                    raise HTTPException(
                        status_code=HTTP_429_TOO_MANY_REQUESTS,
                        detail={
                            "error": "Rate limit exceeded",
                            "detail": (
                                "Automated access detected. Please slow down or "
                                "use an API plan: "
                                "https://plus.xposedornot.com/products/api"
                            ),
                            "retry_after": bot_retry,
                        },
                        headers={"Retry-After": str(bot_retry)},
                    )

            drop_percentage = get_drop_percentage(violation_count)

            if random.random() < drop_percentage:
                await _discard_window_member(redis_conn, key, member)

                raise HTTPException(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Request dropped due to violation history",
                        "violation_count": violation_count,
                        "drop_percentage": f"{drop_percentage * 100:.0f}%",
                        "detail": (
                            f"Request dropped due to {violation_count} previous violations. "
                            "Please reduce your request rate."
                        ),
                    },
                    headers={
                        "X-Dropped": "true",
                        "X-Violation-Count": str(violation_count),
                        "X-Drop-Percentage": f"{drop_percentage * 100:.0f}%",
                    },
                )

            limited, retry_after = False, 0
            for i, (limit, period) in enumerate(rate_limits):
                if request_counts and request_counts[i] > limit:
                    retry = await _oldest_retry_after(
                        redis_conn, key, request_counts[i], period, now
                    )
                    if retry is not None:
                        limited, retry_after = True, retry
                    break
            if limited:
                await increment_violation(client_ip, redis_conn)

                if endpoint in CF_ESCALATION_ENDPOINTS:
                    escalated = await escalate_day_limit_abuse(
                        client_ip, endpoint, redis_conn
                    )
                    if escalated:
                        raise HTTPException(
                            status_code=HTTP_403_FORBIDDEN,
                            detail={
                                "error": "Access blocked",
                                "detail": (
                                    "Rate limit repeatedly exceeded. "
                                    "Access is blocked for 24 hours."
                                ),
                            },
                        )

                reset_time = datetime.now() + timedelta(seconds=retry_after)

                error_detail = {
                    "error": "Rate limit exceeded",
                    "detail": (
                        f"Rate limit exceeded for endpoint {endpoint}. "
                        f"Please try again after {retry_after} seconds."
                    ),
                    "retry_after": retry_after,
                    "reset_time": reset_time.isoformat(),
                }

                if message:
                    error_detail["message"] = message

                raise HTTPException(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    detail=error_detail,
                    headers={"Retry-After": str(retry_after)},
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator
