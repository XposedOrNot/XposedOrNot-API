import time
import redis.asyncio as redis
import random
from functools import wraps
from typing import Callable, Dict, List, Tuple, Optional
from fastapi import Request, HTTPException
from starlette.status import HTTP_429_TOO_MANY_REQUESTS
from datetime import datetime, timedelta

from config.settings import REDIS_URL
from utils.helpers import get_client_ip

redis_pool = redis.from_url(
    REDIS_URL,
    encoding="utf-8",
    decode_responses=True,
    socket_keepalive=True,
    socket_keepalive_options={},
    retry_on_timeout=True,
    health_check_interval=30,
    max_connections=20,
    retry_on_error=[redis.ConnectionError, redis.TimeoutError],
)


async def get_healthy_redis_connection():
    """
    Get a healthy Redis connection with automatic reconnection.
    """
    global redis_pool
    max_retries = 3
    retry_delay = 0.1

    for attempt in range(max_retries):
        try:
            await redis_pool.ping()
            return redis_pool
        except Exception as e:
            if attempt < max_retries - 1:
                try:
                    await redis_pool.close()
                    redis_pool = redis.from_url(
                        REDIS_URL,
                        encoding="utf-8",
                        decode_responses=True,
                        socket_keepalive=True,
                        socket_keepalive_options={},
                        retry_on_timeout=True,
                        health_check_interval=30,
                        max_connections=20,
                        retry_on_error=[redis.ConnectionError, redis.TimeoutError],
                    )
                    await redis_pool.ping()
                    return redis_pool
                except Exception as reconnect_error:
                    if attempt < max_retries - 1:
                        import asyncio

                        try:
                            await asyncio.sleep(retry_delay)
                        except asyncio.CancelledError:
                            break
                        retry_delay *= 2
                    continue

    return redis_pool


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
) -> Tuple[bool, int]:
    """
    Checks if a given key has exceeded any of the specified rate limits using Redis.
    Returns a tuple of (is_limited, retry_after_seconds).
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
                    return True, max(1, retry_after)

                return True, period

        return False, 0
    except Exception as e:
        return False, 0


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
        await redis_conn.zadd(violation_key, {str(now): now})
        await redis_conn.expire(violation_key, 7200)
    except Exception as e:
        pass


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

            violation_count = await get_violation_count(client_ip, redis_conn)
            drop_percentage = get_drop_percentage(violation_count)

            if random.random() < drop_percentage:

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

            limited, retry_after = await is_rate_limited(key, rate_limits, redis_conn)
            if limited:
                await increment_violation(client_ip, redis_conn)

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
