import time
import redis.asyncio as redis
import random
from functools import wraps
from typing import Callable, Dict, List, Tuple
from fastapi import Request, HTTPException
from starlette.status import HTTP_429_TOO_MANY_REQUESTS
from datetime import datetime, timedelta

from config.settings import REDIS_URL
from utils.helpers import get_client_ip


redis_pool = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)


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
    key: str, rate_limits: List[Tuple[int, int]], redis_conn: redis.Redis
) -> Tuple[bool, int]:
    """
    Checks if a given key has exceeded any of the specified rate limits using Redis.
    Returns a tuple of (is_limited, retry_after_seconds).
    """
    now = time.time()

    async with redis_conn.pipeline(transaction=True) as pipe:
        pipe.zadd(key, {str(now): now})
        max_period = max(limit[1] for limit in rate_limits) if rate_limits else 86400
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

            return True, period  # Fallback

    return False, 0


async def get_violation_count(client_ip: str, redis_conn: redis.Redis) -> int:
    """
    Get the number of rate limit violations for a client IP in the last hour.
    """
    violation_key = f"violations:{client_ip}"
    now = time.time()

    # Remove violations older than 1 hour
    await redis_conn.zremrangebyscore(violation_key, 0, now - 3600)

    # Count violations in the last hour
    count = await redis_conn.zcard(violation_key)
    return count


async def increment_violation(client_ip: str, redis_conn: redis.Redis):
    """
    Increment the violation count for a client IP.
    """
    violation_key = f"violations:{client_ip}"
    now = time.time()

    # Add current violation timestamp
    await redis_conn.zadd(violation_key, {str(now): now})

    # Set expiry to 2 hours (1 hour for tracking + 1 hour buffer)
    await redis_conn.expire(violation_key, 7200)


def get_drop_percentage(violation_count: int) -> float:
    """
    Determine the percentage of requests to drop based on violation count.
    """
    if violation_count <= 3:
        return 0.0  # No dropping
    elif violation_count <= 6:
        return 0.5  # Drop 50%
    elif violation_count <= 10:
        return 0.8  # Drop 80%
    else:
        return 0.95  # Drop 95%


def custom_rate_limiter(rate_limit_str: str):
    """
    A decorator for FastAPI routes to enforce custom rate limiting with request dropping.

    Args:
        rate_limit_str: A string defining the limits, e.g.,
                        "2 per second;5 per hour;100 per day"
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

            # Check violation count and determine drop percentage
            violation_count = await get_violation_count(client_ip, redis_pool)
            drop_percentage = get_drop_percentage(violation_count)

            # Random drop decision
            if random.random() < drop_percentage:

                raise HTTPException(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Request dropped due to violation history",
                        "violation_count": violation_count,
                        "drop_percentage": f"{drop_percentage * 100:.0f}%",
                        "detail": f"Request dropped due to {violation_count} previous violations. Please reduce your request rate.",
                    },
                    headers={
                        "X-Dropped": "true",
                        "X-Violation-Count": str(violation_count),
                        "X-Drop-Percentage": f"{drop_percentage * 100:.0f}%",
                    },
                )

            # Continue with normal rate limiting
            limited, retry_after = await is_rate_limited(key, rate_limits, redis_pool)
            if limited:
                # Increment violation count when rate limit is exceeded
                await increment_violation(client_ip, redis_pool)

                reset_time = datetime.now() + timedelta(seconds=retry_after)
                raise HTTPException(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Rate limit exceeded",
                        "detail": f"Rate limit exceeded for endpoint {endpoint}. Please try again after {retry_after} seconds.",
                        "retry_after": retry_after,
                        "reset_time": reset_time.isoformat(),
                    },
                    headers={"Retry-After": str(retry_after)},
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator
