import time
import redis.asyncio as redis
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


def custom_rate_limiter(rate_limit_str: str):
    """
    A decorator for FastAPI routes to enforce custom rate limiting.

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

            limited, retry_after = await is_rate_limited(key, rate_limits, redis_pool)
            if limited:
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
