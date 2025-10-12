"""Monthly digest endpoint for sending breach summaries to validated domain users."""

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import redis
from fastapi import APIRouter, HTTPException, Query, Request
from google.cloud.datastore import Client

from models.responses import MonthlyDigestResponse
from utils.custom_limiter import custom_rate_limiter
from utils.token import generate_confirmation_token
from config.settings import (
    REDIS_HOST,
    REDIS_PORT,
    REDIS_DB,
    REDIS_PASSWORD,
    CF_UNBLOCK_MAGIC,
    ENVIRONMENT,
    DEBUG_EMAIL,
)

from .monthly_digest_helpers import (
    heartbeat_logger,
    prefetch_breach_data,
    batch_create_sessions,
    generate_monthly_digest_html_optimized,
)

# Email constants from send_email service
FROM_EMAIL = "notifications@xposedornot.com"
FROM_NAME = "XposedOrNot Notifications"
MAILJET_API_URL = "https://api.mailjet.com/v3.1/send"
API_KEY = os.environ.get("MJ_API_KEY")
API_SECRET = os.environ.get("MJ_API_SECRET")

router = APIRouter()
logger = logging.getLogger(__name__)

# Redis client for background tasks using environment variables
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    password=REDIS_PASSWORD,
    decode_responses=True,
)


async def process_single_email_optimized(
    email: str,
    email_index: int,
    total_emails: int,
    batch_num: int,
    user_domains: list,
    dashboard_token: str,
    all_breach_data: dict,
    client,
) -> dict:
    """Optimized single email processing with pre-fetched data."""
    try:
        # Generate HTML content with pre-fetched data (much faster)
        html_content = await generate_monthly_digest_html_optimized(
            email, dashboard_token, user_domains, all_breach_data, client
        )

        current_month = datetime.now(timezone.utc).strftime("%B")

        # Environment-specific email logic
        if ENVIRONMENT in ["dev", "test"]:
            # Development/test: send to debug email from environment variable
            send_to_email = DEBUG_EMAIL
        else:
            # Production: send to actual user email
            send_to_email = email

        data = {
            "Messages": [
                {
                    "From": {"Email": FROM_EMAIL, "Name": FROM_NAME},
                    "To": [{"Email": send_to_email, "Name": "User"}],
                    "Subject": (
                        f"🚨 New breaches detected — check your exposure "
                        f"({current_month} update)"
                    ),
                    "HTMLPart": html_content,
                    "TextPart": (
                        f"XposedOrNot Monthly Digest - Visit https://xposedornot.com "
                        f"to view your breach report for {email}"
                    ),
                }
            ]
        }

        try:
            async with httpx.AsyncClient() as http_client:
                response = await http_client.post(
                    MAILJET_API_URL, json=data, auth=(API_KEY, API_SECRET), timeout=30.0
                )

                if response.status_code == 200:
                    logger.info(
                        f"[MONTHLY-DIGEST] ✅ Email sent: {email_index}/{total_emails} ({email})"
                    )
                    return {"email": email, "status": "success", "type": "sent"}
                else:
                    error_msg = f"Mailjet API error: HTTP {response.status_code}"
                    logger.error(
                        f"[MONTHLY-DIGEST] ❌ API error for {email}: {error_msg}"
                    )
                    return {
                        "email": email,
                        "status": "error",
                        "type": "api_error",
                        "error": error_msg,
                    }

        except Exception as e:
            error_msg = f"Email sending error: {str(e)}"
            logger.error(f"[MONTHLY-DIGEST] ❌ Send error for {email}: {error_msg}")
            return {
                "email": email,
                "status": "error",
                "type": "send_error",
                "error": error_msg,
            }

    except Exception as e:
        error_msg = f"HTML generation error: {str(e)}"
        logger.error(f"[MONTHLY-DIGEST] ❌ HTML error for {email}: {error_msg}")
        return {
            "email": email,
            "status": "error",
            "type": "html_error",
            "error": error_msg,
        }


async def process_monthly_digest_for_all_users():
    """
    Internal function to process monthly digest for all verified domain users.
    Optimized with batch datastore operations and performance monitoring.
    """
    start_time = time.time()
    heartbeat_task = None

    try:
        # Start heartbeat to keep container alive
        heartbeat_task = asyncio.create_task(heartbeat_logger())
        logger.info(
            f"[MONTHLY-DIGEST] 🚀 STARTED - Processing began at "
            f"{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}"
        )

        # Get all verified domains with optimized batch operations
        client = Client()

        # PERFORMANCE: Single query for all verified domains
        perf_start = time.time()
        query = client.query(kind="xon_domains")
        query.add_filter("verified", "=", True)
        verified_domains = list(query.fetch(limit=1000))
        logger.info(
            f"[MONTHLY-DIGEST] 📊 PERF: Domain query took {time.time() - perf_start:.2f}s - "
            f"Found {len(verified_domains)} domains"
        )

        if not verified_domains:
            logger.info("[MONTHLY-DIGEST] No verified domains found")
            return {
                "status": "success",
                "message": "No verified domains found",
                "emails_sent": 0,
            }

        email_to_domains = {}
        unique_emails = set()
        skipped_custid_domains = 0
        for domain in verified_domains:
            if domain.get("custid"):
                skipped_custid_domains += 1
                logger.debug(
                    f"[MONTHLY-DIGEST] 🔍 CUSTID SKIP: Skipping domain "
                    f"'{domain.get('domain')}' for '{domain.get('email')}' - "
                    f"has custid: {domain.get('custid')}"
                )
                continue

            email = domain.get("email")
            if email:
                email = email.lower().strip()
                unique_emails.add(email)
                if email not in email_to_domains:
                    email_to_domains[email] = []
                email_to_domains[email].append(domain["domain"])

        unique_emails_list = list(unique_emails)
        processed_domains = len(verified_domains) - skipped_custid_domains
        logger.info(
            f"[MONTHLY-DIGEST] 📊 DATA PREP: {len(unique_emails_list)} unique emails, "
            f"{processed_domains} processed domains (skipped {skipped_custid_domains} "
            f"custid domains from {len(verified_domains)} total)"
        )

        # Check if all domains were skipped due to custid
        if not unique_emails_list:
            logger.info(
                "[MONTHLY-DIGEST] All domains skipped due to custid - no digest emails to send"
            )
            return {
                "status": "success",
                "message": (
                    f"All {len(verified_domains)} verified domains have custid - "
                    f"skipped digest"
                ),
                "emails_sent": 0,
                "skipped_custid_domains": skipped_custid_domains,
                "total_verified_domains": len(verified_domains),
            }

        perf_start = time.time()
        all_breach_data = await prefetch_breach_data(client)
        logger.info(
            f"[MONTHLY-DIGEST] 📊 PERF: Breach prefetch took "
            f"{time.time() - perf_start:.2f}s - {len(all_breach_data)} breaches"
        )

        perf_start = time.time()
        email_tokens = {}
        for email in unique_emails_list:
            email_tokens[email] = await generate_confirmation_token(email)
        logger.info(
            f"[MONTHLY-DIGEST] 📊 PERF: Token generation took {time.time() - perf_start:.2f}s"
        )

        await batch_create_sessions(client, email_tokens)

        # Process emails with optimized batching
        emails_sent = 0
        html_generation_errors = 0
        email_sending_errors = 0
        detailed_errors = []

        batch_size = 10
        total_batches = (len(unique_emails_list) + batch_size - 1) // batch_size

        logger.info(
            f"[MONTHLY-DIGEST] 🔄 BATCH PROCESSING: {len(unique_emails_list)} "
            f"emails in {total_batches} batches"
        )

        for batch_num in range(total_batches):
            batch_start_time = time.time()
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(unique_emails_list))
            batch_emails = unique_emails_list[start_idx:end_idx]

            logger.info(
                f"[MONTHLY-DIGEST] 📦 BATCH {batch_num + 1}/{total_batches}: "
                f"Processing emails {start_idx + 1}-{end_idx}"
            )

            # Create optimized batch tasks with pre-fetched data
            batch_tasks = []
            for i, email in enumerate(batch_emails, start_idx + 1):
                user_domains = email_to_domains.get(email, [])
                dashboard_token = email_tokens[email]
                task = process_single_email_optimized(
                    email,
                    i,
                    len(unique_emails_list),
                    batch_num + 1,
                    user_domains,
                    dashboard_token,
                    all_breach_data,
                    client,
                )
                batch_tasks.append(task)

            # Execute batch concurrently
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

            # Process results
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"[MONTHLY-DIGEST] ❌ Batch task failed: {result}")
                    detailed_errors.append(
                        {"email": "unknown", "type": "task_error", "error": str(result)}
                    )
                elif isinstance(result, dict):
                    if result["status"] == "success":
                        emails_sent += 1
                    else:
                        if result["type"] == "html_error":
                            html_generation_errors += 1
                        else:
                            email_sending_errors += 1
                        detailed_errors.append(result)

            batch_duration = time.time() - batch_start_time
            logger.info(
                f"[MONTHLY-DIGEST] ✅ BATCH {batch_num + 1} COMPLETED in "
                f"{batch_duration:.2f}s - Progress: {emails_sent}/{len(unique_emails_list)}"
            )

            # Brief pause between batches to prevent overwhelming
            if batch_num < total_batches - 1:
                await asyncio.sleep(1)  # Reduced to 1 second

        # Calculate totals and performance metrics
        total_duration = time.time() - start_time
        total_errors = html_generation_errors + email_sending_errors
        success_rate = (
            (emails_sent / len(unique_emails_list) * 100) if unique_emails_list else 0
        )

        result = {
            "status": "success",
            "message": f"Monthly digest processing complete",
            "emails_sent": emails_sent,
            "total_unique_emails": len(unique_emails_list),
            "html_generation_errors": html_generation_errors,
            "email_sending_errors": email_sending_errors,
            "total_errors": total_errors,
            "success_rate": round(success_rate, 2),
            "processing_time_seconds": round(total_duration, 2),
            "emails_per_minute": round(
                (emails_sent / (total_duration / 60)) if total_duration > 0 else 0, 2
            ),
            "detailed_errors": detailed_errors[:10] if detailed_errors else [],
            "skipped_custid_domains": skipped_custid_domains,
            "total_verified_domains": len(verified_domains),
        }

        logger.info(
            f"[MONTHLY-DIGEST] 🏁 FINAL SUMMARY - Duration: {total_duration:.2f}s "
            f"({total_duration/60:.1f}min)"
        )
        logger.info(
            f"[MONTHLY-DIGEST] ✅ Emails sent: {emails_sent}/{len(unique_emails_list)} "
            f"({success_rate:.1f}%)"
        )
        logger.info(
            f"[MONTHLY-DIGEST] 📊 Performance: {result['emails_per_minute']:.1f} emails/min"
        )
        logger.info(
            f"[MONTHLY-DIGEST] ❌ Errors: HTML={html_generation_errors}, "
            f"Email={email_sending_errors}"
        )
        logger.info(
            f"[MONTHLY-DIGEST] 🔍 Filtering: {skipped_custid_domains} custid "
            f"domains skipped from {len(verified_domains)} total"
        )

        if detailed_errors:
            logger.error(f"[MONTHLY-DIGEST] ⚠️ {len(detailed_errors)} errors occurred:")
            for error in detailed_errors[:3]:  # Log first 3 errors
                logger.error(
                    (
                        f"[MONTHLY-DIGEST] - {error.get('email', 'unknown')}: "
                        f"{error.get('error', 'unknown')[:80]}..."
                    )
                )

        return result

    except Exception as e:
        total_duration = time.time() - start_time
        error_msg = (
            f"Monthly digest processing failed after {total_duration:.2f}s: {str(e)}"
        )
        logger.error(f"[MONTHLY-DIGEST] ❌ CRITICAL FAILURE: {error_msg}")
        import traceback

        logger.error(f"[MONTHLY-DIGEST] ❌ Traceback: {traceback.format_exc()}")
        raise Exception(error_msg)
    finally:
        # Stop heartbeat task safely
        if heartbeat_task and not heartbeat_task.done():
            try:
                heartbeat_task.cancel()
                # Wait for graceful cancellation
                await asyncio.wait_for(heartbeat_task, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                # Expected when cancelling
                pass
            except Exception as e:
                logger.warning(
                    f"[MONTHLY-DIGEST] ⚠️ Heartbeat cleanup warning: {str(e)}"
                )

        total_duration = time.time() - start_time
        logger.info(
            f"[MONTHLY-DIGEST] 🔚 CLEANUP COMPLETED - Total session duration: {total_duration:.2f}s"
        )


@router.get("/debug/redis-state")
@custom_rate_limiter(
    "5 per minute;20 per hour", message="Debug endpoints are rate limited"
)
async def debug_redis_state(
    request: Request,  # pylint: disable=unused-argument
    token: Optional[str] = Query(None, description="Authentication token"),
):
    """Debug endpoint to check monthly digest Redis state."""
    # Check magic token for authentication
    if not token or token != CF_UNBLOCK_MAGIC:
        raise HTTPException(status_code=404, detail="Not found")
    if not redis_client:
        return {"error": "Redis not available"}

    try:
        last_run_key = f"{ENVIRONMENT}_monthly_digest_last_run"
        last_run = redis_client.get(last_run_key)
        ttl = redis_client.ttl(last_run_key)
        current_month = datetime.now(timezone.utc).strftime("%Y-%m")

        return {
            "redis_key": last_run_key,
            "value": last_run,
            "ttl_seconds": ttl,
            "ttl_human": f"{ttl//3600}h {(ttl%3600)//60}m" if ttl > 0 else "N/A",
            "key_exists": ttl != -2,
            "current_month": current_month,
            "is_blocked": (
                last_run and last_run.startswith(current_month) if last_run else False
            ),
        }
    except Exception as e:
        return {"error": str(e)}


@router.post("/debug/redis-clear")
@custom_rate_limiter(
    "2 per minute;10 per hour", message="Redis clear endpoint is rate limited"
)
async def debug_clear_redis(
    request: Request,  # pylint: disable=unused-argument
    token: Optional[str] = Query(None, description="Authentication token"),
):
    """Debug endpoint to clear monthly digest Redis state."""
    # Check magic token for authentication
    if not token or token != CF_UNBLOCK_MAGIC:
        raise HTTPException(status_code=404, detail="Not found")
    if not redis_client:
        return {"error": "Redis not available"}

    try:
        last_run_key = f"{ENVIRONMENT}_monthly_digest_last_run"
        running_task_key = f"{ENVIRONMENT}_monthly_digest_task_running"
        scheduler_lock_key = f"{ENVIRONMENT}_global_scheduler_instance_lock"

        # Clear all digest-related keys
        result1 = redis_client.delete(last_run_key)
        result2 = redis_client.delete(running_task_key)
        result3 = redis_client.delete(scheduler_lock_key)

        return {
            "cleared": {
                "last_run_key": bool(result1),
                "running_task_key": bool(result2),
                "scheduler_lock_key": bool(result3),
            },
            "message": "All Redis locks cleared for testing - scheduler instances can now start",
        }
    except Exception as e:
        return {"error": str(e)}


@router.post("/trigger-manual", response_model=MonthlyDigestResponse)
@custom_rate_limiter(
    "1 per 10 minutes;3 per hour;5 per day",
    message="Monthly digest trigger is heavily rate limited for security",
)
async def trigger_manual_monthly_digest(
    request: Request,  # pylint: disable=unused-argument
    token: Optional[str] = Query(None, description="Authentication token"),
    target_email: Optional[str] = Query(
        None, description="Target email for manual testing"
    ),
):
    """
    Manual trigger for monthly digest.
    """
    try:
        # Check magic token for authentication
        if not token or token != CF_UNBLOCK_MAGIC:
            raise HTTPException(status_code=404, detail="Not found")

        logger.info(
            f"Manual monthly digest trigger requested - target: {target_email or 'all users'}"
        )

        result = await process_monthly_digest_for_all_users()

        # Update Redis state after successful execution
        if result and result.get("status") == "success" and redis_client:
            try:

                now = datetime.now(timezone.utc)

                # Calculate TTL to last until next month's first Tuesday + buffer
                current_month = now.replace(day=1)
                next_month = (current_month + timedelta(days=32)).replace(day=1)

                # Find next month's first Tuesday (weekday 1)
                days_to_next_first_tue = (1 - next_month.weekday()) % 7
                next_first_tuesday = next_month + timedelta(days=days_to_next_first_tue)

                # TTL until 3 days after next month's first Tuesday
                ttl_until = next_first_tuesday + timedelta(days=3)
                ttl_seconds = int((ttl_until - now).total_seconds())

                # Ensure TTL is positive (minimum 1 day)
                if ttl_seconds <= 0:
                    ttl_seconds = 86400  # 1 day fallback

                # Store success timestamp with calculated TTL
                last_run_key = f"{ENVIRONMENT}_monthly_digest_last_run"
                full_timestamp = now.strftime("%Y-%m-%d %H:%M:%S UTC")
                redis_client.setex(last_run_key, ttl_seconds, full_timestamp)

                logger.info(
                    f"✅ MANUAL TRIGGER: Updated Redis state - '{last_run_key}' = '{full_timestamp}'"
                )
                logger.info(
                    (
                        f"✅ TTL: {ttl_seconds} seconds "
                        f"(expires: {ttl_until.strftime('%Y-%m-%d %H:%M:%S UTC')})"
                    )
                )

            except Exception as redis_error:
                logger.error(
                    f"❌ MANUAL TRIGGER: Failed to update Redis state: {str(redis_error)}"
                )

        task_id = f"manual_{int(datetime.now(timezone.utc).timestamp())}"

        return MonthlyDigestResponse(
            status="success",
            message="Manual monthly digest triggered successfully",
            task_id=task_id,
            trigger_type="manual",
            target_email=target_email,
            testing_mode=True,  # Always testing mode for manual triggers
        )

    except Exception as e:
        logger.error(f"Manual monthly digest trigger failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
