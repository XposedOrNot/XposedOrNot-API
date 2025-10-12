"""Scheduler service for automated tasks like monthly digest."""

import asyncio
import logging
import os
import socket
import threading
import time
import traceback
from datetime import datetime, timezone, timedelta
from typing import Optional

import redis
import schedule

# from concurrent.futures import ThreadPoolExecutor  # No longer needed

logger = logging.getLogger(__name__)

# Redis client for tracking last run times
try:
    from config.settings import (
        REDIS_HOST,
        REDIS_PORT,
        REDIS_DB,
        REDIS_PASSWORD,
        ENVIRONMENT,
    )
    from api.v1.monthly_digest import process_monthly_digest_for_all_users

    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        decode_responses=True,
    )
    logger.info("📊 SCHEDULER: Redis client initialized for last-run tracking")
except Exception as e:
    logger.error(f"📊 SCHEDULER: Failed to initialize Redis client: {str(e)}")
    redis_client = None


class SchedulerService:
    """Service for managing scheduled tasks."""

    def __init__(self):
        self.is_running = False
        self.scheduler_thread: Optional[threading.Thread] = None

    def schedule_monthly_digest(self):
        """Schedule monthly digest to run at 09:00 UTC on first Tuesday of every month."""
        # Primary trigger at 09:00 UTC on first Tuesday - wrap async function
        # TEMPORARILY COMMENTED OUT FOR MANUAL TESTING
        # schedule.every().day.at("09:00").do(self._run_async_trigger)

        logger.info(
            f"📅 SCHEDULER STARTED: Monthly digest scheduled for 09:00 UTC on "
            f"first Tuesday of month (Environment: {ENVIRONMENT})"
        )
        logger.info(
            f"📅 SCHEDULER: Current UTC time is "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )

        # Test the first Tuesday logic immediately
        test_date = datetime.now(timezone.utc)
        is_first_tuesday = self._is_first_tuesday_of_month(test_date)
        logger.info(
            f"📅 SCHEDULER: Today ({test_date.strftime('%A %Y-%m-%d')}) "
            f"is first Tuesday: {is_first_tuesday}"
        )

    def _is_first_tuesday_of_month(self, date):
        """Check if given date is first Tuesday of the month."""
        # Ensure we're working with UTC timezone
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)

        # Find first day of the month
        first_day = date.replace(day=1)
        logger.debug(
            f"📅 FIRST_TUESDAY_CHECK: First day of month: "
            f"{first_day.strftime('%A %Y-%m-%d')} (weekday: {first_day.weekday()})"
        )

        # Tuesday is weekday 1 (Monday=0, Tuesday=1, Wednesday=2,
        # Thursday=3, Friday=4, Saturday=5, Sunday=6)
        days_to_first_tuesday = (1 - first_day.weekday()) % 7
        first_tuesday = first_day + timedelta(days=days_to_first_tuesday)

        logger.debug(
            f"📅 FIRST_TUESDAY_CHECK: Calculated first Tuesday: "
            f"{first_tuesday.strftime('%A %Y-%m-%d')}"
        )
        logger.debug(
            f"📅 FIRST_TUESDAY_CHECK: Checking date: {date.strftime('%A %Y-%m-%d')}"
        )

        result = date.date() == first_tuesday.date()
        logger.debug(f"📅 FIRST_TUESDAY_CHECK: Result: {result}")

        return result

    def _run_async_trigger(self):
        """Wrapper to run async trigger function in sync context."""
        try:
            asyncio.run(self._trigger_monthly_digest_job())
        except Exception as e:
            logger.error(f"🚀 ASYNC_WRAPPER: ❌ Error running async trigger: {str(e)}")

    async def _trigger_monthly_digest_job(self):
        """Trigger the monthly digest job."""
        try:
            # Always use UTC timezone for consistency
            now = datetime.now(timezone.utc)
            logger.info(
                f"🚀 DIGEST_TRIGGER: Checking monthly digest trigger at "
                f"{now.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )
            logger.info(f"🚀 DIGEST_TRIGGER: Today is {now.strftime('%A %B %d, %Y')}")

            # Test the first Tuesday condition
            is_first_tuesday = self._is_first_tuesday_of_month(now)
            logger.info(
                f"🚀 DIGEST_TRIGGER: First Tuesday test result: {is_first_tuesday}"
            )

            if not is_first_tuesday:
                logger.info(
                    f"🚀 DIGEST_TRIGGER: ❌ CONDITIONS NOT MET - Today is not the "
                    f"first Tuesday of the month"
                )
                logger.info(
                    f"🚀 DIGEST_TRIGGER: Waiting for first Tuesday. Current day: "
                    f"{now.strftime('%A %d')}"
                )
                return

            logger.info(
                f"🚀 DIGEST_TRIGGER: ✅ CONDITIONS MET - Today IS the first "
                f"Tuesday of the month!"
            )

            # ENHANCED: Check if we already sent THIS MONTH (not just today)
            last_run_key = f"{ENVIRONMENT}_monthly_digest_last_run"
            current_month = now.strftime("%Y-%m")  # e.g., "2024-09"

            if redis_client:
                try:
                    last_run = redis_client.get(last_run_key)
                    if last_run and last_run.startswith(current_month):
                        logger.info(
                            f"🚀 DIGEST_TRIGGER: ❌ ALREADY TRIGGERED - Monthly digest "
                            f"already sent this month ({current_month}) in {ENVIRONMENT} "
                            f"environment"
                        )
                        logger.info(
                            f"🚀 DIGEST_TRIGGER: Last run ({ENVIRONMENT}): {last_run}"
                        )
                        return
                    else:
                        logger.info(
                            f"🚀 DIGEST_TRIGGER: ✅ NEW MONTH - Last run ({ENVIRONMENT}) "
                            f"was: {last_run or 'never'}, proceeding..."
                        )
                except Exception as e:
                    logger.error(
                        f"🚀 DIGEST_TRIGGER: ⚠️ Redis check failed: {str(e)}, "
                        f"proceeding anyway..."
                    )
            else:
                logger.warning(
                    "🚀 DIGEST_TRIGGER: ⚠️ Redis client not available, "
                    "skipping duplicate check"
                )

            logger.info(
                "🚀 DIGEST_TRIGGER: ✅ FUNCTION CALLED - Triggering monthly digest "
                "for all validated users"
            )

            # Check if a digest task is already running with atomic Redis operation
            running_task_key = f"{ENVIRONMENT}_monthly_digest_task_running"
            if redis_client:
                try:
                    task_start_time = now.strftime("%Y-%m-%d %H:%M:%S UTC")
                    # Use atomic SET NX EX operation to prevent race conditions
                    # Only sets the key if it doesn't exist, with 30-minute expiry
                    # (reduced from 2 hours)
                    was_set = redis_client.set(
                        running_task_key, task_start_time, nx=True, ex=1800
                    )

                    if not was_set:
                        # Task is already running, get the start time for logging
                        existing_task = redis_client.get(running_task_key)
                        logger.warning(
                            f"🚀 DIGEST_TRIGGER: ⚠️ TASK ALREADY RUNNING - Another "
                            f"digest task is in progress (started: {existing_task})"
                        )
                        return
                    else:
                        logger.info(
                            f"🚀 DIGEST_TRIGGER: 🔄 TASK STARTED - Atomically marked "
                            f"digest task as running: {task_start_time}"
                        )
                except Exception as e:
                    logger.error(
                        f"🚀 DIGEST_TRIGGER: ⚠️ Failed to atomically check/set "
                        f"running task Redis key: {str(e)}, aborting to prevent "
                        f"duplicates"
                    )
                    return  # Don't proceed if Redis operations fail, to prevent duplicates

            # Use direct function call for identical execution context
            logger.info(
                "🚀 DIGEST_TRIGGER: 🔄 CALLING MANUAL TRIGGER DIRECTLY - "
                "Using identical execution context"
            )

            # Call manual trigger function directly for consistent performance
            result = await self._call_manual_trigger_directly()

            logger.info(
                "🚀 DIGEST_TRIGGER: ✅ DIGEST COMPLETED - Monthly digest processing finished"
            )

            # Process direct call response and update Redis state
            if result and redis_client:
                try:
                    # Direct call response should contain status info
                    logger.info(f"🚀 DIGEST_TRIGGER: 📊 DIRECT RESPONSE - {result}")

                    # If direct call was successful, check the actual digest results
                    if result.get("status") == "success":
                        # Calculate TTL to last until next month's first Thursday + buffer
                        end_time = datetime.now(timezone.utc)
                        current_month = end_time.replace(day=1)
                        next_month = (current_month + timedelta(days=32)).replace(day=1)

                        # Find next month's first Tuesday
                        days_to_next_first_tue = (1 - next_month.weekday()) % 7
                        next_first_tuesday = next_month + timedelta(
                            days=days_to_next_first_tue
                        )

                        # TTL until 3 days after next month's first Tuesday
                        ttl_until = next_first_tuesday + timedelta(days=3)
                        ttl_seconds = int((ttl_until - end_time).total_seconds())

                        # Ensure TTL is positive (minimum 1 day)
                        if ttl_seconds <= 0:
                            ttl_seconds = 86400  # 1 day fallback
                            logger.warning(
                                "🚀 DIGEST_TRIGGER: TTL calculation negative, using 1 day fallback"
                            )

                        # Store success timestamp with calculated TTL
                        last_run_key = f"{ENVIRONMENT}_monthly_digest_last_run"
                        full_timestamp = end_time.strftime("%Y-%m-%d %H:%M:%S UTC")
                        redis_client.setex(last_run_key, ttl_seconds, full_timestamp)

                        logger.info(
                            f"🚀 DIGEST_TRIGGER: ✅ SUCCESS REDIS UPDATED - HTTP trigger "
                            f"successful, set '{last_run_key}' = '{full_timestamp}'"
                        )
                        logger.info(
                            f"🚀 DIGEST_TRIGGER: ✅ TTL: {ttl_seconds} seconds "
                            f"(expires: {ttl_until.strftime('%Y-%m-%d %H:%M:%S UTC')})"
                        )
                    else:
                        logger.warning(
                            f"🚀 DIGEST_TRIGGER: ⚠️ SUCCESS REDIS NOT UPDATED - "
                            f"Direct call failed or returned error"
                        )
                except Exception as redis_error:
                    logger.error(
                        (
                            "🚀 DIGEST_TRIGGER: ❌ Failed to update success Redis state: "
                            f"{str(redis_error)}"
                        )
                    )

            # Always clear the running task key when done (success or failure)
            if redis_client:
                try:
                    running_task_key = f"{ENVIRONMENT}_monthly_digest_task_running"
                    redis_client.delete(running_task_key)
                    logger.info(
                        "🚀 DIGEST_TRIGGER: 🧹 CLEANUP - Cleared running task key"
                    )
                except Exception as cleanup_error:
                    logger.error(
                        (
                            "🚀 DIGEST_TRIGGER: ⚠️ Failed to clear running task key: "
                            f"{str(cleanup_error)}"
                        )
                    )

        except Exception as e:
            logger.error(
                f"🚀 DIGEST_TRIGGER: ❌ FUNCTION FAILED - Error triggering "
                f"monthly digest: {str(e)}"
            )
            logger.error(f"🚀 DIGEST_TRIGGER: ❌ Exception type: {type(e).__name__}")

            logger.error(
                f"🚀 DIGEST_TRIGGER: ❌ Full traceback: {traceback.format_exc()}"
            )

            # Ensure cleanup happens even on exception
            if redis_client:
                try:
                    running_task_key = f"{ENVIRONMENT}_monthly_digest_task_running"
                    redis_client.delete(running_task_key)
                    logger.info(
                        "🚀 DIGEST_TRIGGER: 🧹 CLEANUP (EXCEPTION) - Cleared running task key"
                    )
                except Exception as cleanup_error:
                    logger.error(
                        (
                            "🚀 DIGEST_TRIGGER: ⚠️ Failed to clear running task key "
                            f"in exception handler: {str(cleanup_error)}"
                        )
                    )

    async def _call_manual_trigger_directly(self):
        """Call manual trigger function directly for identical execution context."""
        try:
            logger.info("🚀 DIRECT_TRIGGER: Making direct function call")

            # Import and call the processing function directly
            from api.v1.monthly_digest import process_monthly_digest_for_all_users

            # Run the async function directly
            result = await process_monthly_digest_for_all_users()

            if result and result.get("status") == "success":
                logger.info(
                    "🚀 DIRECT_TRIGGER: ✅ Manual trigger via direct call successful"
                )
                return {"status": "success", "data": result}

            logger.error(
                "🚀 DIRECT_TRIGGER: ❌ Direct call returned error or no result"
            )
            return {"status": "error", "data": result}

        except Exception as e:
            logger.error(
                f"🚀 DIRECT_TRIGGER: ❌ Exception during direct call: {str(e)}"
            )
            return {"status": "error", "error": str(e)}

    # LEGACY - COMMENTED OUT - Complex background logic replaced by simple HTTP call
    # def _call_monthly_digest_api_background(self):
    #     """Call monthly digest function directly in background (fire-and-forget)."""
    #     start_time = datetime.now(timezone.utc)
    #     running_task_key = "monthly_digest_task_running"
    #     last_run_key = "monthly_digest_last_run"

    # ENTIRE METHOD COMMENTED OUT - LEGACY CODE BLOCK START
    """
        try:
            logger.info(
                f"🔥 BACKGROUND_DIGEST: ✅ STARTED - Background digest processing started at {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )

            # Import and call the internal function directly
            import asyncio
            from api.v1.monthly_digest import process_monthly_digest_for_all_users

            # Run the async function safely using asyncio.run()
            result = asyncio.run(process_monthly_digest_for_all_users())

            # Process completed - check results and update Redis appropriately
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()

            logger.info(
                f"🔥 BACKGROUND_DIGEST: 🏁 COMPLETED - Processing finished in {duration:.1f} seconds"
            )

            if result and redis_client:
                try:
                    # Check if digest was fully successful
                    emails_sent = result.get("emails_sent", 0)
                    total_emails = result.get("total_unique_emails", 0)
                    success_rate = result.get("success_rate", 0)

                    logger.info(
                        f"🔥 BACKGROUND_DIGEST: 📊 FINAL RESULTS - Sent: {emails_sent}/{total_emails}, Success rate: {success_rate}%"
                    )

                    # Only set last_run Redis if success rate >= 95% and at least some emails sent
                    if success_rate >= 95.0 and emails_sent > 0:
                        # Calculate TTL to last until next month's first Thursday + buffer
                        current_month = end_time.replace(day=1)
                        next_month = (current_month + timedelta(days=32)).replace(day=1)

                        # Find next month's first Tuesday
                        days_to_next_first_tue = (1 - next_month.weekday()) % 7
                        next_first_tuesday = next_month + timedelta(
                            days=days_to_next_first_tue
                        )

                        # TTL until 3 days after next month's first Tuesday
                        ttl_until = next_first_tuesday + timedelta(days=3)
                        ttl_seconds = int((ttl_until - end_time).total_seconds())

                        # Ensure TTL is positive (minimum 1 day)
                        if ttl_seconds <= 0:
                            ttl_seconds = 86400  # 1 day fallback
                            logger.warning(
                                f"🔥 BACKGROUND_DIGEST: TTL calculation negative, using 1 day fallback"
                            )

                        # Store success timestamp with calculated TTL
                        full_timestamp = end_time.strftime("%Y-%m-%d %H:%M:%S UTC")
                        redis_client.setex(last_run_key, ttl_seconds, full_timestamp)

                        logger.info(
                            f"🔥 BACKGROUND_DIGEST: ✅ SUCCESS REDIS UPDATED - Fully successful run, set '{last_run_key}' = '{full_timestamp}'"
                        )
                        logger.info(
                            f"🔥 BACKGROUND_DIGEST: ✅ TTL: {ttl_seconds} seconds (expires: {ttl_until.strftime('%Y-%m-%d %H:%M:%S UTC')})"
                        )
                    else:
                        logger.warning(
                            f"🔥 BACKGROUND_DIGEST: ⚠️ SUCCESS REDIS NOT UPDATED - Partial failure (success rate: {success_rate}%, sent: {emails_sent}/{total_emails})"
                        )
                        logger.warning(
                            f"🔥 BACKGROUND_DIGEST: ⚠️ Will allow retry on next trigger since last_run Redis state not set"
                        )

                except Exception as redis_error:
                    logger.error(
                        f"🔥 BACKGROUND_DIGEST: ❌ Failed to update success Redis state: {str(redis_error)}"
                    )

            return result

        except Exception as e:
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            logger.error(
                f"🔥 BACKGROUND_DIGEST: ❌ FAILED - Background digest processing failed after {duration:.1f} seconds: {str(e)}"
            )
            logger.error(f"🔥 BACKGROUND_DIGEST: ❌ Exception type: {type(e).__name__}")
            import traceback

            logger.error(
                f"🔥 BACKGROUND_DIGEST: ❌ Full traceback: {traceback.format_exc()}"
            )

        finally:
            # Always clear the running task key when done (success or failure)
            if redis_client:
                try:
                    redis_client.delete(running_task_key)
                    end_time = datetime.now(timezone.utc)
                    duration = (end_time - start_time).total_seconds()
                    logger.info(
                        f"🔥 BACKGROUND_DIGEST: 🧹 CLEANUP - Cleared running task key after {duration:.1f} seconds"
                    )
                except Exception as cleanup_error:
                    logger.error(
                        f"🔥 BACKGROUND_DIGEST: ⚠️ Failed to clear running task key: {str(cleanup_error)}"
                    )
    """
    # LEGACY CODE BLOCK END - All above code commented out

    # LEGACY - COMMENTED OUT - No longer needed, replaced by direct execution in manual trigger
    # def _call_monthly_digest_api(self):
    #     """Legacy method - kept for compatibility with manual trigger."""
    #     try:
    #         # Import and call the internal function directly
    #         import asyncio
    #         from api.v1.monthly_digest import process_monthly_digest_for_all_users
    #
    #         # Run the async function safely using asyncio.run()
    #         result = asyncio.run(process_monthly_digest_for_all_users())
    #         return result
    #
    #     except Exception as e:
    #         logger.error(f"Direct call to monthly digest function failed: {str(e)}")
    #         raise

    def start_scheduler(self):
        """Start the scheduler in a background thread."""
        if self.is_running:
            logger.warning("⚠️ SCHEDULER_START: Scheduler is already running")
            return

        # CRITICAL: Add Redis-based global scheduler lock to prevent multiple container instances
        scheduler_lock_key = f"{ENVIRONMENT}_global_scheduler_instance_lock"
        if redis_client:
            try:
                # Try to acquire global scheduler lock (expires in 10 minutes, renewed by heartbeat)
                instance_id = f"{socket.gethostname()}_{os.getpid()}"
                was_set = redis_client.set(
                    scheduler_lock_key, instance_id, nx=True, ex=600
                )

                if not was_set:
                    existing_instance = redis_client.get(scheduler_lock_key)
                    logger.warning(
                        f"⚠️ SCHEDULER_START: Another scheduler instance already "
                        f"running: {existing_instance}"
                    )
                    logger.warning(
                        "⚠️ SCHEDULER_START: This instance will NOT start scheduler "
                        "to prevent conflicts"
                    )
                    return

                logger.info(
                    f"🔒 SCHEDULER_START: Acquired global scheduler lock for "
                    f"instance: {instance_id}"
                )

            except Exception as e:
                logger.error(
                    f"⚠️ SCHEDULER_START: Failed to acquire scheduler lock: {str(e)}"
                )
                logger.error(
                    "⚠️ SCHEDULER_START: Will NOT start scheduler to prevent "
                    "conflicts"
                )
                return

        logger.info("🚀 SCHEDULER_START: Initializing monthly digest scheduler...")
        self.is_running = True
        self.schedule_monthly_digest()

        self.scheduler_thread = threading.Thread(
            target=self._run_scheduler, daemon=True
        )
        self.scheduler_thread.start()

        logger.info("🚀 SCHEDULER_START: ✅ Scheduler service started successfully!")
        logger.info(f"🚀 SCHEDULER_START: Thread ID: {self.scheduler_thread.ident}")
        logger.info(f"🚀 SCHEDULER_START: Daemon mode: {self.scheduler_thread.daemon}")

    def _run_scheduler(self):
        """Run the scheduler loop."""
        logger.info(
            "🔄 SCHEDULER_LOOP: Scheduler loop started - checking every 60 seconds"
        )
        logger.info(
            f"🔄 SCHEDULER_LOOP: Current UTC time: "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )

        loop_count = 0
        while self.is_running:
            try:
                loop_count += 1
                schedule.run_pending()

                # Log every 10 minutes to show we're alive
                if loop_count % 10 == 0:
                    current_time = datetime.now(timezone.utc)
                    logger.info(
                        f"🔄 SCHEDULER_LOOP: Heartbeat #{loop_count} at "
                        f"{current_time.strftime('%H:%M:%S UTC')} - scheduler running "
                        f"normally"
                    )

                    # Show next scheduled jobs
                    jobs = schedule.jobs
                    for job in jobs:
                        logger.info(
                            f"🔄 SCHEDULER_LOOP: Next run scheduled for: {job.next_run}"
                        )

                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"🔄 SCHEDULER_LOOP: ❌ Scheduler loop error: {str(e)}")
                logger.error(
                    f"🔄 SCHEDULER_LOOP: ❌ Exception type: {type(e).__name__}"
                )
                time.sleep(60)

        logger.info("🔄 SCHEDULER_LOOP: Scheduler loop stopped")

    def stop_scheduler(self):
        """Stop the scheduler."""
        self.is_running = False

        if self.scheduler_thread and self.scheduler_thread.is_alive():
            self.scheduler_thread.join(timeout=5)

        schedule.clear()
        logger.info("Scheduler service stopped")

    def get_scheduled_jobs(self):
        """Get list of scheduled jobs."""
        jobs = []
        for job in schedule.jobs:
            jobs.append(
                {
                    "job": str(job.job_func),
                    "next_run": str(job.next_run),
                    "interval": str(job.interval),
                    "unit": job.start_day,
                }
            )
        return jobs

    async def trigger_monthly_digest_manually(self):
        """Manually trigger monthly digest (for testing) - now uses direct execution."""
        logger.info("Manually triggering monthly digest - direct execution")
        try:
            # Direct execution for consistent performance (no ThreadPoolExecutor)
            from api.v1.monthly_digest import (
                process_monthly_digest_for_all_users,
            )

            # Call the async function directly with await (no asyncio.run needed)
            result = await process_monthly_digest_for_all_users()
            return result
        except Exception as e:
            logger.error(f"Manual trigger failed: {str(e)}")
            raise

    def _check_missed_digest_on_startup(self):
        """Check if we missed sending digest this month and send if needed."""
        try:
            now = datetime.now(timezone.utc)
            current_month = now.strftime("%Y-%m")

            # Only check if we're past the 5th of the month
            if now.day < 5:
                logger.info(
                    f"🔍 STARTUP CHECK - Too early in month (day {now.day}), "
                    f"skipping missed digest check"
                )
                return

            last_run_key = f"{ENVIRONMENT}_monthly_digest_last_run"

            if redis_client:
                # Check if key exists and get details
                last_run = redis_client.get(last_run_key)
                ttl = redis_client.ttl(
                    last_run_key
                )  # -1 = no expiry, -2 = key doesn't exist

                logger.info(
                    f"🔍 STARTUP CHECK - Redis key: {last_run}, TTL: {ttl} seconds"
                )

                should_send = False

                if ttl == -2:  # Key doesn't exist
                    logger.warning(
                        "🚨 REDIS KEY EXPIRED - No record of digest this month"
                    )
                    should_send = True
                elif last_run and not last_run.startswith(current_month):
                    logger.warning(
                        f"🚨 OLD DIGEST RECORD - Last run: {last_run}, "
                        f"Current month: {current_month}"
                    )
                    should_send = True
                elif not last_run:
                    logger.warning("🚨 NO DIGEST RECORD FOUND")
                    should_send = True
                else:
                    logger.info(f"✅ DIGEST ALREADY SENT - {last_run}")
                    return

                if should_send:
                    # Check if we're past first Tuesday + 2 days
                    first_day = now.replace(day=1)
                    days_to_first_tuesday = (1 - first_day.weekday()) % 7
                    first_tuesday = first_day + timedelta(days=days_to_first_tuesday)

                    if now.date() > (first_tuesday.date() + timedelta(days=2)):
                        logger.warning(
                            (
                                "🚨 MISSED DIGEST DETECTED - But startup recovery disabled "
                                "to prevent race conditions"
                            )
                        )
                        # self.executor.submit(self._call_monthly_digest_api)  # COMMENTED OUT - Legacy
                    else:
                        logger.info(
                            f"🔍 STARTUP CHECK - Still within normal window, first Tuesday "
                            f"was {first_tuesday.date()}"
                        )

        except Exception as e:
            logger.error(f"Startup digest check failed: {e}")


# Global scheduler instance
scheduler_service = SchedulerService()


def start_scheduler():
    """Start the global scheduler service."""
    try:
        scheduler_service.start_scheduler()
        logger.info("Scheduler service started successfully")
    except Exception as e:
        logger.error(f"Failed to start scheduler service: {str(e)}")


def stop_scheduler():
    """Stop the global scheduler service."""
    scheduler_service.stop_scheduler()


def get_scheduler_status():
    """Get scheduler status and jobs."""
    return {
        "is_running": scheduler_service.is_running,
        "scheduled_jobs": scheduler_service.get_scheduled_jobs(),
    }
