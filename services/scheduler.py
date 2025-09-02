"""Scheduler service for automated tasks like monthly digest."""

import asyncio
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional
import schedule
import time
import threading
import httpx
import redis
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# Redis client for tracking last run times
try:
    from config.settings import REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD

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
        self.executor = ThreadPoolExecutor(max_workers=2)

    def schedule_monthly_digest(self):
        """Schedule monthly digest to run at 9 AM EST on first Wednesday of every month."""
        # Schedule for 9 AM EST = 14:00 UTC (EST is UTC-5)
        schedule.every().day.at("14:00").do(self._trigger_monthly_digest_job)
        logger.info(
            "📅 SCHEDULER STARTED: Monthly digest scheduled for 9 AM EST (14:00 UTC) daily - will check for first Wednesday of month"
        )
        logger.info(
            f"📅 SCHEDULER: Current UTC time is {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )

        # Test the first Wednesday logic immediately
        test_date = datetime.now(timezone.utc)
        is_first_wednesday = self._is_first_wednesday_of_month(test_date)
        logger.info(
            f"📅 SCHEDULER: Today ({test_date.strftime('%A %Y-%m-%d')}) is first Wednesday: {is_first_wednesday}"
        )

    def _is_first_wednesday_of_month(self, date):
        """Check if given date is first Wednesday of the month."""
        # Ensure we're working with UTC timezone
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)

        # Find first day of the month
        first_day = date.replace(day=1)
        logger.debug(
            f"📅 FIRST_WEDNESDAY_CHECK: First day of month: {first_day.strftime('%A %Y-%m-%d')} (weekday: {first_day.weekday()})"
        )

        # Wednesday is weekday 2 (Monday=0, Tuesday=1, Wednesday=2, etc.)
        days_to_first_wednesday = (2 - first_day.weekday()) % 7
        first_wednesday = first_day + timedelta(days=days_to_first_wednesday)

        logger.debug(
            f"📅 FIRST_WEDNESDAY_CHECK: Calculated first Wednesday: {first_wednesday.strftime('%A %Y-%m-%d')}"
        )
        logger.debug(
            f"📅 FIRST_WEDNESDAY_CHECK: Checking date: {date.strftime('%A %Y-%m-%d')}"
        )

        result = date.date() == first_wednesday.date()
        logger.debug(f"📅 FIRST_WEDNESDAY_CHECK: Result: {result}")

        return result

    def _trigger_monthly_digest_job(self):
        """Trigger the monthly digest job."""
        try:
            # Always use UTC timezone for consistency
            now = datetime.now(timezone.utc)
            logger.info(
                f"🚀 DIGEST_TRIGGER: Checking monthly digest trigger at {now.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )
            logger.info(f"🚀 DIGEST_TRIGGER: Today is {now.strftime('%A %B %d, %Y')}")

            # Test the first Wednesday condition
            is_first_wednesday = self._is_first_wednesday_of_month(now)
            logger.info(
                f"🚀 DIGEST_TRIGGER: First Wednesday test result: {is_first_wednesday}"
            )

            if not is_first_wednesday:
                logger.info(
                    f"🚀 DIGEST_TRIGGER: ❌ CONDITIONS NOT MET - Today is not the first Wednesday of the month"
                )
                logger.info(
                    f"🚀 DIGEST_TRIGGER: Waiting for first Wednesday. Current day: {now.strftime('%A %d')}"
                )
                return

            logger.info(
                f"🚀 DIGEST_TRIGGER: ✅ CONDITIONS MET - Today IS the first Wednesday of the month!"
            )

            # Check Redis for last run date instead of file
            last_run_key = "monthly_digest_last_run"
            today_str = now.strftime("%Y-%m-%d")

            if redis_client:
                try:
                    last_run = redis_client.get(last_run_key)
                    if last_run == today_str:
                        logger.info(
                            f"🚀 DIGEST_TRIGGER: ❌ ALREADY TRIGGERED - Monthly digest already sent today ({today_str})"
                        )
                        logger.info(
                            f"🚀 DIGEST_TRIGGER: Redis key '{last_run_key}' = '{last_run}'"
                        )
                        return
                    else:
                        logger.info(
                            f"🚀 DIGEST_TRIGGER: ✅ NEW DAY - Last run was: {last_run or 'never'}, proceeding..."
                        )
                except Exception as e:
                    logger.error(
                        f"🚀 DIGEST_TRIGGER: ⚠️ Redis check failed: {str(e)}, proceeding anyway..."
                    )
            else:
                logger.warning(
                    "🚀 DIGEST_TRIGGER: ⚠️ Redis client not available, skipping duplicate check"
                )

            logger.info(
                "🚀 DIGEST_TRIGGER: ✅ FUNCTION CALLED - Triggering monthly digest for all validated users"
            )

            # Run the async call in the executor
            future = self.executor.submit(self._call_monthly_digest_api)
            result = future.result(timeout=300)  # 5 minute timeout

            # Mark as run today in Redis
            if redis_client:
                try:
                    # Set with 48 hour TTL to allow for timezone edge cases
                    redis_client.setex(last_run_key, 86400 * 2, today_str)
                    logger.info(
                        f"🚀 DIGEST_TRIGGER: ✅ REDIS UPDATED - Set '{last_run_key}' = '{today_str}' (48h TTL)"
                    )
                except Exception as e:
                    logger.error(
                        f"🚀 DIGEST_TRIGGER: ❌ Failed to update Redis: {str(e)}"
                    )
            else:
                logger.warning(
                    "🚀 DIGEST_TRIGGER: ⚠️ Redis client not available, cannot track last run"
                )

            logger.info(
                f"🚀 DIGEST_TRIGGER: ✅ FUNCTION SUCCEEDED - Monthly digest completed successfully!"
            )
            logger.info(f"🚀 DIGEST_TRIGGER: 📊 RESULT SUMMARY: {result}")

        except Exception as e:
            logger.error(
                f"🚀 DIGEST_TRIGGER: ❌ FUNCTION FAILED - Error triggering monthly digest: {str(e)}"
            )
            logger.error(f"🚀 DIGEST_TRIGGER: ❌ Exception type: {type(e).__name__}")
            import traceback

            logger.error(
                f"🚀 DIGEST_TRIGGER: ❌ Full traceback: {traceback.format_exc()}"
            )

    def _call_monthly_digest_api(self):
        """Call monthly digest function directly."""
        try:
            # Import and call the internal function directly
            import asyncio
            from api.v1.monthly_digest import process_monthly_digest_for_all_users

            # Run the async function in a new event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(process_monthly_digest_for_all_users())
                return result
            finally:
                loop.close()

        except Exception as e:
            logger.error(f"Direct call to monthly digest function failed: {str(e)}")
            raise

    def start_scheduler(self):
        """Start the scheduler in a background thread."""
        if self.is_running:
            logger.warning("⚠️ SCHEDULER_START: Scheduler is already running")
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
            f"🔄 SCHEDULER_LOOP: Current UTC time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
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
                        f"🔄 SCHEDULER_LOOP: Heartbeat #{loop_count} at {current_time.strftime('%H:%M:%S UTC')} - scheduler running normally"
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

    def trigger_monthly_digest_manually(self):
        """Manually trigger monthly digest (for testing)."""
        logger.info("Manually triggering monthly digest")
        try:
            future = self.executor.submit(self._call_monthly_digest_api)
            result = future.result(timeout=300)
            return result
        except Exception as e:
            logger.error(f"Manual trigger failed: {str(e)}")
            raise


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
