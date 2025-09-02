"""Scheduler service for automated tasks like monthly digest."""

import asyncio
import logging
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Optional

import schedule

logger = logging.getLogger(__name__)


class SchedulerService:
    """Service for managing scheduled tasks."""

    def __init__(self):
        self.is_running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        self.executor = ThreadPoolExecutor(max_workers=2)

    def schedule_monthly_digest(self):
        """Schedule monthly digest to run at 9 AM EST on first Tuesday of every month."""
        # Schedule for 9 AM EST (which is 14:00 UTC during standard time,
        # 13:00 UTC during daylight saving)
        # We'll use 13:00 UTC to be safe during daylight saving time
        schedule.every().day.at("13:00").do(self._trigger_monthly_digest_job)
        logger.info(
            "Monthly digest scheduled for 9 AM EST (13:00 UTC) daily - "
            "will check for first Tuesday of month"
        )

    def _is_first_tuesday_of_month(self, date):
        """Check if given date is first Tuesday of the month."""
        # Find first day of the month
        first_day = date.replace(day=1)

        # Tuesday is weekday 1 (Monday=0, Tuesday=1, Wednesday=2, etc.)
        days_to_first_tuesday = (1 - first_day.weekday()) % 7
        first_tuesday = first_day + timedelta(days=days_to_first_tuesday)

        return date.date() == first_tuesday.date()

    def _trigger_monthly_digest_job(self):
        """Trigger the monthly digest job."""
        try:
            now = datetime.now()
            if not self._is_first_tuesday_of_month(now):
                # Only log every 7 days to avoid spam
                if now.day % 7 == 0:
                    logger.debug(
                        "Monthly digest check - today is %s, "
                        "waiting for first Tuesday of month",
                        now.strftime('%A %d')
                    )
                return

            last_run_file = "/tmp/monthly_digest_last_run"
            today_str = now.strftime("%Y-%m-%d")

            try:
                if os.path.exists(last_run_file):
                    with open(last_run_file, "r") as f:
                        last_run = f.read().strip()
                    if last_run == today_str:
                        logger.info(
                            "Monthly digest already triggered today (%s)",
                            today_str
                        )
                        return
            except Exception:
                pass  # Ignore file errors, just run

            logger.info("Triggering monthly digest for all validated users")

            # Run the async call in the executor
            future = self.executor.submit(self._call_monthly_digest_api)
            result = future.result(timeout=300)  # 5 minute timeout

            # Mark as run today
            try:
                with open(last_run_file, "w") as f:
                    f.write(today_str)
            except Exception:
                pass  # Ignore file errors

            logger.info("Monthly digest triggered successfully: %s", result)

        except Exception as e:
            logger.error("Failed to trigger monthly digest: %s", str(e))

    def _call_monthly_digest_api(self):
        """Call monthly digest function directly."""
        try:
            # Import and call the internal function directly
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
            logger.error(
                "Direct call to monthly digest function failed: %s", str(e)
            )
            raise

    def start_scheduler(self):
        """Start the scheduler in a background thread."""
        if self.is_running:
            logger.warning("Scheduler is already running")
            return

        self.is_running = True
        self.schedule_monthly_digest()

        self.scheduler_thread = threading.Thread(
            target=self._run_scheduler, daemon=True
        )
        self.scheduler_thread.start()

        logger.info("Scheduler service started")

    def _run_scheduler(self):
        """Run the scheduler loop."""
        logger.info("Scheduler loop started")

        while self.is_running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error("Scheduler loop error: %s", str(e))
                time.sleep(60)

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
            logger.error("Manual trigger failed: %s", str(e))
            raise


# Global scheduler instance
scheduler_service = SchedulerService()


def start_scheduler():
    """Start the global scheduler service."""
    try:
        scheduler_service.start_scheduler()
        logger.info("Scheduler service started successfully")
    except Exception as e:
        logger.error("Failed to start scheduler service: %s", str(e))


def stop_scheduler():
    """Stop the global scheduler service."""
    scheduler_service.stop_scheduler()


def get_scheduler_status():
    """Get scheduler status and jobs."""
    return {
        "is_running": scheduler_service.is_running,
        "scheduled_jobs": scheduler_service.get_scheduled_jobs(),
    }
