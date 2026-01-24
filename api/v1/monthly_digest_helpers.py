"""Helper functions for optimized monthly digest processing."""

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from google.cloud import datastore
from utils.safe_encoding import escape_html, build_safe_url

logger = logging.getLogger(__name__)


async def heartbeat_logger():
    """Keep-alive heartbeat to prevent container from going idle during long processing."""
    heartbeat_count = 0
    try:
        while True:
            await asyncio.sleep(30)  # Heartbeat every 30 seconds
            heartbeat_count += 1
            logger.info(
                (
                    f"[MONTHLY-DIGEST] 💓 HEARTBEAT {heartbeat_count} - "
                    f"Processing still active at {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}"
                )
            )
    except asyncio.CancelledError:
        logger.info(
            f"[MONTHLY-DIGEST] 💓 HEARTBEAT STOPPED after {heartbeat_count} beats"
        )
        raise


async def prefetch_breach_data(client) -> dict:
    """Pre-fetch all breach data we'll need for monthly digests."""
    # Get new breaches from target month (previous month)
    now = datetime.now(timezone.utc)
    current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    target_month_start = (current_month_start - timedelta(days=1)).replace(day=1)
    target_month_end = current_month_start

    query = client.query(kind="xon_breaches")
    query.add_filter("timestamp", ">=", target_month_start)
    query.add_filter("timestamp", "<", target_month_end)
    query.order = ["-timestamp"]

    # Also get breach details we might need
    all_breaches = {}
    new_breaches = []

    start_time = time.time()

    # Fetch new breaches
    for breach in query.fetch():
        breach_id = (
            breach.key.name if hasattr(breach.key, "name") else str(breach.key.id)
        )
        all_breaches[breach_id] = breach

        # Process for new breaches list
        try:
            breach_date_str = (
                breach.get("breached_date", "").strftime("%b %Y")
                if breach.get("breached_date")
                else "Unknown"
            )
            added_date_str = (
                breach.get("timestamp", "").strftime("%b %Y")
                if breach.get("timestamp")
                else "Unknown"
            )
        except (AttributeError, ValueError):
            breach_date_str = "Unknown"
            added_date_str = "Unknown"

        data_types = breach.get("xposed_data", "")
        if isinstance(data_types, list):
            data_types = ";".join(data_types)

        new_breach = {
            "breach_name": breach_id,
            "breach_date": breach_date_str,
            "added_date": added_date_str,
            "data_exposed": str(data_types),
            "records_count": (
                int(breach.get("xposed_records", 0))
                if breach.get("xposed_records")
                else 0
            ),
        }
        new_breaches.append(new_breach)

    # Pre-fetch recent breach details (last 6 months) for user exposures
    six_months_ago = datetime.now(timezone.utc) - timedelta(days=180)
    query_recent = client.query(kind="xon_breaches")
    query_recent.add_filter("timestamp", ">=", six_months_ago)

    for breach in query_recent.fetch():
        breach_id = (
            breach.key.name if hasattr(breach.key, "name") else str(breach.key.id)
        )
        if breach_id not in all_breaches:
            all_breaches[breach_id] = breach

    duration = time.time() - start_time
    logger.info(
        (
            f"[MONTHLY-DIGEST] 📊 PREFETCH: Loaded {len(new_breaches)} new breaches, "
            f"{len(all_breaches)} total breach records in {duration:.2f}s"
        )
    )

    return {
        "new_breaches": new_breaches,
        "breach_details": all_breaches,
    }


async def batch_create_sessions(client, email_tokens: dict):
    """Create all dashboard sessions in batches for better performance."""
    start_time = time.time()
    session_entities = []

    for email, token in email_tokens.items():
        entity = datastore.Entity(client.key("xon_domains_session", email))
        entity.update(
            {
                "magic_timestamp": datetime.now(),
                "domain_magic": token,
            }
        )
        session_entities.append(entity)

    # Batch create sessions in chunks of 25 (datastore limit)
    batch_size = 25
    total_batches = (len(session_entities) + batch_size - 1) // batch_size

    for i in range(0, len(session_entities), batch_size):
        batch = session_entities[i : i + batch_size]
        try:
            client.put_multi(batch)
            batch_num = (i // batch_size) + 1
            logger.info(
                (
                    f"[MONTHLY-DIGEST] 📝 SESSION BATCH {batch_num}/{total_batches}: "
                    f"Created {len(batch)} sessions"
                )
            )
        except Exception as e:
            logger.error(
                f"[MONTHLY-DIGEST] ❌ Failed to create session batch {batch_num}: {str(e)}"
            )

    duration = time.time() - start_time
    logger.info(
        (
            f"[MONTHLY-DIGEST] ✅ SESSION CREATION: Created {len(session_entities)} "
            f"sessions in {duration:.2f}s"
        )
    )


async def generate_monthly_digest_html_optimized(
    email: str,
    dashboard_token: str,
    user_domains: list,
    all_breach_data: dict,
    client=None,
) -> str:
    """Generate HTML with pre-fetched data for better performance."""
    try:
        # Use pre-fetched breach data instead of individual queries
        new_breaches = all_breach_data.get("new_breaches", [])
        breach_details = all_breach_data.get("breach_details", {})

        # Get user exposures using pre-fetched data
        user_exposures = []
        six_months_ago = datetime.now(timezone.utc) - timedelta(days=180)

        # Use provided client or create new one if not available
        if client is None:
            from google.cloud.datastore import Client

            client = Client()

        # OPTIMIZATION: Single batch query instead of N individual queries
        if user_domains:
            query = client.query(kind="xon_domains_summary")
            # Use IN filter for multiple domains at once
            query.add_filter("domain", "IN", user_domains)

            for entity in query.fetch():
                if entity["breach"] == "No_Breaches":
                    continue

                # Use pre-fetched breach data
                breach = breach_details.get(entity["breach"])
                if (
                    breach
                    and breach.get("timestamp")
                    and breach["timestamp"] >= six_months_ago
                ):
                    try:
                        breach_date_str = (
                            breach.get("breached_date", "").strftime("%b %Y")
                            if breach.get("breached_date")
                            else "Unknown"
                        )
                        added_timestamp_str = breach["timestamp"].strftime("%b %Y")
                    except (AttributeError, ValueError):
                        breach_date_str = "Unknown"
                        added_timestamp_str = "Unknown"

                    data_exposed = breach.get("xposed_data", "")
                    if isinstance(data_exposed, list):
                        data_exposed = ";".join(data_exposed)

                    exposure = {
                        "breach_name": entity.get("breach", "Unknown"),
                        "breach_date": breach_date_str,
                        "added_date": added_timestamp_str,
                        "data_exposed": str(data_exposed),
                        "records_count": (
                            int(breach.get("xposed_records", 0))
                            if breach.get("xposed_records")
                            else 0
                        ),
                        "email_count": (
                            int(entity.get("email_count", 0))
                            if entity.get("email_count")
                            else 0
                        ),
                        "domain": entity.get("domain", "Unknown"),
                    }
                    user_exposures.append(exposure)

        # Generate HTML using template logic
        html_content = await generate_html_template(
            email, dashboard_token, user_exposures, new_breaches, user_domains
        )
        return html_content

    except Exception as e:
        logger.error(
            f"[MONTHLY-DIGEST] ❌ Optimized HTML generation failed for {email}: {str(e)}"
        )
        raise


def generate_mobile_exposure_cards(user_exposures: list) -> str:
    """Generate mobile-friendly card layout for user exposures."""
    if not user_exposures:
        return """
                    <div class="mobile-card" style="background-color: #d4edda; border: 1px solid #c3e6cb; text-align: center; padding: 20px;">
                        <strong style="color: #155724;">✅ Good news!</strong><br>
                        <span style="color: #495057; font-size: 14px;">No new exposures found for your domains in the last 6 months.</span>
                    </div>"""

    cards = ""
    for exposure in user_exposures[:10]:  # Limit to top 10
        cards += f"""
                    <div class="mobile-card">
                        <div style="font-weight: bold; color: #e74c3c; font-size: 16px; margin-bottom: 8px;">
                            🚨 {escape_html(exposure.get('breach_name', 'Unknown'))}
                        </div>
                        <div style="color: #495057; font-size: 14px; line-height: 1.4;">
                            <div style="margin: 4px 0;"><strong>Breached:</strong> {escape_html(exposure.get('breach_date', 'Unknown'))}</div>
                            <div style="margin: 4px 0;"><strong>Added:</strong> {escape_html(exposure.get('added_date', 'Unknown'))}</div>
                            <div style="margin: 4px 0;"><strong>Records:</strong> {exposure.get('records_count', 0):,}</div>
                            <div style="margin: 8px 0 0 0; padding: 8px; background-color: #f8f9fa; border-radius: 4px; font-size: 12px;">
                                <strong>Data Exposed:</strong><br>{escape_html(exposure.get('data_exposed', 'Unknown'))}
                            </div>
                        </div>
                    </div>"""
    return cards


def generate_mobile_breach_cards(new_breaches: list) -> str:
    """Generate mobile-friendly card layout for new breaches."""
    if not new_breaches:
        return """
                    <div class="mobile-card" style="background-color: #d4edda; border: 1px solid #c3e6cb; text-align: center; padding: 20px;">
                        <strong style="color: #155724;">✅ No new breaches added this month.</strong>
                    </div>"""

    cards = ""
    for breach in new_breaches[:10]:  # Limit to top 10
        cards += f"""
                    <div class="mobile-card">
                        <div style="font-weight: bold; color: #f39c12; font-size: 16px; margin-bottom: 8px;">
                            🚨 {escape_html(breach.get('breach_name', 'Unknown'))}
                        </div>
                        <div style="color: #495057; font-size: 14px; line-height: 1.4;">
                            <div style="margin: 4px 0;"><strong>Breached:</strong> {escape_html(breach.get('breach_date', 'Unknown'))}</div>
                            <div style="margin: 4px 0;"><strong>Added:</strong> {escape_html(breach.get('added_date', 'Unknown'))}</div>
                            <div style="margin: 4px 0;"><strong>Records:</strong> {breach.get('records_count', 0):,}</div>
                            <div style="margin: 8px 0 0 0; padding: 8px; background-color: #f8f9fa; border-radius: 4px; font-size: 12px;">
                                <strong>Data Exposed:</strong><br>{escape_html(breach.get('data_exposed', 'Unknown'))}
                            </div>
                        </div>
                    </div>"""
    return cards


async def generate_html_template(
    email: str,
    dashboard_token: str,
    user_exposures: list,
    new_breaches: list,
    user_domains: list,
) -> str:
    """Generate the professional HTML template with tables and proper styling."""

    # Get current and previous month names for display
    now = datetime.now(timezone.utc)
    current_month_year = now.strftime("%B %Y")
    previous_month_date = now - timedelta(days=30)
    previous_month = previous_month_date.strftime("%B")

    # Use the verified domains passed to the function (not derived from exposures)
    # user_domains parameter already contains the verified domains for this user

    # Summary info (escape domains for safe HTML display)
    domains_text = (
        ", ".join(escape_html(d) for d in user_domains)
        if user_domains
        else "No verified domains"
    )
    summary_info = (
        "Your summary: <strong>{} verified domains</strong> ({}) • "
        "<strong>{} exposures</strong> • <strong>{} new breaches</strong> this month"
    ).format(len(user_domains), domains_text, len(user_exposures), len(new_breaches))

    # Dashboard URL with properly encoded parameters
    dashboard_url = build_safe_url(
        "https://xposedornot.com/breach-dashboard",
        {"email": email, "token": dashboard_token},
    )

    # Build mobile-friendly cards instead of table rows
    exposure_cards = ""
    if user_exposures:
        for exposure in user_exposures[:10]:  # Limit to top 10
            exposure_cards += f"""
                        <div style="border: 1px solid #dee2e6; border-radius: 6px; padding: 12px; margin: 8px 0; background-color: #fff;">
                            <div style="font-weight: bold; color: #e74c3c; font-size: 16px; margin-bottom: 8px;">
                                🚨 {escape_html(exposure.get('breach_name', 'Unknown'))}
                            </div>
                            <div style="color: #495057; font-size: 14px; line-height: 1.4;">
                                <div style="margin: 4px 0;"><strong>Breached:</strong> {escape_html(exposure.get('breach_date', 'Unknown'))}</div>
                                <div style="margin: 4px 0;"><strong>Added:</strong> {escape_html(exposure.get('added_date', 'Unknown'))}</div>
                                <div style="margin: 4px 0;"><strong>Records:</strong> {exposure.get('records_count', 0):,}</div>
                                <div style="margin: 8px 0 0 0; padding: 8px; background-color: #f8f9fa; border-radius: 4px; font-size: 12px;">
                                    <strong>Data Exposed:</strong><br>{escape_html(exposure.get('data_exposed', 'Unknown'))}
                                </div>
                            </div>
                        </div>"""
    else:
        exposure_cards = """
                        <div style="border: 1px solid #c3e6cb; border-radius: 6px; padding: 20px; margin: 8px 0; background-color: #d4edda; text-align: center;">
                            <strong style="color: #155724;">✅ Good news!</strong><br>
                            <span style="color: #495057; font-size: 14px;">No new exposures found for your domains in the last 6 months.</span>
                        </div>"""

    # Build mobile-friendly breach cards instead of table rows
    breach_cards = ""
    if new_breaches:
        for breach in new_breaches[:10]:  # Limit to top 10
            breach_cards += f"""
                        <div style="border: 1px solid #dee2e6; border-radius: 6px; padding: 12px; margin: 8px 0; background-color: #fff;">
                            <div style="font-weight: bold; color: #f39c12; font-size: 16px; margin-bottom: 8px;">
                                🚨 {escape_html(breach.get('breach_name', 'Unknown'))}
                            </div>
                            <div style="color: #495057; font-size: 14px; line-height: 1.4;">
                                <div style="margin: 4px 0;"><strong>Breached:</strong> {escape_html(breach.get('breach_date', 'Unknown'))}</div>
                                <div style="margin: 4px 0;"><strong>Added:</strong> {escape_html(breach.get('added_date', 'Unknown'))}</div>
                                <div style="margin: 4px 0;"><strong>Records:</strong> {breach.get('records_count', 0):,}</div>
                                <div style="margin: 8px 0 0 0; padding: 8px; background-color: #f8f9fa; border-radius: 4px; font-size: 12px;">
                                    <strong>Data Exposed:</strong><br>{escape_html(breach.get('data_exposed', 'Unknown'))}
                                </div>
                            </div>
                        </div>"""
    else:
        breach_cards = """
                        <div style="border: 1px solid #c3e6cb; border-radius: 6px; padding: 20px; margin: 8px 0; background-color: #d4edda; text-align: center;">
                            <strong style="color: #155724;">✅ No new breaches added this month.</strong>
                        </div>"""

    # Generate Gmail-compatible HTML template (no CSS, no tables)
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 15px; background-color: #f8f9fa;">
        <div style="background-color: white; border-radius: 8px; padding: 20px;">
            
            <!-- Header -->
            <div style="text-align: center; margin-bottom: 25px;">
                <h1 style="color: #2c3e50; margin: 0; font-size: 22px;">XposedOrNot Breach Digest</h1>
                <p style="color: #7f8c8d; font-size: 14px; margin: 8px 0 0 0;">({current_month_year})</p>
            </div>

            <!-- Greeting -->
            <p style="color: #34495e; font-size: 15px; line-height: 1.6; margin: 0 0 12px 0;">Hello there,</p>
            <p style="color: #34495e; font-size: 15px; line-height: 1.6; margin: 0 0 20px 0;">
                We've updated XposedOrNot with new breach data this month. Here's your personalized summary:
            </p>

            <!-- Summary Info -->
            <div style="background-color: #e8f4fd; padding: 12px; font-size: 13px; color: #2c3e50; margin: 15px 0; border-radius: 6px; border-left: 4px solid #3498db;">
                📊 {summary_info}
            </div>

            <!-- User Exposures Section -->
            <div style="margin: 25px 0;">
                <h2 style="color: #e74c3c; font-size: 16px; margin: 0 0 12px 0;">🚨 Your Exposures (last 6 months):</h2>
                
                <!-- Mobile-First Card Layout -->
                <div style="background-color: #fff5f5; border-left: 4px solid #e74c3c; padding: 12px; margin: 12px 0; border-radius: 6px;">
{exposure_cards}
                </div>

                <div style="text-align: center; margin: 15px 0;">
                    <a href="{dashboard_url}" style="background-color: #e74c3c; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block; font-size: 14px;">🔍 View your full breach report</a>
                </div>
            </div>

            <!-- New Breaches Section -->
            <div style="margin: 25px 0;">
                <h2 style="color: #f39c12; font-size: 16px; margin: 0 0 12px 0;">🚨 New Breaches Added in {previous_month}:</h2>
                
                <!-- Mobile-First Card Layout -->
                <div style="background-color: #fff9e6; border-left: 4px solid #f39c12; padding: 12px; margin: 12px 0; border-radius: 6px;">
{breach_cards}
                </div>

                <div style="text-align: center; margin: 15px 0;">
                    <a href="https://xposedornot.com/xposed" style="background-color: #f39c12; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block; font-size: 14px;">📋 See complete breach list</a>
                </div>
            </div>

            <!-- Security Reminder -->
            <div style="background-color: #e8f4fd; border-left: 4px solid #3498db; padding: 20px; margin: 30px 0;">
                <h3 style="color: #2980b9; font-size: 16px; margin: 0 0 10px 0;">🛡️ Security Reminder</h3>
                <p style="color: #34495e; font-size: 14px; line-height: 1.6; margin: 0 0 15px 0;">
                    Even if your email wasn't in these recent breaches, attackers often reuse leaked data across platforms.
                </p>
                <ul style="color: #34495e; font-size: 14px; line-height: 1.6; margin: 0; padding-left: 20px;">
                    <li>Rotate reused passwords</li>
                    <li>Enable 2FA on key accounts</li>
                    <li>Use a password manager</li>
                </ul>
            </div>

            <!-- Closing -->
            <div style="text-align: center; margin: 30px 0 20px 0; padding: 20px 0; border-top: 1px solid #dee2e6;">
                <p style="color: #34495e; font-size: 16px; margin: 0 0 10px 0;">Stay safe,</p>
                <p style="color: #2c3e50; font-weight: bold; margin: 0;">⚡ The XposedOrNot Team</p>
            </div>

            <!-- Email Footer -->
            <div style="background-color: #f8f9fa; padding: 20px; margin-top: 30px; border-top: 1px solid #dee2e6; font-size: 12px; color: #6c757d; text-align: center;">
                <p style="margin: 0 0 10px 0;">This email was sent to <strong>{escape_html(email)}</strong> because of monthly breach notifications in XposedOrNot.com.</p>
                <p style="margin: 0;">© 2026 XposedOrNot. All rights reserved. | <a href="https://xposedornot.com/dashboard" style="color: #6c757d;">Visit Website</a></p>
            </div>

        </div>
    </div>
    """

    return html_content
