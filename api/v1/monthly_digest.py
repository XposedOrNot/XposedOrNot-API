"""Monthly digest endpoint for sending breach summaries to validated domain users."""

# Standard library imports
import logging
import os
from datetime import datetime, timedelta, timezone

# Third-party imports
import httpx
import redis
from fastapi import APIRouter
from google.cloud import datastore

# First-party imports
from config.settings import REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD
from utils.token import generate_confirmation_token

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


async def generate_monthly_digest_html(email: str, dashboard_token: str = None) -> str:
    """
    Generate complete HTML content for monthly digest email - matches JSON endpoint logic
    """
    try:
        # Initialize datastore client
        client = datastore.Client()

        # Get verified domains for this email
        query = client.query(kind="xon_domains")
        query.add_filter("email", "=", email.lower().strip())
        query.add_filter("verified", "=", True)
        user_domains = [ent["domain"] for ent in query.fetch()]

        # Get user exposures from last 6 months
        user_exposures = []
        six_months_ago = datetime.now(timezone.utc) - timedelta(days=180)

        for domain in user_domains:
            # Get domain summary
            query = client.query(kind="xon_domains_summary")
            query.add_filter("domain", "=", domain)

            for entity in query.fetch():
                if entity["breach"] == "No_Breaches":
                    continue

                # Get breach details
                breach_key = client.key("xon_breaches", entity["breach"])
                breach = client.get(breach_key)

                if breach and breach.get("timestamp"):
                    # Use timestamp field for filtering when data was added
                    breach_timestamp = breach["timestamp"]
                    if breach_timestamp >= six_months_ago:
                        # Safe datetime formatting with error handling
                        try:
                            breach_date_str = (
                                breach.get("breached_date", "").strftime("%b %Y")
                                if breach.get("breached_date")
                                else "Unknown"
                            )
                            added_timestamp_str = breach_timestamp.strftime("%b %Y")
                        except (AttributeError, ValueError):
                            breach_date_str = "Unknown"
                            added_timestamp_str = "Unknown"

                        # Handle xposed_data field (can be string or list)
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
                            "domain": domain,
                        }
                        user_exposures.append(exposure)

        # Get new breaches added in the last month
        new_breaches = []
        one_month_ago = datetime.now(timezone.utc) - timedelta(days=30)

        query = client.query(kind="xon_breaches")
        query.add_filter("timestamp", ">=", one_month_ago)
        query.order = ["-timestamp"]

        for breach in query.fetch():
            # Safe datetime formatting with error handling
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

            # Handle data_types field (can be string or list)
            data_types = breach.get("xposed_data", "")
            if isinstance(data_types, list):
                data_types = ";".join(data_types)

            breach_info = {
                "breach_name": breach.key.name if breach.key.name else "Unknown",
                "breach_date": breach_date_str,
                "records_exposed": (
                    int(breach.get("xposed_records", 0))
                    if breach.get("xposed_records")
                    else 0
                ),
                "data_types": str(data_types),
                "added_date": added_date_str,
            }
            new_breaches.append(breach_info)

        # Generate HTML content - ALWAYS show full template structure
        current_month_year = datetime.now(timezone.utc).strftime("%B %Y")
        current_month = current_month_year.split()[0]

        # Summary info for email (replace debug) - process this first
        domains_text = (
            ", ".join(user_domains) if user_domains else "No verified domains"
        )
        summary_info = (
            "Your summary: <strong>{} verified domains</strong> ({}) • "
            "<strong>{} exposures</strong> • <strong>{} new breaches</strong> this month"
        ).format(
            len(user_domains), domains_text, len(user_exposures), len(new_breaches)
        )

        # Use provided dashboard token or generate new one
        if not dashboard_token:
            dashboard_token = await generate_confirmation_token(email)

        # Use production domain for dashboard URL (not API domain)
        dashboard_base_url = "https://xposedornot.com"
        email_param = "email={}".format(email)
        token_param = "token={}".format(dashboard_token)
        dashboard_url = "{}/breach-dashboard?{}&{}".format(
            dashboard_base_url, email_param, token_param
        )

        # Build dynamic table rows first
        exposure_rows = ""
        if user_exposures:
            for exposure in user_exposures[:10]:  # Limit to top 10
                exposure_rows += f"""
                                <tr>
                                    <td style="padding: 10px; border: 1px solid #9ca3af; color: #495057;">{exposure.get('breach_name', 'Unknown')}</td>
                                    <td style="padding: 10px; border: 1px solid #9ca3af; color: #495057;">{exposure.get('breach_date', 'Unknown')}</td>
                                    <td style="padding: 10px; border: 1px solid #9ca3af; color: #495057;">{exposure.get('added_date', 'Unknown')}</td>
                                    <td style="padding: 10px; border: 1px solid #9ca3af; color: #495057;">{exposure.get('records_count', 0):,}</td>
                                    <td style="padding: 10px; border: 1px solid #9ca3af; color: #495057; font-size: 14px;">{exposure.get('data_exposed', 'Unknown')}</td>
                                </tr>"""
        else:
            exposure_rows = """
                                <tr>
                                    <td colspan="5" style="padding: 20px; text-align: center; color: #155724; font-weight: bold; background-color: #d4edda; border: 1px solid #9ca3af;">
                                        ✅ Good news! No new exposures found for your domains in the last 6 months.
                                    </td>
                                </tr>"""

        breach_rows = ""
        if new_breaches:
            for breach in new_breaches[:10]:  # Limit to top 10
                breach_rows += f"""
                                <tr>
                                    <td style="padding: 10px; border: 1px solid #9ca3af; color: #495057;">{breach.get('breach_name', 'Unknown')}</td>
                                    <td style="padding: 10px; border: 1px solid #9ca3af; color: #495057;">{breach.get('breach_date', 'Unknown')}</td>
                                    <td style="padding: 10px; border: 1px solid #9ca3af; color: #495057;">{breach.get('added_date', 'Unknown')}</td>
                                    <td style="padding: 10px; border: 1px solid #9ca3af; color: #495057;">{breach.get('records_exposed', 0):,}</td>
                                    <td style="padding: 10px; border: 1px solid #9ca3af; color: #495057; font-size: 14px;">{breach.get('data_types', 'Unknown')}</td>
                                </tr>"""
        else:
            breach_rows = """
                                <tr>
                                    <td colspan="5" style="padding: 20px; text-align: center; color: #155724; font-weight: bold; background-color: #d4edda; border: 1px solid #9ca3af;">
                                        ✅ No new breaches added this month.
                                    </td>
                                </tr>"""

        # Use .format() instead of f-strings to avoid CSS conflicts
        html_content = """
        <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f8f9fa;">
            <div style="background-color: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                
                <!-- Header -->
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #2c3e50; margin: 0;">XposedOrNot Community Breach Digest</h1>
                    <p style="color: #7f8c8d; font-size: 16px; margin: 10px 0 0 0;">({current_month_year})</p>
                </div>

                <!-- Greeting -->
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">Hello there,</p>
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    We've updated XposedOrNot with new breach data this month. Here's your personalized summary:
                </p>

                <!-- Summary Info -->
                <div style="background-color: #e8f4fd; padding: 15px; font-size: 14px; color: #2c3e50; margin: 15px 0; border-radius: 6px; border-left: 4px solid #3498db;">
                    📊 {summary_info}
                </div>

                <!-- User Exposures Section -->
                <div style="margin: 30px 0;">
                    <h2 style="color: #e74c3c; font-size: 18px; margin-bottom: 15px;">🚨 Your Exposures (last 6 months):</h2>
                    
                    <!-- Always show table structure -->
                    <div style="background-color: #fff5f5; border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0;">
                        <table style="width: 100%; border-collapse: separate; border-spacing: 0; border: 1px solid #9ca3af;">
                            <thead>
                                <tr style="background-color: #f8f9fa;">
                                    <th style="padding: 10px; text-align: left; border: 1px solid #9ca3af; border-bottom: 2px solid #dee2e6; color: #495057;">Breach Name</th>
                                    <th style="padding: 10px; text-align: left; border: 1px solid #9ca3af; border-bottom: 2px solid #dee2e6; color: #495057;">Breached Date</th>
                                    <th style="padding: 10px; text-align: left; border: 1px solid #9ca3af; border-bottom: 2px solid #dee2e6; color: #495057;">Added Date</th>
                                    <th style="padding: 10px; text-align: left; border: 1px solid #9ca3af; border-bottom: 2px solid #dee2e6; color: #495057;">Records</th>
                                    <th style="padding: 10px; text-align: left; border: 1px solid #9ca3af; border-bottom: 2px solid #dee2e6; color: #495057;">Data Types</th>
                                </tr>
                            </thead>
                            <tbody>
{exposure_rows}
                            </tbody>
                        </table>
                    </div>
                    <div style="text-align: center; margin: 20px 0;">
                        <a href="{dashboard_url}" style="background-color: #e74c3c; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">🔍 View your full breach report</a>
                    </div>
                </div>

                <!-- New Breaches Section -->
                <div style="margin: 30px 0;">
                    <h2 style="color: #f39c12; font-size: 18px; margin-bottom: 15px;">🚨 New Breaches Added in {current_month}:</h2>
                    
                    <!-- Always show new breaches table -->
                    <div style="background-color: #fff9e6; border-left: 4px solid #f39c12; padding: 15px; margin: 15px 0;">
                        <table style="width: 100%; border-collapse: separate; border-spacing: 0; border: 1px solid #9ca3af;">
                            <thead>
                                <tr style="background-color: #f8f9fa;">
                                    <th style="padding: 10px; text-align: left; border: 1px solid #9ca3af; border-bottom: 2px solid #dee2e6; color: #495057;">Breach Name</th>
                                    <th style="padding: 10px; text-align: left; border: 1px solid #9ca3af; border-bottom: 2px solid #dee2e6; color: #495057;">Breached Date</th>
                                    <th style="padding: 10px; text-align: left; border: 1px solid #9ca3af; border-bottom: 2px solid #dee2e6; color: #495057;">Added Date</th>
                                    <th style="padding: 10px; text-align: left; border: 1px solid #9ca3af; border-bottom: 2px solid #dee2e6; color: #495057;">Records</th>
                                    <th style="padding: 10px; text-align: left; border: 1px solid #9ca3af; border-bottom: 2px solid #dee2e6; color: #495057;">Data Types</th>
                                </tr>
                            </thead>
                            <tbody>
{breach_rows}
                            </tbody>
                        </table>
                    </div>
                    <div style="text-align: center; margin: 20px 0;">
                        <a href="https://xposedornot.com/xposed" style="background-color: #f39c12; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">📋 See complete breach list</a>
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
                    <p style="margin: 0 0 10px 0;">This email was sent to <strong>{user_email}</strong> because of monthly breach notifications in XposedOrNot.com.</p>
                    <p style="margin: 0;">© 2025 XposedOrNot. All rights reserved. | <a href="https://xposedornot.com/dashboard" style="color: #6c757d;">Visit Website</a></p>
                </div>

            </div>
        </div>
        """.format(
            current_month_year=current_month_year,
            summary_info=summary_info,
            current_month=current_month,
            user_email=email,
            exposure_rows=exposure_rows,
            breach_rows=breach_rows,
            dashboard_url=dashboard_url,
        )

        return html_content

    except Exception as e:
        # Return error HTML if data fetch fails
        return """
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #e74c3c;">❌ Error Generating Digest</h2>
            <p>We encountered an error while generating your monthly digest: {}</p>
            <p><a href="https://xposedornot.com" style="color: #3498db;">Visit XposedOrNot</a> for manual checking.</p>
        </div>
        """.format(
            str(e)
        )


async def process_monthly_digest_for_all_users():
    """
    Internal function to process monthly digest for all verified domain users.
    This function can be called directly by the scheduler without HTTP overhead.
    """
    try:
        # Get all verified domains
        client = datastore.Client()
        query = client.query(kind="xon_domains")
        query.add_filter("verified", "=", True)
        verified_domains = list(query.fetch())

        if not verified_domains:
            logger.info("No verified domains found for monthly digest")
            return {
                "status": "success",
                "message": "No verified domains found",
                "emails_sent": 0,
            }

        # Get unique emails from verified domains
        unique_emails = set()
        for domain in verified_domains:
            if domain.get("email"):
                unique_emails.add(domain["email"])

        emails_sent = 0
        html_generation_errors = 0
        email_sending_errors = 0
        detailed_errors = []

        logger.info(
            "[MONTHLY-DIGEST] Starting processing for %s unique emails",
            len(unique_emails),
        )

        # Send digest to each unique email
        for i, email in enumerate(unique_emails, 1):
            logger.info(
                "[MONTHLY-DIGEST] Processing %s/%s: %s", i, len(unique_emails), email
            )

            try:
                # Generate dashboard token and create session FIRST
                dashboard_token = await generate_confirmation_token(email)
                logger.debug("[MONTHLY-DIGEST] Generated token for %s", email)

                # Create session data (matches analytics.py:212-225 exactly)
                try:
                    session_client = datastore.Client()
                    logger.info(
                        "[MONTHLY-DIGEST] Creating session key for email: %s", email
                    )

                    alert_task_data = datastore.Entity(
                        session_client.key("xon_domains_session", email)
                    )
                    logger.info(
                        "[MONTHLY-DIGEST] Entity created, updating with token: %s",
                        dashboard_token,
                    )

                    alert_task_data.update(
                        {
                            "magic_timestamp": datetime.now(),
                            "domain_magic": dashboard_token,
                        }
                    )
                    logger.info(
                        "[MONTHLY-DIGEST] Data updated, putting to datastore..."
                    )

                    session_client.put(alert_task_data)
                    logger.info(
                        "[MONTHLY-DIGEST] ✅ Session successfully stored for %s with token %s",
                        email,
                        dashboard_token,
                    )

                    # Verify the session was created
                    verification_key = session_client.key("xon_domains_session", email)
                    verification_task = session_client.get(verification_key)
                    if verification_task:
                        logger.info(
                            "[MONTHLY-DIGEST] ✅ VERIFIED: Session exists with "
                            "magic_timestamp=%s and domain_magic=%s",
                            verification_task.get("magic_timestamp"),
                            verification_task.get("domain_magic"),
                        )
                    else:
                        logger.error(
                            "[MONTHLY-DIGEST] ❌ VERIFICATION FAILED: "
                            "Session not found after creation"
                        )

                except Exception as session_error:
                    logger.error(
                        "[MONTHLY-DIGEST] ❌ Failed to create session for %s: %s",
                        email,
                        str(session_error),
                    )
                    logger.error(
                        "[MONTHLY-DIGEST] ❌ Exception type: %s",
                        type(session_error).__name__,
                    )
                    import traceback

                    logger.error(
                        "[MONTHLY-DIGEST] ❌ Full traceback: %s", traceback.format_exc()
                    )
                    # Continue anyway, but log the error

                # Generate HTML content with the token
                html_content = await generate_monthly_digest_html(
                    email, dashboard_token
                )
                logger.debug(
                    "[MONTHLY-DIGEST] HTML generated successfully for %s", email
                )

                # Generate dashboard URL for testing (production domain, not API)
                dashboard_base_url = "https://xposedornot.com"
                email_param = f"email={email}"
                token_param = f"token={dashboard_token}"
                dashboard_url = (
                    f"{dashboard_base_url}/breach-dashboard?{email_param}&{token_param}"
                )

                # DEBUG: Log the dashboard URL for manual testing
                logger.info(
                    "[MONTHLY-DIGEST] 🔗 DASHBOARD URL for %s: %s", email, dashboard_url
                )
                logger.info(
                    "[MONTHLY-DIGEST] 🔑 TOKEN for %s: %s", email, dashboard_token
                )

                current_month = datetime.now(timezone.utc).strftime("%B")

                # EMAIL SENDING ENABLED FOR TESTING - sending to deva@xposedornot.com
                data = {
                    "Messages": [
                        {
                            "From": {"Email": FROM_EMAIL, "Name": FROM_NAME},
                            "To": [{"Email": "deva@xposedornot.com", "Name": "User"}],
                            "Subject": (
                                "🚨 New breaches detected — check your exposure ({} update)"
                            ).format(current_month),
                            "HTMLPart": html_content,
                            "TextPart": (
                                "XposedOrNot Monthly Digest - Visit https://xposedornot.com "
                                "to view your breach report for {}"
                            ).format(email),
                        }
                    ]
                }

                try:
                    async with httpx.AsyncClient() as http_client:
                        logger.debug(
                            "[MONTHLY-DIGEST] Attempting to send email for %s", email
                        )
                        response = await http_client.post(
                            MAILJET_API_URL,
                            json=data,
                            auth=(API_KEY, API_SECRET),
                            timeout=30.0,
                        )

                        if response.status_code == 200:
                            emails_sent += 1
                            logger.info(
                                "[MONTHLY-DIGEST] ✅ SUCCESS: Email sent for %s "
                                "to deva@xposedornot.com (#%s)",
                                email,
                                i,
                            )
                        else:
                            email_sending_errors += 1
                            error_msg = "Mailjet API error for {}: HTTP {} - {}".format(
                                email, response.status_code, response.text[:200]
                            )
                            detailed_errors.append(
                                {
                                    "email": email,
                                    "type": "api_error",
                                    "error": error_msg,
                                }
                            )
                            logger.error(
                                "[MONTHLY-DIGEST] ❌ API ERROR for %s: %s",
                                email,
                                error_msg,
                            )

                except httpx.RequestError as e:
                    email_sending_errors += 1
                    error_msg = "Network error for {}: {}".format(email, str(e))
                    detailed_errors.append(
                        {"email": email, "type": "network_error", "error": error_msg}
                    )
                    logger.error(
                        "[MONTHLY-DIGEST] ❌ NETWORK ERROR for %s: %s", email, error_msg
                    )
                except Exception as e:
                    email_sending_errors += 1
                    error_msg = "Email sending error for {}: {}".format(email, str(e))
                    detailed_errors.append(
                        {"email": email, "type": "send_error", "error": error_msg}
                    )
                    logger.error(
                        "[MONTHLY-DIGEST] ❌ SEND ERROR for %s: %s", email, error_msg
                    )

            except Exception as e:
                html_generation_errors += 1
                error_msg = "HTML generation error for {}: {}".format(email, str(e))
                detailed_errors.append(
                    {"email": email, "type": "html_error", "error": error_msg}
                )
                logger.error(
                    "[MONTHLY-DIGEST] ❌ HTML ERROR for %s: %s", email, error_msg
                )

        # Calculate totals
        total_errors = html_generation_errors + email_sending_errors
        success_rate = (emails_sent / len(unique_emails) * 100) if unique_emails else 0

        result = {
            "status": "success",
            "message": "Monthly digest processing complete",
            "emails_sent": emails_sent,
            "total_unique_emails": len(unique_emails),
            "html_generation_errors": html_generation_errors,
            "email_sending_errors": email_sending_errors,
            "total_errors": total_errors,
            "success_rate": round(success_rate, 2),
            "detailed_errors": (
                detailed_errors[:10] if detailed_errors else []
            ),  # Limit to 10 most recent
        }

        logger.info("[MONTHLY-DIGEST] 📊 FINAL SUMMARY:")
        logger.info("[MONTHLY-DIGEST] ✅ Emails sent successfully: %s", emails_sent)
        logger.info(
            "[MONTHLY-DIGEST] ❌ HTML generation errors: %s", html_generation_errors
        )
        logger.info(
            "[MONTHLY-DIGEST] ❌ Email sending errors: %s", email_sending_errors
        )
        logger.info(
            "[MONTHLY-DIGEST] 📈 Success rate: %.2f%% (%s/%s)",
            success_rate,
            emails_sent,
            len(unique_emails),
        )

        if detailed_errors:
            logger.error(
                "[MONTHLY-DIGEST] ⚠️ Error summary: %s total errors occurred",
                len(detailed_errors),
            )
            for error in detailed_errors[:5]:  # Log first 5 errors
                logger.error(
                    "[MONTHLY-DIGEST] - %s: %s - %s...",
                    error["email"],
                    error["type"],
                    error["error"][:100],
                )

        return result

    except Exception as e:
        error_msg = "Monthly digest processing failed: {}".format(str(e))
        logger.error(error_msg)
        raise Exception(error_msg)
