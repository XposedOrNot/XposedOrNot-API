"""Helper functions for optimized monthly digest processing."""

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from google.cloud import datastore

from config.clients import ds_client
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
                    "Processing still active at "
                    f"{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}"
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
        "target_month_start": target_month_start,
        "target_month_end": target_month_end,
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
        batch_num = (i // batch_size) + 1
        try:
            client.put_multi(batch)
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
                            <div style="margin: 4px 0;"><strong>Breached:</strong> {
                            escape_html(exposure.get('breach_date', 'Unknown'))}</div>
                            <div style="margin: 4px 0;"><strong>Added:</strong> {
                            escape_html(exposure.get('added_date', 'Unknown'))}</div>
                            <div style="margin: 4px 0;"><strong>Records:</strong> {
                            exposure.get('records_count', 0):,}</div>
                            <div style="margin: 8px 0 0 0; padding: 8px; background-color: #f8f9fa; border-radius: 4px; font-size: 12px;">
                                <strong>Data Exposed:</strong><br>{
                                escape_html(exposure.get('data_exposed', 'Unknown'))}
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
                            <div style="margin: 4px 0;"><strong>Breached:</strong> {
                            escape_html(breach.get('breach_date', 'Unknown'))}</div>
                            <div style="margin: 4px 0;"><strong>Added:</strong> {
                            escape_html(breach.get('added_date', 'Unknown'))}</div>
                            <div style="margin: 4px 0;"><strong>Records:</strong> {
                            breach.get('records_count', 0):,}</div>
                            <div style="margin: 8px 0 0 0; padding: 8px; background-color: #f8f9fa; border-radius: 4px; font-size: 12px;">
                                <strong>Data Exposed:</strong><br>{
                                escape_html(breach.get('data_exposed', 'Unknown'))}
                            </div>
                        </div>
                    </div>"""
    return cards


DASHBOARD_HOME_URL = "https://xposedornot.com/dashboard"
BREACH_LIST_URL = "https://xposedornot.com/xposed"
MAX_EXPOSURE_CARDS = 10
MAX_EARLIER_ROWS = 5
MAX_CATALOGUE_ROWS = 5
MAX_DOMAINS_LISTED = 5

WRAPPER_STYLE = (
    "font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; "
    "padding: 15px; background-color: #f8f9fa;"
)
PANEL_STYLE = "background-color: #ffffff; border-radius: 8px; padding: 20px;"
CARD_STYLE = (
    "border: 1px solid #dee2e6; border-radius: 6px; padding: 12px; "
    "margin: 8px 0; background-color: #ffffff;"
)
CLEAN_STYLE = (
    "border: 1px solid #c3e6cb; border-radius: 6px; padding: 16px; "
    "margin: 8px 0; background-color: #d4edda; color: #155724; font-size: 14px;"
)
HEADING_STYLE = "color: #2c3e50; font-size: 16px; margin: 0 0 10px 0;"
TEXT_STYLE = "color: #34495e; font-size: 14px; line-height: 1.6; margin: 0 0 10px 0;"
MUTED_STYLE = "color: #6c757d; font-size: 13px; line-height: 1.5;"
BUTTON_STYLE = (
    "background-color: #2c3e50; color: #ffffff; padding: 10px 20px; "
    "text-decoration: none; border-radius: 6px; font-weight: bold; "
    "display: inline-block; font-size: 14px;"
)
LINK_STYLE = "color: #2980b9;"
LIST_STYLE = (
    "color: #34495e; font-size: 14px; line-height: 1.6; margin: 0; "
    "padding-left: 20px;"
)

ACTIONS_WHEN_EXPOSED = [
    "Reset passwords for the affected accounts and sign them out of active sessions.",
    "Enforce multi-factor authentication for those users.",
    "Check whether the exposed passwords are reused on your internal systems.",
]
ACTIONS_WHEN_CLEAN = [
    "Keep multi-factor authentication enforced for all users.",
    "Remind your team not to reuse work passwords on other sites.",
    "Check that every domain you own is verified so nothing is missed.",
]


def digest_target_month(now=None):
    """Return the start and end of the calendar month the digest reports on."""
    now = now or datetime.now(timezone.utc)
    month_end = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_start = (month_end - timedelta(days=1)).replace(day=1)
    return month_start, month_end


def format_data_types(raw) -> str:
    """Render the exposed data types of a breach as a comma separated list."""
    parts = raw if isinstance(raw, list) else str(raw or "").split(";")
    cleaned = [str(part).strip() for part in parts if str(part).strip()]
    return ", ".join(cleaned) if cleaned else "Not specified"


def format_count(value: int) -> str:
    """Render a large number in a short readable form."""
    for threshold, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
        if value >= threshold:
            return f"{value / threshold:.1f}".rstrip("0").rstrip(".") + suffix
    return str(value)


def plural(count: int, singular: str, plural_form: str) -> str:
    """Render a count with the matching singular or plural noun."""
    return f"{count:,} {singular if count == 1 else plural_form}"


def format_month_year(value) -> str:
    """Render a datetime as a short month and year, or Unknown."""
    try:
        return value.strftime("%b %Y") if value else "Unknown"
    except (AttributeError, ValueError):
        return "Unknown"


def collect_user_exposures(client, user_domains: list, all_breach_data: dict) -> list:
    """Collect the exposures of a user's domains from the last six months."""
    if not user_domains:
        return []

    breach_details = all_breach_data.get("breach_details", {})
    month_start = all_breach_data.get("target_month_start") or digest_target_month()[0]
    six_months_ago = datetime.now(timezone.utc) - timedelta(days=180)

    query = client.query(kind="xon_domains_summary")
    query.add_filter("domain", "IN", user_domains)

    exposures = []
    for entity in query.fetch():
        if entity["breach"] == "No_Breaches":
            continue
        breach = breach_details.get(entity["breach"])
        if not breach or not breach.get("timestamp"):
            continue
        if breach["timestamp"] < six_months_ago:
            continue
        exposures.append(
            {
                "breach_name": entity.get("breach", "Unknown"),
                "breach_date": format_month_year(breach.get("breached_date")),
                "added_date": format_month_year(breach.get("timestamp")),
                "data_exposed": format_data_types(breach.get("xposed_data", "")),
                "email_count": int(entity.get("email_count") or 0),
                "domain": entity.get("domain", "Unknown"),
                "is_new": breach["timestamp"] >= month_start,
            }
        )

    exposures.sort(key=lambda item: item["email_count"], reverse=True)
    return exposures


def summarise_exposures(exposures: list) -> dict:
    """Count the distinct breaches and the email exposures in a list."""
    return {
        "breaches": len({item["breach_name"] for item in exposures}),
        "emails": sum(item["email_count"] for item in exposures),
    }


def emails_phrase(count: int) -> str:
    """Describe how many of the user's emails a breach contains."""
    if count <= 0:
        return "Emails from your domain"
    return f"{plural(count, 'email', 'emails')} from your domain"


def domains_label(user_domains: list) -> str:
    """List the user's domains, shortened when there are many."""
    shown = user_domains[:MAX_DOMAINS_LISTED]
    label = ", ".join(shown)
    extra = len(user_domains) - len(shown)
    if extra > 0:
        label += f" and {extra} more"
    return label


def build_digest_subject(
    user_domains: list, new_exposures: list, month_name: str
) -> str:
    """Build a subject line that reflects the user's own result."""
    if len(user_domains) == 1:
        label = user_domains[0]
    else:
        label = f"Your {len(user_domains)} domains"

    if not new_exposures:
        return f"{label}: no new exposure in {month_name}"

    totals = summarise_exposures(new_exposures)
    breaches = plural(totals["breaches"], "new breach", "new breaches")
    if totals["emails"] > 0:
        exposures = plural(totals["emails"], "email exposure", "email exposures")
        return f"{label}: {exposures} in {breaches} ({month_name})"
    return f"{label}: {breaches} affecting your emails ({month_name})"


def top_catalogue_breaches(new_breaches: list) -> list:
    """Return the largest breaches added in the target month."""
    ranked = sorted(
        new_breaches, key=lambda item: item.get("records_count", 0), reverse=True
    )
    return ranked[:MAX_CATALOGUE_ROWS]


def render_new_exposures_html(new_exposures: list, month_name: str) -> str:
    """Render the cards for exposures that are new in this digest."""
    if not new_exposures:
        return (
            f'<div style="{CLEAN_STYLE}"><strong>No new exposure.</strong> '
            "No emails from your domains appeared in the breaches we added in "
            f"{escape_html(month_name)}.</div>"
        )

    cards = []
    for exposure in new_exposures[:MAX_EXPOSURE_CARDS]:
        cards.append(
            f'<div style="{CARD_STYLE}">'
            '<div style="font-weight: bold; color: #2c3e50; font-size: 16px;">'
            f"{escape_html(exposure['breach_name'])}</div>"
            '<div style="color: #c0392b; font-size: 14px; font-weight: bold; '
            'margin: 6px 0;">'
            f"{escape_html(emails_phrase(exposure['email_count']))} "
            f"({escape_html(exposure['domain'])})</div>"
            f'<div style="{MUTED_STYLE}">'
            f"Breached {escape_html(exposure['breach_date'])} &middot; "
            f"Added {escape_html(exposure['added_date'])}</div>"
            f'<div style="{MUTED_STYLE}">'
            f"Data exposed: {escape_html(exposure['data_exposed'])}</div>"
            "</div>"
        )

    hidden = len(new_exposures) - MAX_EXPOSURE_CARDS
    if hidden > 0:
        cards.append(
            f'<p style="{MUTED_STYLE}">and {hidden:,} more in your dashboard.</p>'
        )
    return "".join(cards)


def render_earlier_exposures_html(earlier_exposures: list, dashboard_url: str) -> str:
    """Render the short list of exposures reported in earlier digests."""
    if not earlier_exposures:
        return ""

    totals = summarise_exposures(earlier_exposures)
    rows = []
    for exposure in earlier_exposures[:MAX_EARLIER_ROWS]:
        rows.append(
            f"<li><strong>{escape_html(exposure['breach_name'])}</strong>: "
            f"{escape_html(emails_phrase(exposure['email_count']))} "
            f"({escape_html(exposure['domain'])}), "
            f"added {escape_html(exposure['added_date'])}</li>"
        )

    hidden = len(earlier_exposures) - MAX_EARLIER_ROWS
    more = f"<li>and {hidden:,} more</li>" if hidden > 0 else ""

    return (
        '<div style="margin: 25px 0;">'
        f'<h2 style="{HEADING_STYLE}">Earlier exposures (last 6 months)</h2>'
        f'<p style="{TEXT_STYLE}">'
        f"{plural(totals['breaches'], 'breach', 'breaches')}, "
        f"{plural(totals['emails'], 'email exposure', 'email exposures')}. "
        "Worth a second look if you have not acted on them yet.</p>"
        f'<ul style="{LIST_STYLE}">{"".join(rows)}{more}</ul>'
        f'<p style="{TEXT_STYLE} margin-top: 10px;">'
        f'<a href="{dashboard_url}" style="{LINK_STYLE}">'
        "Review them in your dashboard</a></p>"
        "</div>"
    )


def render_catalogue_html(new_breaches: list, month_name: str) -> str:
    """Render the summary of every breach added in the target month."""
    heading = (
        f'<h2 style="{HEADING_STYLE}">'
        f"Also added to XposedOrNot in {escape_html(month_name)}</h2>"
    )
    if not new_breaches:
        return (
            f'<div style="margin: 25px 0;">{heading}'
            f'<p style="{TEXT_STYLE}">No new breaches were added in '
            f"{escape_html(month_name)}.</p></div>"
        )

    total_records = sum(item.get("records_count", 0) for item in new_breaches)
    rows = []
    for breach in top_catalogue_breaches(new_breaches):
        rows.append(
            f"<li><strong>{escape_html(breach['breach_name'])}</strong>: "
            f"{format_count(breach.get('records_count', 0))} records. "
            f"{escape_html(format_data_types(breach.get('data_exposed', '')))}</li>"
        )

    hidden = len(new_breaches) - MAX_CATALOGUE_ROWS
    more = f"<li>and {hidden:,} more</li>" if hidden > 0 else ""

    return (
        f'<div style="margin: 25px 0;">{heading}'
        f'<p style="{TEXT_STYLE}">'
        f"{plural(len(new_breaches), 'breach', 'breaches')}, "
        f"{format_count(total_records)} records in total. The largest:</p>"
        f'<ul style="{LIST_STYLE}">{"".join(rows)}{more}</ul>'
        f'<p style="{TEXT_STYLE} margin-top: 10px;">'
        f'<a href="{BREACH_LIST_URL}" style="{LINK_STYLE}">'
        "See the complete breach list</a></p>"
        "</div>"
    )


def render_actions_html(has_new_exposures: bool) -> str:
    """Render the recommended actions for a domain administrator."""
    if has_new_exposures:
        heading = "What to do now"
        actions = ACTIONS_WHEN_EXPOSED
    else:
        heading = "Good habits to keep"
        actions = ACTIONS_WHEN_CLEAN
    items = "".join(f"<li>{escape_html(action)}</li>" for action in actions)
    return (
        '<div style="background-color: #e8f4fd; border-left: 4px solid #3498db; '
        'padding: 16px; margin: 25px 0; border-radius: 6px;">'
        f'<h2 style="{HEADING_STYLE}">{heading}</h2>'
        f'<ul style="{LIST_STYLE}">{items}</ul>'
        "</div>"
    )


def render_digest_html(context: dict) -> str:
    """Render the full HTML body of the monthly digest."""
    month_name = context["month_name"]
    new_exposures = context["new_exposures"]
    dashboard_url = context["dashboard_url"]
    domains_text = escape_html(domains_label(context["user_domains"]))

    button = ""
    if new_exposures:
        button = (
            '<div style="text-align: center; margin: 15px 0;">'
            f'<a href="{dashboard_url}" style="{BUTTON_STYLE}">'
            "See affected emails in your dashboard</a></div>"
        )

    return (
        f'<div style="{WRAPPER_STYLE}"><div style="{PANEL_STYLE}">'
        '<div style="text-align: center; margin-bottom: 20px;">'
        '<h1 style="color: #2c3e50; margin: 0; font-size: 22px;">'
        f"Your {escape_html(month_name)} breach digest</h1>"
        f'<p style="{MUTED_STYLE} margin: 8px 0 0 0;">'
        f"Domains monitored: {domains_text}</p>"
        "</div>"
        '<div style="margin: 25px 0;">'
        f'<h2 style="{HEADING_STYLE}">New for your domains</h2>'
        f"{render_new_exposures_html(new_exposures, month_name)}"
        f"{button}"
        "</div>"
        f"{render_earlier_exposures_html(context['earlier_exposures'], dashboard_url)}"
        f"{render_catalogue_html(context['new_breaches'], month_name)}"
        f"{render_actions_html(bool(new_exposures))}"
        '<div style="text-align: center; margin: 25px 0 15px 0; padding-top: 20px; '
        'border-top: 1px solid #dee2e6;">'
        f'<p style="{TEXT_STYLE}">Stay safe,<br>'
        "<strong>The XposedOrNot Team</strong></p>"
        "</div>"
        '<div style="padding: 15px; border-top: 1px solid #dee2e6; font-size: 12px; '
        'color: #6c757d; text-align: center;">'
        '<p style="margin: 0 0 8px 0;">You are receiving this because '
        f"<strong>{escape_html(context['email'])}</strong> verified "
        f"{domains_text} on XposedOrNot.</p>"
        f'<p style="margin: 0;">&copy; {context["year"]} XposedOrNot | '
        f'<a href="{DASHBOARD_HOME_URL}" style="color: #6c757d;">'
        "Open your dashboard</a></p>"
        "</div>"
        "</div></div>"
    )


def render_digest_text(context: dict) -> str:
    """Render the plain text body of the monthly digest."""
    month_name = context["month_name"]
    new_exposures = context["new_exposures"]
    earlier_exposures = context["earlier_exposures"]
    new_breaches = context["new_breaches"]

    lines = [
        f"Your {month_name} breach digest",
        f"Domains monitored: {domains_label(context['user_domains'])}",
        "",
        "NEW FOR YOUR DOMAINS",
    ]

    if new_exposures:
        for exposure in new_exposures[:MAX_EXPOSURE_CARDS]:
            lines.append(
                f"- {exposure['breach_name']}: "
                f"{emails_phrase(exposure['email_count'])} ({exposure['domain']}). "
                f"Breached {exposure['breach_date']}, added {exposure['added_date']}. "
                f"Data exposed: {exposure['data_exposed']}"
            )
        hidden = len(new_exposures) - MAX_EXPOSURE_CARDS
        if hidden > 0:
            lines.append(f"- and {hidden:,} more in your dashboard")
        lines.append(f"See affected emails: {context['dashboard_url_text']}")
    else:
        lines.append(
            "No emails from your domains appeared in the breaches we added in "
            f"{month_name}."
        )

    if earlier_exposures:
        totals = summarise_exposures(earlier_exposures)
        lines += [
            "",
            "EARLIER EXPOSURES (LAST 6 MONTHS)",
            f"{plural(totals['breaches'], 'breach', 'breaches')}, "
            f"{plural(totals['emails'], 'email exposure', 'email exposures')}. "
            f"Review them: {context['dashboard_url_text']}",
        ]

    lines += ["", f"ALSO ADDED TO XPOSEDORNOT IN {month_name.upper()}"]
    if new_breaches:
        total_records = sum(item.get("records_count", 0) for item in new_breaches)
        lines.append(
            f"{plural(len(new_breaches), 'breach', 'breaches')}, "
            f"{format_count(total_records)} records in total. The largest:"
        )
        for breach in top_catalogue_breaches(new_breaches):
            lines.append(
                f"- {breach['breach_name']}: "
                f"{format_count(breach.get('records_count', 0))} records"
            )
        lines.append(f"Complete list: {BREACH_LIST_URL}")
    else:
        lines.append(f"No new breaches were added in {month_name}.")

    actions = ACTIONS_WHEN_EXPOSED if new_exposures else ACTIONS_WHEN_CLEAN
    lines += ["", "WHAT TO DO NOW" if new_exposures else "GOOD HABITS TO KEEP"]
    lines += [f"- {action}" for action in actions]

    lines += [
        "",
        "Stay safe,",
        "The XposedOrNot Team",
        "",
        f"You are receiving this because {context['email']} verified "
        f"{domains_label(context['user_domains'])} on XposedOrNot.",
    ]
    return "\n".join(lines)


async def build_monthly_digest_content(
    email: str,
    dashboard_token: str,
    user_domains: list,
    all_breach_data: dict,
    client=None,
) -> dict:
    """Build the subject, HTML body and text body of one user's digest."""
    try:
        if client is None:
            client = ds_client

        month_start = (
            all_breach_data.get("target_month_start") or digest_target_month()[0]
        )
        month_name = month_start.strftime("%B")

        exposures = collect_user_exposures(client, user_domains, all_breach_data)
        new_exposures = [item for item in exposures if item["is_new"]]
        earlier_exposures = [item for item in exposures if not item["is_new"]]

        dashboard_url = build_safe_url(
            "https://xposedornot.com/breach-dashboard",
            {"email": email, "token": dashboard_token},
        )

        context = {
            "email": email,
            "user_domains": user_domains,
            "month_name": month_name,
            "year": datetime.now(timezone.utc).year,
            "new_exposures": new_exposures,
            "earlier_exposures": earlier_exposures,
            "new_breaches": all_breach_data.get("new_breaches", []),
            "dashboard_url": escape_html(dashboard_url),
            "dashboard_url_text": dashboard_url,
        }

        return {
            "subject": build_digest_subject(user_domains, new_exposures, month_name),
            "html": render_digest_html(context),
            "text": render_digest_text(context),
        }

    except Exception as e:
        logger.error(
            "[MONTHLY-DIGEST] ❌ Digest content generation failed for %s: %s",
            email,
            str(e),
        )
        raise
