"""Analytics-related service functions."""

# Standard library imports
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional, Set

# Third-party imports
from fastapi import HTTPException
from google.cloud import datastore
from google.api_core import exceptions as google_exceptions
from openai import OpenAI
from openai import OpenAIError

# Initialize OpenAI client
ai_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# Logger
logger = logging.getLogger(__name__)

# Constants
TEMPERATURE = 0.7  # OpenAI temperature parameter

# Data categories mapping
data_categories = {
    "Names": {"category": "👤 Personal Identification", "group": "A"},
    "Usernames": {"category": "👤 Personal Identification", "group": "A"},
    "Genders": {"category": "👤 Personal Identification", "group": "A"},
    "Nationalities": {"category": "👤 Personal Identification", "group": "A"},
    "Ethnicities": {"category": "👤 Personal Identification", "group": "A"},
    "Places of Birth": {"category": "👤 Personal Identification", "group": "A"},
    "Photos": {"category": "👤 Personal Identification", "group": "A"},
    "Profile Photos": {"category": "👤 Personal Identification", "group": "A"},
    "Salutations": {"category": "👤 Personal Identification", "group": "A"},
    "Nicknames": {"category": "👤 Personal Identification", "group": "A"},
    "Vehicle Identification Numbers": {
        "category": "👤 Personal Identification",
        "group": "A",
    },
    "Licence Plates": {"category": "👤 Personal Identification", "group": "A"},
    "Social media profiles": {"category": "👤 Personal Identification", "group": "A"},
    "Avatars": {"category": "👤 Personal Identification", "group": "A"},
    "Credit Card Info": {"category": "💳 Financial Details", "group": "B"},
    "Income levels": {"category": "💳 Financial Details", "group": "B"},
    "Credit card details": {"category": "💳 Financial Details", "group": "B"},
    "Bank Account Numbers": {"category": "💳 Financial Details", "group": "B"},
    "Apps Installed on Devices": {
        "category": "🍔 Personal Habits and Lifestyle",
        "group": "C",
    },
    "Buying Preferences": {
        "category": "🍔 Personal Habits and Lifestyle",
        "group": "C",
    },
    "Drinking Habits": {"category": "🍔 Personal Habits and Lifestyle", "group": "C"},
    "Drug Habits": {"category": "🍔 Personal Habits and Lifestyle", "group": "C"},
    "Eating Habits": {"category": "🍔 Personal Habits and Lifestyle", "group": "C"},
    "Living Costs": {"category": "🍔 Personal Habits and Lifestyle", "group": "C"},
    "Travel Habits": {"category": "🍔 Personal Habits and Lifestyle", "group": "C"},
    "Work Habits": {"category": "🍔 Personal Habits and Lifestyle", "group": "C"},
    "Professional Skills": {
        "category": "🍔 Personal Habits and Lifestyle",
        "group": "C",
    },
    "Spoken languages": {"category": "🍔 Personal Habits and Lifestyle", "group": "C"},
    "Time Zones": {"category": "🍔 Personal Habits and Lifestyle", "group": "C"},
    "Vehicle Details": {"category": "🍔 Personal Habits and Lifestyle", "group": "C"},
    "Passwords": {"category": "🔒 Security Practices", "group": "D"},
    "Historical Passwords": {"category": "🔒 Security Practices", "group": "D"},
    "Password Hints": {"category": "🔒 Security Practices", "group": "D"},
    "Password Strengths": {"category": "🔒 Security Practices", "group": "D"},
    "Security Questions and Answers": {
        "category": "🔒 Security Practices",
        "group": "D",
    },
    "Security questions and answers": {
        "category": "🔒 Security Practices",
        "group": "D",
    },
    "Auth Tokens": {"category": "🔒 Security Practices", "group": "D"},
    "Encrypted Keys": {"category": "🔒 Security Practices", "group": "D"},
    "Mnemonic Phrases": {"category": "🔒 Security Practices", "group": "D"},
    "Job Applications": {"category": "🎓 Employment and Education", "group": "E"},
    "Job titles": {"category": "🎓 Employment and Education", "group": "E"},
    "Employers": {"category": "🎓 Employment and Education", "group": "E"},
    "Employment Statuses": {"category": "🎓 Employment and Education", "group": "E"},
    "Occupations": {"category": "🎓 Employment and Education", "group": "E"},
    "Education Levels": {"category": "🎓 Employment and Education", "group": "E"},
    "Years of Professional Experience": {
        "category": "🎓 Employment and Education",
        "group": "E",
    },
    "School Grades (Class Levels)": {
        "category": "🎓 Employment and Education",
        "group": "E",
    },
    "Email addresses": {
        "category": "📞 Communication and Social Interactions",
        "group": "F",
    },
    "Email Messages": {
        "category": "📞 Communication and Social Interactions",
        "group": "F",
    },
    "Chat Logs": {"category": "📞 Communication and Social Interactions", "group": "F"},
    "Instant Messenger Identities": {
        "category": "📞 Communication and Social Interactions",
        "group": "F",
    },
    "Instant messenger identities": {
        "category": "📞 Communication and Social Interactions",
        "group": "F",
    },
    "Phone numbers": {
        "category": "📞 Communication and Social Interactions",
        "group": "F",
    },
    "Private Messages": {
        "category": "📞 Communication and Social Interactions",
        "group": "F",
    },
    "Social connections": {
        "category": "📞 Communication and Social Interactions",
        "group": "F",
    },
    "IP addresses": {"category": "🖥️ Device and Network Information", "group": "G"},
    "Device information": {
        "category": "🖥️ Device and Network Information",
        "group": "G",
    },
    "Device Serial Numbers": {
        "category": "🖥️ Device and Network Information",
        "group": "G",
    },
    "Device Usage Tracking Data": {
        "category": "🖥️ Device and Network Information",
        "group": "G",
    },
    "Browser user agent details": {
        "category": "🖥️ Device and Network Information",
        "group": "G",
    },
    "MAC Addresses": {"category": "🖥️ Device and Network Information", "group": "G"},
    "IMEI Numbers": {"category": "🖥️ Device and Network Information", "group": "G"},
    "IMSI Numbers": {"category": "🖥️ Device and Network Information", "group": "G"},
    "Homepage URLs": {"category": "🖥️ Device and Network Information", "group": "G"},
    "User Website URLs": {
        "category": "🖥️ Device and Network Information",
        "group": "G",
    },
    "Website Activity": {"category": "🖥️ Device and Network Information", "group": "G"},
    "Personal Health Data": {"category": "🩺 Health Information", "group": "H"},
    "HIV Statuses": {"category": "🩺 Health Information", "group": "H"},
    "Blood Types": {"category": "🩺 Health Information", "group": "H"},
    "Medical Conditions": {"category": "🩺 Health Information", "group": "H"},
    "Medications": {"category": "🩺 Health Information", "group": "H"},
    "Body Measurements": {"category": "🩺 Health Information", "group": "H"},
    "Physical Activity Levels": {"category": "🩺 Health Information", "group": "H"},
    "Physical Disabilities": {"category": "🩺 Health Information", "group": "H"},
    "Psychological Conditions": {"category": "🩺 Health Information", "group": "H"},
    "Sexual Orientations": {"category": "🩺 Health Information", "group": "H"},
    "Dietary Preferences": {"category": "🩺 Health Information", "group": "H"},
    "Gambling Habits": {"category": "🩺 Health Information", "group": "H"},
    "Smoking Habits": {"category": "🩺 Health Information", "group": "H"},
    "Sexual Fetishes": {"category": "🩺 Health Information", "group": "H"},
    "Sleep Patterns": {"category": "🩺 Health Information", "group": "H"},
    "Ages": {"category": "Demographics", "group": "I"},
    "Dates of birth": {"category": "👥 Demographics", "group": "I"},
    "Physical addresses": {"category": "👥 Demographics", "group": "I"},
    "Geographic locations": {"category": "👥 Demographics", "group": "I"},
    "GPS Coordinates": {"category": "👥 Demographics", "group": "I"},
    "Languages": {"category": "👥 Demographics", "group": "I"},
    "Marital statuses": {"category": "👥 Demographics", "group": "I"},
    "Political Views": {"category": "👥 Demographics", "group": "I"},
    "Religions": {"category": "👥 Demographics", "group": "I"},
    "Races": {"category": "👥 Demographics", "group": "I"},
    "Astronomical Observations": {"category": "Science and Technology", "group": "J"},
    "Chemical Analyses": {"category": "Science and Technology", "group": "J"},
    "Scientific Measurements": {"category": "Science and Technology", "group": "J"},
    "Weather Observations": {"category": "Science and Technology", "group": "J"},
    "Books Read": {"category": "Arts and Entertainment", "group": "K"},
    "Games Played": {"category": "Arts and Entertainment", "group": "K"},
    "Movies Watched": {"category": "Arts and Entertainment", "group": "K"},
    "Music Listened To": {"category": "Arts and Entertainment", "group": "K"},
    "Photos Uploaded": {"category": "Arts and Entertainment", "group": "K"},
    "Videos Watched": {"category": "Arts and Entertainment", "group": "K"},
    "Aircraft Details": {"category": "Transport and Travel", "group": "L"},
    "Flight Details": {"category": "Transport and Travel", "group": "L"},
    "Public Transport Details": {"category": "Transport and Travel", "group": "L"},
    "Shipping Details": {"category": "Transport and Travel", "group": "L"},
    # Additional types found in real breach data
    "Social security numbers": {"category": "👤 Personal Identification", "group": "A"},
    "Government IDs": {"category": "👤 Personal Identification", "group": "A"},
    "Government issued IDs": {"category": "👤 Personal Identification", "group": "A"},
    "Passport numbers": {"category": "👤 Personal Identification", "group": "A"},
    "Mothers maiden names": {"category": "🔒 Security Practices", "group": "D"},
    "Account balances": {"category": "💳 Financial Details", "group": "B"},
    "Credit cards": {"category": "💳 Financial Details", "group": "B"},
    "Partial credit card data": {"category": "💳 Financial Details", "group": "B"},
    "Spouses details": {"category": "👥 Demographics", "group": "I"},
    "Years of birth": {"category": "👥 Demographics", "group": "I"},
    "Sexual preferences": {"category": "🩺 Health Information", "group": "H"},
    "Browsers": {"category": "🖥️ Device and Network Information", "group": "G"},
}

# AI prompts for breach data analysis
AI_SYSTEM_PROMPT = (
    "You are a cybersecurity expert providing clear, actionable insights about data breaches. "
    "Summarize the breach details in a conversational tone, analytical and provide recommendations "
    "based on risks. Avoid calling or referencing other security products or tools and keep "
    "recommendations generic."
)

AI_USER_PROMPT_TEMPLATE = (
    "Here is the breach data: {breach_data}. "
    "Analyze and provide an insightful summary in a conversational tone with analytical data, "
    "risks along with recommendations. Limit the recommendation to the user level only. "
    "Start with a single para summarizing the breaches with title summary of key data breaches. "
    "if the breaches are too large in count, talk about the ones with significant risk or size. "
    "Next section should be the risk assessment. highlight the issues. "
    "Call out all plain text password breaches. finally provide a recommendation with bullets "
    "with title Recommendations for you. All topics can have titles in bold text. "
    "also highlight text which needs focus or attention. Make the language simple and make it "
    "humanized. all titles should start with these emojis. Add magnifying glass for summary, "
    "red siren for risk assessment and blue shield for recommendations. add para breaks or "
    "line breaks as appropriate and make it look presentable. after recommendations add a line "
    "break and then give that final one liner or two as closure. finally you can also add one "
    "additional line with a blog link to how to avoid account take over and what to do if your "
    "data is breached - https://blog.xposedornot.com/what-should-you-do-after-data-breach/. "
    "add line breaks <br> afer every section and one between section and subsequent text. "
    "Use markdown for easy readability and highlight essential points."
)


# Data type normalization for handling typos, variants, and compound entries
DATA_TYPE_ALIASES = {
    "Name": "Names",
    "Username": "Usernames",
    "User names": "Usernames",
    "Email addresse": "Email addresses",
    "Drink habits": "Drinking Habits",
    "Passwords history": "Historical Passwords",
    "Sexual preferences": "Sexual Orientations",
}

# Known compound entries that need special splitting
COMPOUND_FIXES = {
    "GendersDates of birth": ["Genders", "Dates of birth"],
}

# Risk tier definitions
# CRITICAL: Direct account takeover or financial fraud
_CRITICAL_TYPES = {
    "Passwords",
    "Historical Passwords",
    "Credit Card Info",
    "Credit card details",
    "Credit cards",
    "Bank Account Numbers",
    "Account balances",
    "Social security numbers",
    "Government IDs",
    "Government issued IDs",
    "Passport numbers",
    "Mothers maiden names",
    "Security Questions and Answers",
    "Security questions and answers",
    "Auth Tokens",
    "Mnemonic Phrases",
}

# HIGH: Identity theft enablers, SIM swap risk
_HIGH_TYPES = {
    "Phone numbers",
    "Physical addresses",
    "Dates of birth",
    "Years of birth",
    "Income levels",
    "Private Messages",
    "Sexual Orientations",
    "Sexual Fetishes",
    "Partial credit card data",
    "Encrypted Keys",
    "Password Hints",
    "Personal Health Data",
    "HIV Statuses",
    "Medical Conditions",
    "Medications",
    "Psychological Conditions",
    "Physical Disabilities",
    "Email Messages",
    "Chat Logs",
    "GPS Coordinates",
}

# MEDIUM: Useful for social engineering
_MEDIUM_TYPES = {
    "Names",
    "Usernames",
    "Email addresses",
    "IP addresses",
    "Employers",
    "Occupations",
    "Nationalities",
    "Ethnicities",
    "Education Levels",
    "Marital statuses",
    "Vehicle Details",
    "Vehicle Identification Numbers",
    "Licence Plates",
    "Ages",
    "Religions",
    "Political Views",
    "Races",
    "Spouses details",
    "MAC Addresses",
    "IMEI Numbers",
    "IMSI Numbers",
    "Social connections",
    "Instant Messenger Identities",
    "Instant messenger identities",
    "Employment Statuses",
    "Job titles",
    "Password Strengths",
}

# Points per tier
TIER_POINTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
DEFAULT_TIER_POINTS = TIER_POINTS["MEDIUM"]


def normalize_data_types(raw_data: str) -> Set[str]:
    """
    Normalize raw xposed_data string into a set of canonical data type names.
    Handles semicolon/comma delimiters, compound entries, typos, and aliases.
    """
    normalized = set()
    parts = [p.strip() for p in raw_data.split(";") if p.strip()]

    for part in parts:
        # Check for known compound fixes (no separator)
        if part in COMPOUND_FIXES:
            for fixed in COMPOUND_FIXES[part]:
                normalized.add(DATA_TYPE_ALIASES.get(fixed, fixed))
            continue

        # Split on commas (secondary delimiter for compound entries)
        sub_parts = [s.strip() for s in part.split(",") if s.strip()]

        for sub in sub_parts:
            canonical = DATA_TYPE_ALIASES.get(sub, sub)
            normalized.add(canonical)

    return normalized


def get_tier_points(data_type: str) -> int:
    """Get risk tier points for a data type."""
    if data_type in _CRITICAL_TYPES:
        return TIER_POINTS["CRITICAL"]
    if data_type in _HIGH_TYPES:
        return TIER_POINTS["HIGH"]
    if data_type in _MEDIUM_TYPES:
        return TIER_POINTS["MEDIUM"]
    if data_type in data_categories:
        return TIER_POINTS["LOW"]
    # Unknown type - log and default to MEDIUM
    logger.info("Unmapped data type encountered: '%s'", data_type)
    return DEFAULT_TIER_POINTS


def calculate_risk_score(
    total_breaches: int,
    password_counts: Dict[str, int],
    breach_dates: List[datetime],
    exposed_data_types: Set[str],
) -> Tuple[int, str]:
    """
    Calculate weighted exposure risk score (0-100).

    Primary signal: per-data-type tier scoring (CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1)
    Modifiers: breach frequency, recency, plaintext passwords

    Display zones:
      0-25:  Low (green)
      26-50: Moderate (yellow)
      51-75: High (orange)
      76-100: Critical (red)

    Returns tuple of (risk_score, risk_label)
    """
    # Step 1: Raw score from data type tiers
    raw_score = sum(get_tier_points(dt) for dt in exposed_data_types)

    # Step 2: Modifiers
    modifier = 1.0

    # Breach frequency: +1% per breach with plaintext/easytocrack beyond the first, cap +15%
    critical_breach_count = password_counts.get("PlainText", 0) + password_counts.get(
        "EasyToCrack", 0
    )
    if critical_breach_count > 1:
        modifier += min(0.15, (critical_breach_count - 1) * 0.01)

    # Recency: +15% if most recent breach ≤12 months, +8% if ≤24 months
    if breach_dates:
        most_recent = max(breach_dates)
        months_since = (datetime.now().date() - most_recent).days / 30
        if months_since <= 12:
            modifier += 0.15
        elif months_since <= 24:
            modifier += 0.08

    # Plaintext password penalty: +10%
    if password_counts.get("PlainText", 0) > 0:
        modifier += 0.10

    # Step 3: Final score
    final_score = min(100, round(raw_score * modifier))

    # Step 4: Risk label (4 zones)
    if final_score >= 76:
        risk_label = "Critical"
    elif final_score >= 51:
        risk_label = "High"
    elif final_score >= 26:
        risk_label = "Moderate"
    else:
        risk_label = "Low"

    return (final_score, risk_label)


def get_breaches(breaches: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Returns the exposed breaches with details including records, domain, industry,
    and other metadata.
    """
    ds_client = datastore.Client()
    breaches_output = {"breaches_details": []}

    breaches = breaches.split(";")

    for breach in breaches:
        try:
            key = ds_client.key("xon_breaches", breach)
            query_result = ds_client.get(key)

            if query_result is not None:
                xposed_records = query_result.get("xposed_records", 0)
                breach_date = query_result.get("breached_date")
                breach_year = breach_date.strftime("%Y") if breach_date else ""

                # Convert searchable to "Yes"/"No" string format
                searchable = query_result.get("searchable", "")
                if isinstance(searchable, bool):
                    searchable = "Yes" if searchable else "No"
                elif isinstance(searchable, str):
                    searchable = (
                        "Yes"
                        if searchable.lower() in ("true", "t", "yes", "y", "1")
                        else "No"
                    )

                # Convert verified to "Yes"/"No" string format
                verified = query_result.get("verified", "")
                if isinstance(verified, bool):
                    verified = "Yes" if verified else "No"
                elif isinstance(verified, str):
                    verified = (
                        "Yes"
                        if verified.lower() in ("true", "t", "yes", "y", "1")
                        else "No"
                    )

                # Get timestamp for sorting (ISO 8601 format)
                timestamp = query_result.get("timestamp")
                if timestamp:
                    # Ensure UTC timezone and format as ISO 8601
                    added = timestamp.replace(microsecond=0).isoformat()
                else:
                    added = None

                breach_details = {
                    "breach": breach,
                    "details": query_result.get("xposure_desc", ""),
                    "domain": query_result.get("domain", ""),
                    "industry": query_result.get("industry", ""),
                    "logo": query_result.get("logo", ""),
                    "password_risk": query_result.get("password_risk", ""),
                    "references": query_result.get("references", ""),
                    "searchable": searchable,
                    "verified": verified,
                    "xposed_data": query_result.get("xposed_data", ""),
                    "xposed_date": breach_year,
                    "xposed_records": xposed_records,
                    "added": added,
                }
                breaches_output["breaches_details"].append(breach_details)
            else:
                raise HTTPException(status_code=404, detail="Breach not found")

        except Exception as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    # Sort breaches by 'added' timestamp in descending order (most recent first)
    breaches_output["breaches_details"].sort(
        key=lambda x: x.get("added") or "", reverse=True
    )

    return breaches_output


def get_breaches_data(breaches: str) -> dict:
    """Returns a dictionary with the count of various types of exposed data in breaches"""
    try:
        ds_client = datastore.Client()
        breach_list = breaches.split(";")

        # Initialize metrics structure
        metrics = {
            "get_details": [],
            "industry": [
                [
                    ["misc", 0],
                    ["ente", 0],
                    ["heal", 0],
                    ["elec", 0],
                    ["mini", 0],
                    ["musi", 0],
                    ["manu", 0],
                    ["ener", 0],
                    ["news", 0],
                    ["hosp", 0],
                    ["food", 0],
                    ["phar", 0],
                    ["educ", 0],
                    ["cons", 0],
                    ["agri", 0],
                    ["tele", 0],
                    ["info", 0],
                    ["tran", 0],
                    ["aero", 0],
                    ["fina", 0],
                    ["reta", 0],
                    ["nonp", 0],
                    ["govt", 0],
                    ["spor", 0],
                    ["envi", 0],
                ]
            ],
            "passwords_strength": [
                {"EasyToCrack": 0, "PlainText": 0, "StrongHash": 0, "Unknown": 0}
            ],
            "risk": [{"risk_label": "Low", "risk_score": 0}],
            "xposed_data": [],
            "yearwise_details": [
                {
                    "y2007": 0,
                    "y2008": 0,
                    "y2009": 0,
                    "y2010": 0,
                    "y2011": 0,
                    "y2012": 0,
                    "y2013": 0,
                    "y2014": 0,
                    "y2015": 0,
                    "y2016": 0,
                    "y2017": 0,
                    "y2018": 0,
                    "y2019": 0,
                    "y2020": 0,
                    "y2021": 0,
                    "y2022": 0,
                    "y2023": 0,
                    "y2024": 0,
                    "y2025": 0,
                    "y2026": 0,
                }
            ],
        }

        # Process each breach
        exposed_data_types = set()
        date_list = []
        password_risk_counters = {
            "PlainText": 0,
            "EasyToCrack": 0,
            "StrongHash": 0,
            "Unknown": 0,
        }

        for breach in breach_list:
            try:
                key = ds_client.key("xon_breaches", breach)
                query_result = ds_client.get(key)

                if query_result:
                    # Update industry count
                    industry = query_result.get("industry", "").lower()[:4]
                    for ind in metrics["industry"][0]:
                        if ind[0] == industry:
                            ind[1] += 1

                    # Collect breach dates
                    if breach_date := query_result.get("breached_date"):
                        date_list.append(breach_date.date())
                        year = breach_date.year
                        if 2007 <= year <= 2026:
                            metrics["yearwise_details"][0][f"y{year}"] += 1

                    # Update password strength counters
                    password_risk = query_result.get("password_risk", "").lower()
                    if password_risk == "plaintext":
                        password_risk_counters["PlainText"] += 1
                        metrics["passwords_strength"][0]["PlainText"] += 1
                    elif password_risk == "easytocrack":
                        password_risk_counters["EasyToCrack"] += 1
                        metrics["passwords_strength"][0]["EasyToCrack"] += 1
                    elif password_risk == "hardtocrack":
                        password_risk_counters["StrongHash"] += 1
                        metrics["passwords_strength"][0]["StrongHash"] += 1
                    else:
                        password_risk_counters["Unknown"] += 1
                        metrics["passwords_strength"][0]["Unknown"] += 1

                    # Collect exposed data types (normalized)
                    if xposed_data := query_result.get("xposed_data"):
                        normalized_types = normalize_data_types(xposed_data)
                        exposed_data_types.update(normalized_types)

            except Exception as e:
                continue

        # Calculate risk score using new method
        risk_score, risk_label = calculate_risk_score(
            total_breaches=len(breach_list),
            password_counts=password_risk_counters,
            breach_dates=date_list,
            exposed_data_types=exposed_data_types,
        )

        metrics["risk"] = [{"risk_label": risk_label, "risk_score": risk_score}]

        # Build exposed data hierarchy
        xposed_data_structure = {"children": []}

        # Process exposed data from each breach (normalized)
        exposed_data_counts = {}
        for breach in breach_list:
            key = ds_client.key("xon_breaches", breach)
            query_result = ds_client.get(key)
            if query_result and "xposed_data" in query_result:
                normalized = normalize_data_types(query_result["xposed_data"])
                for data_type in normalized:
                    exposed_data_counts[data_type] = (
                        exposed_data_counts.get(data_type, 0) + 1
                    )

        # Map exposed data to categories
        category_dict = {}
        for data_type, count in exposed_data_counts.items():
            if data_type in data_categories:
                category = data_categories[data_type]["category"]
                group = data_categories[data_type]["group"]

                if category not in category_dict:
                    category_dict[category] = {
                        "name": category,
                        "children": [],
                        "colname": "level2",
                    }

                category_dict[category]["children"].append(
                    {
                        "colname": "level3",
                        "group": group,
                        "name": f"data_{data_type}",
                        "value": 1,  # Count of occurrences
                    }
                )

        for category in category_dict.values():
            if category["children"]:
                xposed_data_structure["children"].append(category)

        metrics["xposed_data"] = [xposed_data_structure]

        return metrics

    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


async def get_summary_and_metrics(
    breach_record: Optional[Dict], sensitive_record: Optional[Dict]
) -> Tuple[
    Optional[Dict],
    Optional[Dict],
    Optional[Dict],
    Optional[Dict],
    Optional[Dict],
    Optional[Dict],
]:
    """Helper function to fetch the summary and metrics of breaches and pastes."""
    breach_summary = None
    paste_summary = None
    exposed_breaches = None
    exposed_pastes = None
    breach_metrics = None
    paste_metrics = None
    sensitive_breaches = None

    try:
        # Process regular breaches first
        if breach_record:
            site_name = str(breach_record.get("site", ""))

            # Only proceed if we have regular sites
            if site_name:
                breach_summary = {"site": site_name}
                exposed_breaches = get_breaches(site_name)
                breach_metrics = get_breaches_data(site_name)

        # Process sensitive sites if token is provided (indicated by sensitive_record being present)
        if sensitive_record is not None and breach_record:
            # Get sensitive sites from breach record
            sensitive_sites = str(breach_record.get("sensitive_site", ""))

            if sensitive_sites:
                sensitive_breaches = get_breaches(sensitive_sites)

                # Add sensitive sites to breach summary but keep breaches separate
                if breach_summary:
                    breach_summary["sensitive_site"] = sensitive_sites
                else:
                    breach_summary = {"site": "", "sensitive_site": sensitive_sites}

                # Update metrics to include both regular and sensitive breaches
                if breach_metrics:
                    sensitive_metrics = get_breaches_data(sensitive_sites)
                    # Combine metrics while keeping breach details separate
                    breach_metrics = _combine_metrics(breach_metrics, sensitive_metrics)
                else:
                    breach_metrics = get_breaches_data(sensitive_sites)

        # If we have sensitive breaches, add them to exposed_breaches under a separate key
        if sensitive_breaches:
            if not exposed_breaches:
                exposed_breaches = {
                    "breaches_details": [],
                    "sensitive_breaches_details": [],
                }
            exposed_breaches["sensitive_breaches_details"] = sensitive_breaches[
                "breaches_details"
            ]

        return (
            breach_summary,
            paste_summary,
            exposed_breaches,
            exposed_pastes,
            breach_metrics,
            paste_metrics,
        )
    except Exception as e:
        raise


def _combine_metrics(regular_metrics: Dict, sensitive_metrics: Dict) -> Dict:
    """Helper function to combine regular and sensitive breach metrics."""
    combined = regular_metrics.copy()

    # Combine industry counts
    for i, industry in enumerate(sensitive_metrics["industry"][0]):
        combined["industry"][0][i][1] += industry[1]

    # Combine password strength counts
    for key in combined["passwords_strength"][0]:
        combined["passwords_strength"][0][key] += sensitive_metrics[
            "passwords_strength"
        ][0][key]

    # Combine yearwise details
    for year in combined["yearwise_details"][0]:
        combined["yearwise_details"][0][year] += sensitive_metrics["yearwise_details"][
            0
        ][year]

    # Combine exposed data
    regular_data = combined["xposed_data"][0]["children"]
    sensitive_data = sensitive_metrics["xposed_data"][0]["children"]

    # Create a mapping of category names to their indices
    category_map = {cat["name"]: i for i, cat in enumerate(regular_data)}

    # Combine the data
    for sensitive_category in sensitive_data:
        if sensitive_category["name"] in category_map:
            # Category exists in regular data, combine children
            regular_idx = category_map[sensitive_category["name"]]
            regular_children = regular_data[regular_idx]["children"]

            # Create a map of existing children
            children_map = {
                child["name"]: i for i, child in enumerate(regular_children)
            }

            # Add or update children
            for sensitive_child in sensitive_category["children"]:
                if sensitive_child["name"] in children_map:
                    # Update existing child's value
                    child_idx = children_map[sensitive_child["name"]]
                    regular_children[child_idx]["value"] += sensitive_child["value"]
                else:
                    # Add new child
                    regular_children.append(sensitive_child)
        else:
            # Add new category
            regular_data.append(sensitive_category)

    # Recalculate risk score using unified formula
    # Extract exposed types from combined xposed_data structure
    exposed_types = set()
    for cat in combined["xposed_data"][0].get("children", []):
        for child in cat.get("children", []):
            name = child.get("name", "")
            if name.startswith("data_"):
                exposed_types.add(name[5:])

    # Approximate breach dates from yearwise (mid-year for recency check)
    breach_dates = []
    for year_key, count in combined["yearwise_details"][0].items():
        if count > 0:
            year = int(year_key[1:])
            breach_dates.append(datetime(year, 7, 1).date())

    total_breaches = sum(combined["yearwise_details"][0].values())

    risk_score, risk_label = calculate_risk_score(
        total_breaches=total_breaches,
        password_counts=combined["passwords_strength"][0],
        breach_dates=breach_dates,
        exposed_data_types=exposed_types,
    )
    combined["risk"] = [{"risk_label": risk_label, "risk_score": risk_score}]

    return combined


def get_ai_summary(breach_data: Dict[str, Any]) -> str:
    """Generate AI-powered summary of breach data."""
    try:
        system_prompt = AI_SYSTEM_PROMPT

        user_prompt = AI_USER_PROMPT_TEMPLATE.format(
            breach_data=json.dumps(breach_data, indent=2)
        )

        response = ai_client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            model="gpt-4",
            temperature=TEMPERATURE,
        )
        return response.choices[0].message.content
    except (ValueError, KeyError, json.JSONDecodeError, OpenAIError) as e:
        return "Error fetching AI summary: " + str(e)


async def get_detailed_metrics() -> Dict[str, Any]:
    """Get detailed metrics about breaches."""
    try:
        datastore_client = datastore.Client()
        metrics_key = datastore_client.key("xon_metrics", "metrics")
        metrics_data = datastore_client.get(metrics_key)

        if metrics_data is None:
            raise ValueError("Metrics not found")

        breaches_count = metrics_data["breaches_count"]
        breaches_total_records = metrics_data["breaches_records"]
        pastes_count = f"{metrics_data['pastes_count']:,}"
        pastes_total_records = metrics_data["pastes_records"]

        # Get all breaches for yearly count
        query = datastore_client.query(kind="xon_breaches")
        breaches = list(query.fetch())

        yearly_count = {}
        industry_count = {}

        for breach in breaches:
            # Get yearly counts
            breach_date = breach["breached_date"]
            year = breach_date.year
            yearly_count[year] = yearly_count.get(year, 0) + 1

            # Get industry counts
            industry = breach.get("industry", "Unknown")
            if industry:
                industry_count[industry] = industry_count.get(industry, 0) + 1
            else:
                industry_count["Unknown"] = industry_count.get("Unknown", 0) + 1

        # Get top breaches by exposed records
        query.order = ["-xposed_records"]
        top_breaches = list(query.fetch(limit=10))

        # Get recent breaches
        recent_query = datastore_client.query(kind="xon_breaches")
        recent_query.order = ["-timestamp"]
        recent_breaches = list(recent_query.fetch(limit=10))

        # Sort industry count by value for consistency
        industry_breaches_count = dict(
            sorted(industry_count.items(), key=lambda x: x[1], reverse=True)
        )

        return {
            "breaches_count": breaches_count,
            "breaches_total_records": breaches_total_records,
            "pastes_count": pastes_count,
            "pastes_total_records": pastes_total_records,
            "yearly_count": yearly_count,
            "industry_breaches_count": industry_breaches_count,
            "top_breaches": top_breaches,
            "recent_breaches": recent_breaches,
        }

    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


async def get_pulse_news() -> List[Dict[str, Any]]:
    """Get news feed for data breaches."""
    try:
        client = datastore.Client()
        query = client.query(kind="xon-pulse")
        results = list(query.fetch())

        news_items = []
        for entity in results:
            item = {
                "title": entity.get("title", ""),
                "date": entity.get("date").strftime("%Y-%b-%d"),
                "summary": entity.get("description", ""),
                "url": entity.get("url", ""),
            }
            news_items.append(item)

        return news_items

    except Exception as e:
        detail_msg = "Error fetching news feed: " + str(e)
        raise HTTPException(status_code=404, detail=detail_msg) from e


async def get_breaches_analytics(site: str) -> Dict[str, Any]:
    """Returns analytics of data breaches for a given site."""
    try:
        ds_client = datastore.Client()
        breach_list = site.split(";")

        total_breaches = len(breach_list)
        total_records = 0
        first_breach = None
        last_breach = None
        industry_count = {}

        for breach in breach_list:
            key = ds_client.key("xon_breaches", breach)
            breach_data = ds_client.get(key)

            if breach_data:
                records = breach_data.get("xposed_records", 0)
                total_records += records if isinstance(records, int) else 0

                breach_date = breach_data.get("breached_date")
                if breach_date:
                    if not first_breach or breach_date < first_breach:
                        first_breach = breach_date
                    if not last_breach or breach_date > last_breach:
                        last_breach = breach_date

                industry = breach_data.get("industry", "Unknown")
                if industry:
                    industry_count[industry] = industry_count.get(industry, 0) + 1
                else:
                    industry_count["Unknown"] = industry_count.get("Unknown", 0) + 1

        industry_breaches_count = dict(
            sorted(industry_count.items(), key=lambda x: x[1], reverse=True)
        )

        return {
            "total_breaches": total_breaches,
            "total_records": total_records,
            "first_breach": first_breach.strftime("%Y-%m-%d") if first_breach else None,
            "last_breach": last_breach.strftime("%Y-%m-%d") if last_breach else None,
            "industry_breaches_count": industry_breaches_count,
        }

    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
