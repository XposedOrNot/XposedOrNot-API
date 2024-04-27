#!/usr/bin/python3

"""XposedOrNot API module"""

# Standard Library Imports
import datetime
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
from collections import defaultdict
from datetime import timedelta, timezone
from operator import itemgetter
from urllib.parse import unquote, urlparse

# Related Third Party Imports
import domcheck
import requests
from cryptography.fernet import Fernet
from feedgen.feed import FeedGenerator
from flask import (
    Flask,
    abort,
    jsonify,
    make_response,
    render_template,
    request,
    url_for,
    send_from_directory,
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from google.cloud import datastore
from itsdangerous import SignatureExpired, URLSafeTimedSerializer
from user_agents import parse
from validate_email import validate_email

# Local Application/Library Specific Imports
from cloudflare import block_day, block_hour, unblock
from send_email import (
    send_alert_confirmation,
    send_dashboard_email_confirmation,
    send_domain_confirmation,
    send_domain_verified_success,
    send_exception_email,
    send_shield_email,
    send_unsub_email,
)

# Fetch environment variables
CF_MAGIC = os.environ["CF_MAGIC"]
CF_UNBLOCK_MAGIC = os.environ["CF_UNBLOCK_MAGIC"]
SECRET_APIKEY = os.environ["SECRET_APIKEY"]
SECURITY_SALT = os.environ["SECURITY_SALT"]
WTF_CSRF_SECRET_KEY = os.environ["WTF_CSRF_SECRET_KEY"]
XMLAPI_KEY = os.environ["XMLAPI_KEY"]
FERNET_KEY = os.environ.get("ENCRYPTION_KEY")
CIPHER_SUITE = Fernet(FERNET_KEY)

# Initialize the Flask app
XON = Flask(__name__)
CORS(XON)

# Configure the secret key
XON.config.update(SECRET_KEY=WTF_CSRF_SECRET_KEY)

# Initialize and configure CSRF protection
CSRF = CSRFProtect()
CSRF.init_app(XON)


def set_csp_headers(response):
    """Sets the Content-Security-Policy header for a given response object."""
    csp_value = (
        "default-src 'self';"
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://maxcdn.bootstrapcdn.com https://static.cloudflareinsights.com;"
        "style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com https://fonts.googleapis.com https://xposedornot.com;"
        "img-src 'self' https://xposedornot.com;"
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com;"
    )
    response.headers["Content-Security-Policy"] = csp_value
    return response


@XON.after_request
def apply_csp_headers(response):
    """A Flask after_request handler that applies CSP headers to responses."""
    return set_csp_headers(response)


@XON.after_request
def set_x_frame_options(response):
    """Sets the X-Frame-Options header to 'DENY' for all outgoing responses."""
    response.headers["X-Frame-Options"] = "DENY"
    return response


@XON.after_request
def set_referrer_policy(response):
    """Applies a strict-origin-when-cross-origin Referrer Policy to all responses."""
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@XON.after_request
def set_permissions_policy(response):
    """Sets a Permissions-Policy header on the response to disable powerful features."""
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), microphone=(), midi=(), payment=(), usb=()"
    )
    return response


@XON.after_request
def add_cache_control(response):
    """
    Adds Cache-Control headers to prevent caching of the response.
    """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


# Initialize and configure rate limiting
LIMITER = Limiter(
    app=XON,
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    headers_enabled=True,
)


@XON.errorhandler(404)
def not_found(error):
    """Returns response for 404"""
    return make_response(jsonify({"Error": "Not found"}), 404)


@XON.errorhandler(429)
def ratelimit_handler(error):
    """Returns response for 429"""
    rate_limit_info = re.search(r"(\d+)\sper\s(\d+\s\w+)", str(error.description))
    if rate_limit_info:
        count, period = rate_limit_info.groups()
        period_seconds = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}[
            period.split()[1]
        ]
        retry_after = period_seconds // int(count)
    else:
        retry_after = "unknown"  # TODO: Revisit logic

    if "hour" in error.description:
        # pass
        block_hour(ip_address=request.headers.get("X-Forwarded-For"))
    elif "day" in error.description:
        block_day(ip_address=request.headers.get("X-Forwarded-For"))

    response = make_response(
        jsonify(
            error=f"Ratelimit exceeded {error.description}",
            retry_after_seconds=retry_after,
        ),
        429,
    )
    return response


@XON.route("/robots.txt")
@LIMITER.limit("500 per day;100 per hour")
def serve_robots_txt():
    """Returns robots.txt"""
    return send_from_directory(XON.static_folder, "robots.txt")


@XON.route("/", methods=["GET"])
@LIMITER.limit("5000 per day;1000 per hour;100 per second")
def index():
    """Returns default landing page"""
    return render_template("index.html")


@XON.route("/v1/help/", methods=["GET"])
@LIMITER.limit("500 per day;100 per hour")
def helper():
    """Basic guidance to API documentation page"""
    return render_template("index.html")


def validate_variables(variables_to_validate):
    """
    Validate input variables to ensure they contain only valid characters.
    """
    pattern = r"^[a-zA-Z0-9@._:/-]*$"

    for value in variables_to_validate:
        if not value or value.isspace() or not re.match(pattern, value):
            return False

    return True


def validate_email_with_tld(email):
    """
    Validate email with TLD
    """
    if validate_email(email):
        tld = re.search("@[\w.]+", email)
        if tld:
            tld = tld.group()
            if "." in tld:
                return True
    return False


def validate_domain(domain):
    """Returns True if the domain is valid, False otherwise"""
    LIMITER.limit("10 per hour")
    if not is_valid_domain_name(domain):
        return False

    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        return False

    return True


def is_valid_domain_name(domain):
    """
    Returns True if the domain is a valid domain name, False otherwise
    """
    if not domain:
        return False
    if len(domain) > 253:
        return False
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-."
    if not all(char in allowed_chars for char in domain):
        return False
    if domain[0] == "-" or domain[-1] == "-":
        return False
    if "--" in domain:
        return False
    return True


def validate_url():
    """
    Returns True if the url  is a valid url, False otherwise
    """
    try:
        url = request.url
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception as exception:
        return False


def log_except(api_route, error_details):
    """Logs the exception for more thorough analysis"""
    ds_client = datastore.Client()
    task_except = datastore.Entity(
        ds_client.key(
            "xon_except",
            str(api_route) + "-" + str(time.time()),
        )
    )
    task_except.update(
        {
            "api": api_route,
            "error": str(error_details),
            "timestamp": datetime.datetime.now(),
        }
    )
    try:
        ds_client.put(task_except)
    except Exception as error_details:
        print(api_route + " --->  " + str(error_details))
    send_exception_email(api_route + " --->  " + str(error_details))

    return "Success"


def generate_confirmation_token(email):
    """Returns confirmation token generated for validation"""
    # TODO try/except
    serializer = URLSafeTimedSerializer(SECRET_APIKEY)
    return serializer.dumps(email, salt=SECURITY_SALT)


def confirm_token(token, expiration=1296000):
    """Returns status of confirmation used for validation"""
    try:
        serializer = URLSafeTimedSerializer(SECRET_APIKEY)
        return serializer.loads(token, salt=SECURITY_SALT, max_age=expiration)
    except:
        # except SignatureExpired:
        return False


def fetch_location_by_ip(ip_address: str) -> str:
    """
    Returns the nearest city and country based on the given IP address.
    """
    if not is_valid_ip(ip_address):
        return "Error: Invalid IP address format"

    ip_api_url = f"http://ip-api.com/json/{ip_address}"
    default_timeout = 20

    try:
        response = requests.get(ip_api_url, timeout=default_timeout)
        response.raise_for_status()
        location_data = response.json()
        return f' Near {location_data["city"]}, {location_data["country"]}'
    except (requests.Timeout, requests.HTTPError, requests.RequestException, KeyError):
        return "Error"


def is_valid_ip(ip_address: str) -> bool:
    """
    Validates the IP address format for both IPv4 and IPv6.
    """
    ipv4_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ipv6_pattern = r"^([\da-fA-F]{1,4}:){7}([\da-fA-F]{1,4})$"

    return (
        re.match(ipv4_pattern, ip_address) is not None
        or re.match(ipv6_pattern, ip_address) is not None
    )


def get_preferred_ip_address(x_forwarded_for):
    """
    Extracts and returns the preferred IP address (IPv4 if available, otherwise IPv6)
    from the X-Forwarded-For header value.
    """
    # Split the header value by commas to get individual IP addresses
    ip_addresses = x_forwarded_for.split(",")

    # First, search for an IPv4 address
    for ip in ip_addresses:
        ip = ip.strip()
        try:
            if ipaddress.ip_address(ip).version == 4:
                return ip
        except ValueError:
            continue

    # If no IPv4 address found, search for an IPv6 address
    for ip in ip_addresses:
        ip = ip.strip()
        try:
            if ipaddress.ip_address(ip).version == 6:
                return ip
        except ValueError:
            continue

    # Return None if no valid IP address is found
    return None


def encrypt_data(data):
    """
    Encrypts the given data using a predefined cipher suite.
    """
    return CIPHER_SUITE.encrypt(data.encode())


def decrypt_data(data):
    """
    Decrypts the given data using a predefined cipher suite.
    """
    return CIPHER_SUITE.decrypt(data).decode()


def get_breaches(breaches):
    """Returns the exposed breaches"""
    ds_client = datastore.Client()
    breaches_output = {"breaches_details": []}

    breaches = breaches.split(";")

    for breach in breaches:
        try:
            key = ds_client.key("xon_breaches", breach)
            query_result = ds_client.get(key)

            if query_result is not None:
                xposed_records = query_result.get("xposed_records", 0)
                breaches_output["breaches_details"].append(
                    {
                        "breach": breach,
                        "xposed_records": xposed_records,
                        "details": query_result.get("xposure_desc", ""),
                        "domain": query_result.get("domain", ""),
                        "industry": query_result.get("industry", ""),
                        "logo": query_result.get("logo", ""),
                        "password_risk": query_result.get("password_risk", ""),
                        "xposed_data": query_result.get("xposed_data", ""),
                        "searchable": query_result.get("searchable", ""),
                        "verified": query_result.get("verified", ""),
                        "references": query_result.get("references", ""),
                        "xposed_date": query_result.get("xposed_date", "").strftime(
                            "%Y"
                        ),
                    }
                )
            else:
                abort(404)

        except Exception:
            abort(404)

    return breaches_output


def get_breaches_metrics(breaches):
    """Returns the metrics of exposed breaches"""
    try:
        xposed_data = get_breaches_data(breaches)
        ds_client = datastore.Client()
        query = ds_client.query(kind="xon_breaches")
        breaches = breaches.split(";")

        get_metrics = {
            "yearwise_details": [],
            "passwords_strength": [],
            "industry": [],
            "get_details": [],
            "risk": [],
            "xposed_data": [],
        }
        date_list = []

        year_counts = {year: 0 for year in range(2007, 2025)}
        count_plaintext = count_easy = count_hard = count_unknown = 0
        count_aero = count_tran = count_info = count_tele = count_agri = count_cons = (
            count_educ
        ) = count_phar = count_food = count_heal = count_hosp = count_ente = (
            count_news
        ) = count_ener = count_manu = count_musi = count_mini = count_elec = (
            count_misc
        ) = count_reale = count_fina = count_reta = count_nonp = count_govt = (
            count_spor
        ) = count_envi = 0
        password_risk_counters = {
            "plaintext": count_plaintext,
            "easytocrack": count_easy,
            "hardtocrack": count_hard,
            "unknown": count_unknown,
        }
        industry_counters = {
            "Miscellaneous": count_misc,
            "Electronics": count_elec,
            "Mining": count_mini,
            "Music": count_musi,
            "Manufacturing": count_manu,
            "Energy": count_ener,
            "News Media": count_news,
            "Entertainment": count_ente,
            "Hospitality": count_hosp,
            "Health Care": count_heal,
            "Food": count_food,
            "Pharmaceutical": count_phar,
            "Education": count_educ,
            "Construction": count_cons,
            "Agriculture": count_agri,
            "Telecommunication": count_tele,
            "Information Technology": count_info,
            "Transport": count_tran,
            "Aerospace": count_aero,
            "Real Estate": count_reale,
            "Finance": count_fina,
            "Retail": count_reta,
            "Non-Profit/Charities": count_nonp,
            "Government": count_govt,
            "Sports": count_spor,
            "Environment": count_envi,
        }
        for index_count, breach in enumerate(breaches):
            if not re.match(r"^[a-zA-Z0-9.-]*$", breach):
                return False
            key = ds_client.key("xon_breaches", breach)
            query = ds_client.get(key)
            password_risk_counters[query["password_risk"]] += 1
            industry_counters[query["industry"]] += 1
            date_list.append(query["breached_date"])

            year = query["breached_date"].year
            if year in year_counts:
                year_counts[year] += 1

        get_metrics["yearwise_details"].append(
            {f"y{year}": count for year, count in year_counts.items()}
        )

        get_metrics["passwords_strength"].append(
            {
                "PlainText": password_risk_counters["plaintext"],
                "EasyToCrack": password_risk_counters["easytocrack"],
                "StrongHash": password_risk_counters["hardtocrack"],
                "Unknown": password_risk_counters["unknown"],
            }
        )

        sorted_industries = {
            "misc": industry_counters["Miscellaneous"],
            "elec": industry_counters["Electronics"],
            "mini": industry_counters["Mining"],
            "musi": industry_counters["Music"],
            "manu": industry_counters["Manufacturing"],
            "ener": industry_counters["Energy"],
            "news": industry_counters["News Media"],
            "ente": industry_counters["Entertainment"],
            "hosp": industry_counters["Hospitality"],
            "heal": industry_counters["Health Care"],
            "food": industry_counters["Food"],
            "phar": industry_counters["Pharmaceutical"],
            "educ": industry_counters["Education"],
            "cons": industry_counters["Construction"],
            "agri": industry_counters["Agriculture"],
            "tele": industry_counters["Telecommunication"],
            "info": industry_counters["Information Technology"],
            "tran": industry_counters["Transport"],
            "aero": industry_counters["Aerospace"],
            "fina": industry_counters["Finance"],
            "reta": industry_counters["Retail"],
            "nonp": industry_counters["Non-Profit/Charities"],
            "govt": industry_counters["Government"],
            "spor": industry_counters["Sports"],
            "envi": industry_counters["Environment"],
        }
        sorted_industries = sorted(
            sorted_industries.items(), key=lambda x: x[1], reverse=True
        )

        get_metrics["industry"].append(sorted_industries)
        password_score = password_risk_counters["plaintext"] / (
            password_risk_counters["easytocrack"]
            + password_risk_counters["hardtocrack"]
            + password_risk_counters["plaintext"]
            + password_risk_counters["unknown"]
        )

        if password_score <= 0.33:
            password_strength = 1
        elif password_score <= 0.66:
            password_strength = 2
        else:
            password_strength = 3

        num_breaches = len(breaches)
        high_severity = password_risk_counters["plaintext"]
        sorted_dates = sorted(date_list)
        least_date = sorted_dates[0]
        current_date = datetime.date.today()
        months_difference = (current_date.year - least_date.year) * 12 + (
            current_date.month - least_date.month
        )

        if months_difference < 6:
            last_breach_months = 3
        elif months_difference >= 6 and months_difference <= 12:
            last_breach_months = 2
        else:
            last_breach_months = 1

        risk_score = round(
            (num_breaches * high_severity)
            + (high_severity * 2)
            + (last_breach_months / 12)
            + (password_strength * 3)
        )

        if risk_score >= 61:
            risk_label = "High"
        elif risk_score >= 21:
            risk_label = "Medium"
        else:
            risk_label = "Low"

        get_metrics["risk"].append(
            {
                "risk_score": risk_score,
                "risk_label": risk_label,
            }
        )
        get_metrics["xposed_data"].append(xposed_data)

        return get_metrics

    except Exception:
        abort(404)


def get_breaches_data(breaches: str) -> dict:
    """
    Returns a dictionary with the count of various types of exposed data in breaches
    """
    try:
        ds_client = datastore.Client()
        breach_list = breaches.split(";")

        data_categories = {
            # TODO: Revise the labels to suit after xon-data
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
            "Social media profiles": {
                "category": "👤 Personal Identification",
                "group": "A",
            },
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
            "Drinking Habits": {
                "category": "🍔 Personal Habits and Lifestyle",
                "group": "C",
            },
            "Drug Habits": {
                "category": "🍔 Personal Habits and Lifestyle",
                "group": "C",
            },
            "Eating Habits": {
                "category": "🍔 Personal Habits and Lifestyle",
                "group": "C",
            },
            "Living Costs": {
                "category": "🍔 Personal Habits and Lifestyle",
                "group": "C",
            },
            "Travel Habits": {
                "category": "🍔 Personal Habits and Lifestyle",
                "group": "C",
            },
            "Work Habits": {
                "category": "🍔 Personal Habits and Lifestyle",
                "group": "C",
            },
            "Professional Skills": {
                "category": "🍔 Personal Habits and Lifestyle",
                "group": "C",
            },
            "Spoken languages": {
                "category": "🍔 Personal Habits and Lifestyle",
                "group": "C",
            },
            "Time Zones": {
                "category": "🍔 Personal Habits and Lifestyle",
                "group": "C",
            },
            "Vehicle Details": {
                "category": "🍔 Personal Habits and Lifestyle",
                "group": "C",
            },
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
            "Job Applications": {
                "category": "🎓 Employment and Education",
                "group": "E",
            },
            "Job titles": {"category": "🎓 Employment and Education", "group": "E"},
            "Employers": {"category": "🎓 Employment and Education", "group": "E"},
            "Employment Statuses": {
                "category": "🎓 Employment and Education",
                "group": "E",
            },
            "Occupations": {"category": "🎓 Employment and Education", "group": "E"},
            "Education Levels": {
                "category": "🎓 Employment and Education",
                "group": "E",
            },
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
            "Chat Logs": {
                "category": "📞 Communication and Social Interactions",
                "group": "F",
            },
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
            "IP addresses": {
                "category": "🖥️ Device and Network Information",
                "group": "G",
            },
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
            "MAC Addresses": {
                "category": "🖥️ Device and Network Information",
                "group": "G",
            },
            "IMEI Numbers": {
                "category": "🖥️ Device and Network Information",
                "group": "G",
            },
            "IMSI Numbers": {
                "category": "🖥️ Device and Network Information",
                "group": "G",
            },
            "Homepage URLs": {
                "category": "🖥️ Device and Network Information",
                "group": "G",
            },
            "User Website URLs": {
                "category": "🖥️ Device and Network Information",
                "group": "G",
            },
            "Website Activity": {
                "category": "🖥️ Device and Network Information",
                "group": "G",
            },
            "Personal Health Data": {"category": "🩺 Health Information", "group": "H"},
            "HIV Statuses": {"category": "🩺 Health Information", "group": "H"},
            "Blood Types": {"category": "🩺 Health Information", "group": "H"},
            "Medical Conditions": {"category": "🩺 Health Information", "group": "H"},
            "Medications": {"category": "🩺 Health Information", "group": "H"},
            "Body Measurements": {"category": "🩺 Health Information", "group": "H"},
            "Physical Activity Levels": {
                "category": "🩺 Health Information",
                "group": "H",
            },
            "Physical Disabilities": {
                "category": "🩺 Health Information",
                "group": "H",
            },
            "Psychological Conditions": {
                "category": "🩺 Health Information",
                "group": "H",
            },
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
            "Astronomical Observations": {
                "category": "Science and Technology",
                "group": "J",
            },
            "Chemical Analyses": {"category": "Science and Technology", "group": "J"},
            "Scientific Measurements": {
                "category": "Science and Technology",
                "group": "J",
            },
            "Weather Observations": {
                "category": "Science and Technology",
                "group": "J",
            },
            "Books Read": {"category": "Arts and Entertainment", "group": "K"},
            "Games Played": {"category": "Arts and Entertainment", "group": "K"},
            "Movies Watched": {"category": "Arts and Entertainment", "group": "K"},
            "Music Listened To": {"category": "Arts and Entertainment", "group": "K"},
            "Photos Uploaded": {"category": "Arts and Entertainment", "group": "K"},
            "Videos Watched": {"category": "Arts and Entertainment", "group": "K"},
            "Aircraft Details": {"category": "Transport and Travel", "group": "L"},
            "Flight Details": {"category": "Transport and Travel", "group": "L"},
            "Public Transport Details": {
                "category": "Transport and Travel",
                "group": "L",
            },
            "Shipping Details": {"category": "Transport and Travel", "group": "L"},
        }

        # Initialize counters for each data type
        data_counter_dict = {data: 0 for data in data_categories.keys()}

        # Initialize metrics with structure
        metrics = {"children": []}
        for breach in breach_list:
            key = ds_client.key("xon_breaches", breach)
            query_result = ds_client.get(key)
            data_list = query_result["xposed_data"].split(";")
            for data in data_list:
                if data in data_counter_dict:  # Skip data types not in our mapping
                    data_counter_dict[data] += 1

        # Build the final structure
        category_dict = {}
        for data, count in data_counter_dict.items():
            category = data_categories[data]["category"]
            group = data_categories[data]["group"]
            if category not in category_dict:
                category_dict[category] = {
                    "name": category,
                    "children": [],
                    "colname": "level2",
                }
            if count > 0:  # Append the data only if count is greater than 0
                category_dict[category]["children"].append(
                    {
                        "name": f"data_{data}",
                        "group": group,
                        "value": count,
                        "colname": "level3",
                    }
                )

        # Add each category to the final metrics
        for category in category_dict.values():
            # Add category to metrics only if it has at least one child
            if len(category["children"]) > 0:
                metrics["children"].append(category)

        return metrics
    except Exception as exception_details:
        abort(404)


def get_breaches_analytics(breaches, sensitive_breaches):
    """Returns the metrics of exposed breaches"""
    try:
        ds_client = datastore.Client()
        get_details = {"description": "Data Breaches", "children": []}

        # Year-wise dictionaries
        yy2024 = {"description": "2024", "children": []}
        yy2023 = {"description": "2023", "children": []}
        yy2022 = {"description": "2022", "children": []}
        yy2021 = {"description": "2021", "children": []}
        yy2020 = {"description": "2020", "children": []}
        yy2019 = {"description": "2019", "children": []}
        yy2018 = {"description": "2018", "children": []}
        yy2017 = {"description": "2017", "children": []}
        yy2016 = {"description": "2016", "children": []}
        yy2015 = {"description": "2015", "children": []}
        yy2014 = {"description": "2014", "children": []}
        yy2013 = {"description": "2013", "children": []}
        yy2012 = {"description": "2012", "children": []}
        yy2011 = {"description": "2011", "children": []}
        yy2010 = {"description": "2010", "children": []}
        yy2009 = {"description": "2009", "children": []}
        yy2008 = {"description": "2008", "children": []}
        yy2007 = {"description": "2007", "children": []}

        # Process regular breaches
        if breaches and len(breaches) > 0:
            breaches = breaches.split(";")
            for breach in breaches:
                breach_logo = details = ""
                key = ds_client.key("xon_breaches", breach)
                query = ds_client.get(key)
                parts_s = str(key).split(",")
                bid = parts_s[1][:-2][2:]
                breach_logo = bid
                logo = query.get("logo", "default_logo.jpg")
                details = (
                    "<img src='" + logo + "' style='height:40px;width:65px;' />"
                    "<a target='_blank' href='https://xposedornot.com/xposed/#"
                    + bid
                    + "'> &nbsp;"
                    + "Details</a>"
                )

                child = {"description": breach_logo, "children": []}
                child["children"].append(
                    {
                        "description": details,
                        "tooltip": "Click here 👇",
                        "children": [],
                    }
                )
                if (query["breached_date"].year) == 2024:
                    yy2024["children"].append(child)
                elif (query["breached_date"].year) == 2023:
                    yy2023["children"].append(child)
                elif (query["breached_date"].year) == 2022:
                    yy2022["children"].append(child)
                elif (query["breached_date"].year) == 2021:
                    yy2021["children"].append(child)
                elif (query["breached_date"].year) == 2020:
                    yy2020["children"].append(child)
                elif (query["breached_date"].year) == 2019:
                    yy2019["children"].append(child)
                elif (query["breached_date"].year) == 2018:
                    yy2018["children"].append(child)
                elif (query["breached_date"].year) == 2017:
                    yy2017["children"].append(child)
                elif (query["breached_date"].year) == 2016:
                    yy2016["children"].append(child)
                elif (query["breached_date"].year) == 2015:
                    yy2015["children"].append(child)
                elif (query["breached_date"].year) == 2014:
                    yy2014["children"].append(child)
                elif (query["breached_date"].year) == 2013:
                    yy2013["children"].append(child)
                elif (query["breached_date"].year) == 2012:
                    yy2012["children"].append(child)
                elif (query["breached_date"].year) == 2011:
                    yy2011["children"].append(child)
                elif (query["breached_date"].year) == 2010:
                    yy2010["children"].append(child)
                elif (query["breached_date"].year) == 2009:
                    yy2009["children"].append(child)
                elif (query["breached_date"].year) == 2008:
                    yy2008["children"].append(child)
                elif (query["breached_date"].year) == 2007:
                    yy2007["children"].append(child)

        # Process sensitive breaches
        if sensitive_breaches and len(sensitive_breaches) > 0:
            sensitive_breaches = sensitive_breaches.split(";")
            for breach in sensitive_breaches:
                breach_logo = details = ""
                key = ds_client.key("xon_breaches", breach)
                query = ds_client.get(key)
                parts_s = str(key).split(",")
                bid = parts_s[1][:-2][2:]

                breach_logo = bid
                logo = query.get("logo", "default_logo.jpg")
                details = (
                    "<img src='" + logo + "' style='height:40px;width:65px;' />"
                    "<a target='_blank' href='https://xposedornot.com/xposed/#"
                    + bid
                    + "'> &nbsp;"
                    + "Details</a>"
                )

                child = {"description": breach_logo, "children": []}
                child["children"].append(
                    {
                        "description": details,
                        "tooltip": "Click here ...",
                        "children": [],
                    }
                )

                if (query["breached_date"].year) == 2024:
                    yy2024["children"].append(child)
                elif (query["breached_date"].year) == 2023:
                    yy2023["children"].append(child)
                elif (query["breached_date"].year) == 2022:
                    yy2022["children"].append(child)
                elif (query["breached_date"].year) == 2021:
                    yy2021["children"].append(child)
                elif (query["breached_date"].year) == 2020:
                    yy2020["children"].append(child)
                elif (query["breached_date"].year) == 2019:
                    yy2019["children"].append(child)
                elif (query["breached_date"].year) == 2018:
                    yy2018["children"].append(child)
                elif (query["breached_date"].year) == 2017:
                    yy2017["children"].append(child)
                elif (query["breached_date"].year) == 2016:
                    yy2016["children"].append(child)
                elif (query["breached_date"].year) == 2015:
                    yy2015["children"].append(child)
                elif (query["breached_date"].year) == 2014:
                    yy2014["children"].append(child)
                elif (query["breached_date"].year) == 2013:
                    yy2013["children"].append(child)
                elif (query["breached_date"].year) == 2012:
                    yy2012["children"].append(child)
                elif (query["breached_date"].year) == 2011:
                    yy2011["children"].append(child)
                elif (query["breached_date"].year) == 2010:
                    yy2010["children"].append(child)
                elif (query["breached_date"].year) == 2009:
                    yy2009["children"].append(child)
                elif (query["breached_date"].year) == 2008:
                    yy2008["children"].append(child)
                elif (query["breached_date"].year) == 2007:
                    yy2007["children"].append(child)

        # Combine years into get_details
        years = [
            yy2024,
            yy2023,
            yy2022,
            yy2021,
            yy2020,
            yy2019,
            yy2018,
            yy2017,
            yy2016,
            yy2015,
            yy2014,
            yy2013,
            yy2012,
            yy2011,
            yy2010,
            yy2009,
            yy2008,
            yy2007,
        ]

        for year in years:
            get_details["children"].append(year)

        return get_details
    except Exception as e:
        print(f"An error occurred: {e}")
        abort(404)


def get_pastes(pastes):
    """Returns the details of exposed pastes"""
    try:
        dp_client = datastore.Client()
        query = dp_client.query(kind="xon_paste_master")
        pastes = pastes.split(";")
        pastes_output = {"pastes_details": []}
        for index_count, paste in enumerate(pastes):
            key = dp_client.key("xon_paste_master", paste)
            query = dp_client.get(key)
            records_xposed = int(query["insrt_cnt"]) + int(query["updt_cnt"])
            pastes_output["pastes_details"].append(
                {
                    "pasteId": paste,
                    "xposed_date": query["insrt_tmpstmp"].strftime(
                        "%Y-%m-%dT%H:%M:%S%Z"
                    ),
                    "xposed_records": records_xposed,
                }
            )
        return pastes_output
    except Exception:
        abort(404)


def get_exposure(user_email):
    """Returns breach data for a given email"""
    breach_data = ""
    try:
        datastore_client = datastore.Client()
        search_key = datastore_client.key("xon", user_email)
        user_data = datastore_client.get(search_key)
        if user_data is not None:
            breach_data = user_data.get("site", "")
    except Exception as exception_details:
        print(f"An error occurred while fetching data: {exception_details}")
    return breach_data


def get_sensitive_exposure(user_email):
    """Returns sensitive breach data for a given email."""
    sensitive_breach_data = ""
    try:
        datastore_client = datastore.Client()
        search_key = datastore_client.key("xon", user_email)
        user_data = datastore_client.get(search_key)
        if user_data is not None:
            sensitive_breach_data = user_data.get("sensitive_site", "")
    except Exception as exception_details:
        print(f"An error occurred while fetching data: {exception_details}")
    return sensitive_breach_data


def get_summary_and_metrics(breach_record, paste_record):
    """Helper function to fetch the summary and metrics of breaches and pastes"""
    breach_summary = None
    paste_summary = None
    exposed_breaches = None
    exposed_pastes = None
    breach_metrics = None
    paste_metrics = None

    if breach_record:
        site_name = str(breach_record["site"])
        breach_summary = {"site": site_name}
        exposed_breaches = get_breaches(site_name)
        breach_metrics = get_breaches_metrics(site_name)

    if paste_record:
        tweet_id_str = str(paste_record["tweet_id"].decode("utf-8"))
        paste_summary = {"cnt": paste_record["cnt"], "tweet_id": tweet_id_str}
        exposed_pastes = get_pastes(tweet_id_str)
        paste_metrics = get_pastes_metrics(tweet_id_str)

    return (
        breach_summary,
        paste_summary,
        exposed_breaches,
        exposed_pastes,
        breach_metrics,
        paste_metrics,
    )


def get_domain_exposure(domain):
    """Returns exposure for a given domain"""
    try:
        if domain is None:
            abort(404)
        ds_domain = datastore.Client()
        task_domain = ds_domain.query(kind="xon")
        task_domain.add_filter("domain", "=", domain.strip())
        query_domain = task_domain.fetch()
        total = emails_count = 0
        breach_details = {"breaches_details": []}
        emails = ""
        for entity_domain in query_domain:
            if emails_count <= 50:
                emails_count += 1
                emails = emails + ","
        ds_paste = datastore.Client()
        task_paste = ds_paste.query(kind="xon_paste")
        task_paste.add_filter("domain", "=", domain.strip())
        query_paste = task_paste.fetch()
        pastes_count = 0
        for entity_aa_daily in query_paste:
            if pastes_count <= 50:
                pastes_count += 1
        total = emails_count + pastes_count
        breach_details["breaches_details"].append(
            {
                "breachid": domain,
                "breach_pastes": pastes_count,
                "breach_emails": emails_count,
                "breach_total": total,
            }
        )
        return jsonify({"sendDomains": breach_details, "SearchStatus": "Success"})
    except Exception:
        abort(404)


def get_pastes_metrics(pastes):
    """Returns the high level metrics of exposed pastes"""
    try:
        ds_client = datastore.Client()
        query = ds_client.query(kind="xon_paste_master")
        breaches = pastes.split(";")
        get_metrics = {"yearwise_details": []}
        y2021 = y2020 = y2019 = y2018 = y2017 = y2016 = y2015 = y2015 = y2014 = (
            y2013
        ) = y2012 = y2011 = y2010 = y2009 = y2008 = y2007 = y2022 = y2023 = 0
        for index_count, count in enumerate(breaches):
            key = ds_client.key("xon_paste_master", count)
            query = ds_client.get(key)
            if (query["insrt_tmpstmp"].year) == 2023:
                y2023 += 1
            elif (query["insrt_tmpstmp"].year) == 2022:
                y2022 += 1
            elif (query["insrt_tmpstmp"].year) == 2021:
                y2021 += 1
            elif (query["insrt_tmpstmp"].year) == 2020:
                y2020 += 1
            elif (query["insrt_tmpstmp"].year) == 2019:
                y2019 += 1
            elif (query["insrt_tmpstmp"].year) == 2018:
                y2018 += 1
            elif (query["insrt_tmpstmp"].year) == 2017:
                y2017 += 1
            elif (query["insrt_tmpstmp"].year) == 2016:
                y2016 += 1
            elif (query["insrt_tmpstmp"].year) == 2015:
                y2015 += 1
            elif (query["insrt_tmpstmp"].year) == 2014:
                y2014 += 1
            elif (query["insrt_tmpstmp"].year) == 2013:
                y2013 += 1
            elif (query["insrt_tmpstmp"].year) == 2012:
                y2012 += 1
            elif (query["insrt_tmpstmp"].year) == 2011:
                y2011 += 1
            elif (query["insrt_tmpstmp"].year) == 2010:
                y2010 += 1
            elif (query["insrt_tmpstmp"].year) == 2009:
                y2009 += 1
            elif (query["insrt_tmpstmp"].year) == 2008:
                y2008 += 1
            elif (query["insrt_tmpstmp"].year) == 2007:
                y2007 += 1
        get_metrics["yearwise_details"].append(
            {
                "y2023": y2023,
                "y2022": y2022,
                "y2021": y2021,
                "y2020": y2020,
                "y2019": y2019,
                "y2018": y2018,
                "y2017": y2017,
                "y2016": y2016,
                "y2015": y2015,
                "y2014": y2014,
                "y2013": y2013,
                "y2012": y2012,
                "y2011": y2011,
                "y2010": y2010,
                "y2009": y2009,
                "y2008": y2008,
                "y2007": y2007,
            }
        )
        return get_metrics
    except Exception:
        abort(404)


def check_file(domain, prefix, code):
    """
    Supports domain verification using HTML file check process.
    """
    if not validate_domain(domain) or not validate_variables([code]):
        return False

    headers = {
        "User-Agent": "XposedOrNot-DomainCheck 1.0 (+https://XposedOrNot.com) ",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
        "Accept-Encoding": "none",
        "Accept-Language": "en-US,en;q=0.8",
        "Connection": "keep-alive",
    }
    url = f"https://{domain}/{code}.html"
    token = f"{prefix}={code}"

    try:
        response = requests.get(url, headers=headers, timeout=20)
        data = response.content[:1000]
        if response.status_code == 200:
            if str(token.strip()) == str(data.strip().decode("utf-8")):
                return True
    except requests.exceptions.RequestException as exception_details:
        print(f"Error: {exception_details}")

    return False


def check_emails(domain):
    """
    Sends a request to the WhoisXML API to get the 'whois' record of the given domain and
    extracts the registrant's email from the response.
    """
    response = requests.get(
        f"https://www.whoisxmlapi.com/whoisserver/WhoisService?"
        f"apiKey={XMLAPI_KEY}&domainName={domain}&outputFormat=JSON",
        timeout=20,
    )

    if response.status_code != 200:
        return jsonify({"domainVerification": "Failure"})

    try:
        who_is = json.loads(response.text)
    except json.decoder.JSONDecodeError:
        print("Could not decode the response")

    registrant_email = who_is["WhoisRecord"]["contactEmail"]

    if isinstance(registrant_email, str):
        registrant_email = registrant_email.split(",")

    return jsonify({"domainVerification": registrant_email})


def verify_email(domain, email):
    """
    Verifies if the provided email matches with the registrant's email from the 'whois' record
    of the given domain (using WhoisXML API).
    """
    response = requests.get(
        f"https://www.whoisxmlapi.com/whoisserver/WhoisService?"
        f"apiKey={XMLAPI_KEY}&domainName={domain}&outputFormat=JSON",
        timeout=20,
    )

    if response.status_code != 200:
        return jsonify({"domainVerification": "Failure"})
    who_is = json.loads(response.text)

    registrant_email = who_is["WhoisRecord"]["contactEmail"]

    if email == registrant_email:
        datastore_client = datastore.Client()
        domain_key = datastore_client.key("xon_domains", domain + "_" + email)
        domain_record = datastore_client.get(domain_key)
        token = generate_confirmation_token(email)

        if domain_record is None:
            create_new_record(domain, "", token, "email", datastore_client)

        threading.Thread(target=process_single_domain, args=(domain,)).start()

        client_ip_address = request.headers.get("X-Forwarded-For")
        location = fetch_location_by_ip(client_ip_address)
        user_agent_string = request.headers.get("User-Agent")
        user_agent = parse(user_agent_string)
        browser_type = (
            user_agent.browser.family + " " + user_agent.browser.version_string
        )
        client_platform = user_agent.os.family + " " + user_agent.os.version_string

        send_domain_confirmation_email(
            email, token, client_ip_address, browser_type, client_platform
        )
        return jsonify({"domainVerification": "Success"})
    else:
        return jsonify({"domainVerification": "Failure"})


def verify_dns(domain, email, code, prefix):
    """Validates email and code, verifies the domain via DNS TXT record, creates or updates
    the domain record in datastore, and processes the domain."""
    if not validate_email_with_tld(email) or not validate_variables(code):
        return jsonify({"domainVerification": "Failure"})
    if domcheck.check(domain, prefix, code, strategies="dns_txt"):
        datastore_client = datastore.Client()
        domain_key = datastore_client.key("xon_domains", domain + "_" + email)
        domain_record = datastore_client.get(domain_key)

        if domain_record is None:
            create_new_record(domain, email, code, "dns_txt", datastore_client)
        else:
            domain_record["last_verified"] = datetime.datetime.now()
            datastore_client.put(domain_record)

        threading.Thread(target=process_single_domain, args=(domain,)).start()

        client_ip_address = request.headers.get("X-Forwarded-For")
        location = fetch_location_by_ip(client_ip_address)
        user_agent_string = request.headers.get("User-Agent")
        user_agent = parse(user_agent_string)
        browser_type = (
            user_agent.browser.family + " " + user_agent.browser.version_string
        )
        client_platform = user_agent.os.family + " " + user_agent.os.version_string
        send_domain_verified_success(
            email, client_ip_address, browser_type, client_platform
        )
        return jsonify({"domainVerification": "Success"})
    else:
        return jsonify({"domainVerification": "Failure"})


def verify_html(domain, email, code, prefix):
    """Validates email and code, checks for specific HTML file in domain, and creates or
    updates a domain record in datastore."""
    if not validate_email_with_tld(email) or not validate_variables(code):
        return jsonify({"domainVerification": "Failure"})
    if check_file(domain, prefix, code):
        datastore_client = datastore.Client()
        domain_key = datastore_client.key("xon_domains", domain + "_" + email)
        domain_record = datastore_client.get(domain_key)
        if domain_record is None:
            create_new_record(domain, email, code, "html_file", datastore_client)
        else:
            domain_record["last_verified"] = datetime.datetime.now()
            datastore_client.put(domain_record)

        threading.Thread(target=process_single_domain, args=(domain,)).start()

        client_ip_address = request.headers.get("X-Forwarded-For")
        location = fetch_location_by_ip(client_ip_address)
        user_agent_string = request.headers.get("User-Agent")
        user_agent = parse(user_agent_string)
        browser_type = (
            user_agent.browser.family + " " + user_agent.browser.version_string
        )
        client_platform = user_agent.os.family + " " + user_agent.os.version_string
        send_domain_verified_success(
            email, client_ip_address, browser_type, client_platform
        )

        return jsonify({"domainVerification": "Success"})
    else:
        return jsonify({"domainVerification": "Failure"})


def create_new_record(domain, email, token, mode, datastore_client):
    """
    Creates a new domain record with the provided domain, email, token, and verification mode.
    """
    new_domain_record = datastore.Entity(
        datastore_client.key("xon_domains", domain + "_" + email)
    )
    new_domain_record.update(
        {
            "email": email,
            "domain": domain,
            "mode": mode,
            "token": token,
            "verified": True,
            "insert_timestamp": datetime.datetime.now(),
        }
    )
    datastore_client.put(new_domain_record)


def send_domain_confirmation_email(
    email, token, ip_address, browser_type, client_platform
):
    """
    Generates a confirmation URL for domain validation and sends a domain confirmation email to the
    provided email address, including the client's IP address, browser type, and operating system.
    """
    confirm_url = url_for("domain_validation", token=token, _external=True)
    send_domain_confirmation(
        email, confirm_url, ip_address, browser_type, client_platform
    )


def process_single_domain(domain):
    """
    Processes transactions for a given domain, populates breach details, and updates a
    summary of breaches per domain.
    """
    client = datastore.Client()

    def list_transactions_for_domain(domain):
        client = datastore.Client()

        # Create a query and add a filter based on the "domain" column
        query = client.query(kind="xon")
        query.add_filter("domain", "=", domain)

        result = []

        try:
            result = [tx for tx in query.fetch()]
        except Exception as exception:
            return []

        return result

    domain_transactions = list_transactions_for_domain(domain)

    if not domain_transactions:
        entity_key = client.key("xon_domains_summary", domain + "+No_Breaches")
        entity = datastore.Entity(key=entity_key)
        entity.update({"domain": domain, "breach": "No_Breaches", "email_count": 0})
        client.put(entity)

    breach_summary = defaultdict(int)
    for tx in domain_transactions:
        if "site" in tx and tx["site"]:
            breaches = tx["site"].split(";")
            for breach in breaches:
                email_from_key = tx.key.name
                entity_key = client.key(
                    "xon_domains_details", breach + "_" + email_from_key
                )
                entity = datastore.Entity(key=entity_key)
                entity.update(
                    {
                        "breach_email": breach + "_" + email_from_key,
                        "domain": domain,
                        "breach": breach,
                        "email": email_from_key,
                    }
                )
                client.put(entity)
                breach_summary[(domain, breach)] += 1
        else:
            print(f"Transaction {tx.key.name} does not contain site information.")

    for (domain, breach), count in breach_summary.items():
        entity_key = client.key("xon_domains_summary", domain + "+" + breach)
        entity = datastore.Entity(key=entity_key)
        entity.update({"domain": domain, "breach": breach, "email_count": count})
        client.put(entity)
    # TODO: Need to send an email afer processing completed


@XON.route("/v1/unblock_cf/<token>", methods=["GET"])
@LIMITER.limit("24 per day;2 per hour;1 per second")
def unblock_cloudflare(token):
    """Returns status of unblock done at Cloudflare"""
    try:
        if not token or token != CF_UNBLOCK_MAGIC:
            abort(404)

        unblock()

        return make_response(jsonify({"status": "Success"}), 200)

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/metrics/", methods=["GET"])
@LIMITER.limit("500 per day;100 per hour")
def get_metrics():
    """Returns high level summary of data breaches loaded in XoN"""
    try:
        datastore_client = datastore.Client()
        metrics_key = datastore_client.key("xon_metrics", "metrics")
        metrics_data = datastore_client.get(metrics_key)

        if metrics_data is None:
            abort(404)

        breaches_count = metrics_data["breaches_count"]
        breaches_total_records = metrics_data["breaches_records"]
        pastes_count = "{:,}".format(metrics_data["pastes_count"])
        pastes_total_records = metrics_data["pastes_records"]

        return jsonify(
            {
                "Breaches_Count": breaches_count,
                "Breaches_Records": breaches_total_records,
                "Pastes_Count": pastes_count,
                "Pastes_Records": pastes_total_records,
            }
        )

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/breach-analytics", methods=["GET"])
@LIMITER.limit("500 per day;100 per hour;2 per second")
def search_data_breaches():
    """Returns summary and details of data breaches for a given email"""
    verification_token = request.args.get("token", default=None)
    email = request.args.get("email", default=None)

    if not email or not validate_email(email) or not validate_url():
        return make_response(jsonify({"Error": "Not found"}), 404)

    try:
        email = email.lower()
        datastore_client = datastore.Client()
        alert_datastore_client = datastore.Client()
        paste_datastore_client = datastore.Client()

        alert_key = alert_datastore_client.key("xon_alert", email)
        alert_record = alert_datastore_client.get(alert_key)

        include_sensitive = False

        if verification_token:
            if alert_record and alert_record["token"] == verification_token:
                include_sensitive = True
            else:
                return make_response(jsonify({"Error": "Invalid token"}), 403)

        breach_key = datastore_client.key("xon", email)
        breach_record = datastore_client.get(breach_key)

        paste_key = paste_datastore_client.key("xon_paste", email)
        paste_record = paste_datastore_client.get(paste_key)

        if alert_record and alert_record.get("shieldOn"):
            raise ShieldOnException("Shield is on")
        if include_sensitive:
            combined_breach_data = get_combined_breach_data(
                breach_record, include_sensitive
            )
            existing_sites = (
                set(breach_record["site"].split(";"))
                if "site" in breach_record and breach_record["site"]
                else set()
            )
            unique_sites = existing_sites.union(combined_breach_data)
            breach_record["site"] = ";".join(unique_sites)

        (
            breach_summary,
            paste_summary,
            exposed_breaches,
            exposed_pastes,
            breach_metrics,
            paste_metrics,
        ) = get_summary_and_metrics(breach_record, paste_record)

        if breach_summary or paste_summary:
            return jsonify(
                {
                    "ExposedBreaches": exposed_breaches,
                    "BreachesSummary": (
                        breach_summary
                        if breach_summary
                        else {"domain": "", "site": "", "tmpstmp": ""}
                    ),
                    "BreachMetrics": breach_metrics,
                    "PastesSummary": (
                        paste_summary
                        if paste_summary
                        else {"cnt": 0, "domain": "", "tmpstmp": ""}
                    ),
                    "ExposedPastes": exposed_pastes,
                    "PasteMetrics": paste_metrics,
                }
            )
        else:
            return jsonify(
                {
                    "BreachesSummary": {"domain": "", "site": "", "tmpstmp": ""},
                    "PastesSummary": {"cnt": 0, "domain": "", "tmpstmp": ""},
                }
            )
    except ShieldOnException as shield_error:
        abort(404)
    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


class ShieldOnException(Exception):
    """
    Exception raised when an attempt is made to access data that is protected by a shield.
    """

    pass


def get_combined_breach_data(breach_record, include_sensitive=False):
    """
    Combine standard and sensitive breach data based on authorization.

    :param breach_record: The datastore record containing breach information.
    :param include_sensitive: Flag to indicate if sensitive data should be included.
    :return: A set of unique breach data.
    """
    standard_sites = (
        set(breach_record["site"].split(";"))
        if "site" in breach_record and breach_record["site"]
        else set()
    )

    if (
        include_sensitive
        and "sensitive_site" in breach_record
        and breach_record["sensitive_site"]
    ):
        sensitive_sites = set(breach_record["sensitive_site"].split(";"))
        return standard_sites.union(sensitive_sites)
    else:
        return standard_sites


def merge_data(standard_data, sensitive_data):
    """Merge standard and sensitive data"""
    merged_data = []

    standard_sites = standard_data.split(";") if standard_data else []
    sensitive_sites = sensitive_data.split(";") if sensitive_data else []

    merged_data.extend(standard_sites)

    for site in sensitive_sites:
        if site not in merged_data:
            merged_data.append(site)

    return merged_data


@XON.route("/v1/analytics/<user_email>", methods=["GET"])
@LIMITER.limit("500 per day;100 per hour;2 per second")
def get_breach_analytics(user_email):
    """Returns analytics of data breaches for a given email"""
    try:
        user_email = user_email.lower()
        if (
            not user_email
            or not validate_email_with_tld(user_email)
            or not validate_url()
        ):
            return make_response(jsonify({"Error": "Not found"}), 404)

        data_store = datastore.Client()
        xon_key = data_store.key("xon", user_email)
        xon_record = data_store.get(xon_key)
        alert_key = data_store.key("xon_alert", user_email)
        alert_record = data_store.get(alert_key)
        paste_key = data_store.key("xon_paste", user_email)
        paste_record = data_store.get(paste_key)

        if alert_record and alert_record["shieldOn"]:
            raise ShieldOnException("Shield is on")

        if xon_record:
            site = str(xon_record["site"])
            breach_metrics = get_breaches_analytics(site, "")
        else:
            breach_metrics = None

        # To revisit
        if paste_record:
            exposed_pastes = ""

        return breach_metrics

    except ShieldOnException as shield_error:
        abort(404)

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/check-email/<email>", methods=["GET"])
@LIMITER.limit("50000 per day;10000 per hour;100 per second")
def search_email(email):
    """Returns exposed breaches for a given email"""
    try:
        email = email.lower()
        exposed_breaches = {"breaches": [], "email": email}

        if not email or not validate_email(email):
            return make_response(jsonify({"Error": "Invalid or not found email"}), 404)

        data_store = datastore.Client()
        xon_key = data_store.key("xon", email)
        xon_record = data_store.get(xon_key)

        alert_key = data_store.key("xon_alert", email)
        alert_record = data_store.get(alert_key)

        if alert_record and alert_record.get("shieldOn", False):
            # if alert_record and alert_record["shieldOn"]:
            return make_response(jsonify({"Error": "Not found"}), 404)

        if xon_record and "site" in xon_record:
            domains = xon_record["site"].split(";")
            filtered_domains = [domain for domain in domains if domain.strip()]
            if filtered_domains:
                exposed_breaches["breaches"].append(filtered_domains)
            else:
                return make_response(
                    jsonify({"Error": "No breaches found", "email": email}), 404
                )

            return jsonify(exposed_breaches)
        else:
            return make_response(
                jsonify({"Error": "No breaches found", "email": email}), 404
            )

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/check-paste/<email>", methods=["GET"])
@LIMITER.limit("50 per day;10 per hour;1 per second")
def search_paste(email):
    """Returns exposed pastes for a given email"""  # To be deprecated soon
    try:
        email = email.lower()
        if not email or not validate_email(email) or not validate_url():
            return make_response(jsonify({"Error": "Not found"}), 404)
        ds_paste = datastore.Client()
        ds_alert = datastore.Client()
        key = ds_paste.key("xon_paste", email)
        task_paste = ds_paste.get(key)
        alert_key = ds_alert.key("xon_alert", email)
        task_alert = ds_alert.get(alert_key)
        if task_alert is None:
            if task_paste is None:
                abort(404)
            else:
                return jsonify({"SearchMePaste": task_paste})
        else:
            if task_alert["shieldOn"]:
                abort(404)
            else:
                if task_paste is None:
                    abort(404)
                else:
                    return jsonify({"SearchMePaste": task_paste})
    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/domain_email_validation/<token>", methods=["GET"])
@LIMITER.limit("50 per day;10 per hour;1 per second")
def domain_validation(token):
    """Returns status of domain email validation"""
    error_template = render_template("domain_email_error.html")
    verification_template = render_template("domain_email_verify.html")
    try:
        if not validate_variables(token):
            return error_template

        email = confirm_token(token)
        datastore_client = datastore.Client()
        query = datastore_client.query(kind="xon_domains")
        query.add_filter("token", "=", token)
        domain_results = list(query.fetch())
        if not domain_results:
            return error_template
        else:
            domain_result = domain_results[0]

            existing_emails = domain_result.get("emails")
            domain_result["emails"] = (
                f"{existing_emails};{email}" if existing_emails else email
            )
        domain_result["verify_timestamp"] = datetime.datetime.now()
        domain_result["verified"] = True
        datastore_client.put(domain_result)

    except Exception as exception_details:
        log_except(request.url, exception_details)
        return error_template
    return verification_template


@XON.route("/v1/domcheck_alert/<domain>", methods=["GET"])
@LIMITER.limit("50 per day;10 per hour;1 per second")
def domcheck_subscribe(domain):
    """Returns status of enabling domcheck-html"""
    try:
        domain = domain.lower()
        if not validate_domain(domain):
            return make_response(jsonify({"Error": "Not found"}), 404)
        token = generate_confirmation_token(domain)
        confirm_url = url_for("domcheck_verification", token=token, _external=True)
        return confirm_url
    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/domcheck_verify/<token>", methods=["GET"])
@LIMITER.limit("50 per day;10 per hour;1 per second")
def domcheck_verification(token):
    """Returns domain of domcheck verification"""
    try:
        if not validate_variables(token) or not token or not validate_url():
            return False
        domain = confirm_token(token)
    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)
    return domain


@XON.route("/v1/alertme/<user_email>", methods=["GET"])
@LIMITER.limit("50 per day;5 per hour;1 per second")
def subscribe_to_alert_me(user_email):
    """Subscribe to alert-me notifications and send confirmation email."""
    try:
        user_email = user_email.lower()
        if (
            not user_email
            or not validate_email_with_tld(user_email)
            or not validate_variables(user_email)
            or not validate_url()
        ):
            return make_response(jsonify({"Error": "Invalid request"}), 400)

        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)

        verification_token = generate_confirmation_token(user_email)
        confirmation_url = url_for(
            "alert_me_verification",
            verification_token=verification_token,
            _external=True,
        )

        if alert_task is None or not alert_task["verified"]:
            alert_task_data = datastore.Entity(
                datastore_client.key("xon_alert", user_email),
                exclude_from_indexes=[
                    "insert_timestamp",
                    "verify_timestamp",
                    "verified",
                    "unSubscribeOn",
                    "shieldOn",
                ],
            )
            if alert_task is None:
                alert_task_data.update(
                    {
                        "insert_timestamp": datetime.datetime.now(),
                        "verified": False,
                        "unSubscribeOn": False,
                        "shieldOn": False,
                    }
                )
                datastore_client.put(alert_task_data)

            if "X-Forwarded-For" in request.headers:
                client_ip_address = (
                    request.headers["X-Forwarded-For"].split(",")[0].strip()
                )
            elif "X-Real-IP" in request.headers:
                client_ip_address = request.headers["X-Real-IP"].strip()
            else:
                client_ip_address = request.remote_addr

            preferred_ip = get_preferred_ip_address(client_ip_address)

            if preferred_ip:
                location = fetch_location_by_ip(preferred_ip)
            else:
                # To be revisited
                pass
            user_agent_string = request.headers.get("User-Agent")
            user_agent = parse(user_agent_string)
            browser_type = (
                user_agent.browser.family + " " + user_agent.browser.version_string
            )
            client_platform = user_agent.os.family

            send_alert_confirmation(
                user_email,
                confirmation_url,
                f"{preferred_ip} ({location})",
                browser_type,
                client_platform,
            )

            return make_response(jsonify({"Success": "Subscription Successful"}), 200)
        else:
            return make_response(jsonify({"Error": "Not found"}), 404)

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


#        return make_response(jsonify({"Error": "An error occurred"}), 500)


@XON.route("/v1/verifyme/<verification_token>", methods=["GET"])
@LIMITER.limit("50 per day;5 per hour;1 per second")
def alert_me_verification(verification_token):
    """Verify alert-me subscription and send initial leaks if any."""
    error_template = render_template("email_error.html")
    verification_template = render_template("email_verify.html")

    try:
        if (
            not verification_token
            or not validate_variables(verification_token)
            or not validate_url()
        ):
            return make_response(jsonify({"Error": "Not found"}), 404)

        user_email = confirm_token(verification_token)
        if not user_email:
            return make_response(jsonify({"Error": "Not found"}), 404)

        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)

        if alert_task["verified"]:
            return error_template
        else:
            with datastore_client.transaction():
                alert_task["verify_timestamp"] = datetime.datetime.now()
                alert_task["verified"] = True
                alert_task["token"] = verification_token
                datastore_client.put(alert_task)

            exposure_info = get_exposure(user_email).strip()
            sensitive_exposure_info = get_sensitive_exposure(user_email).strip()

            if len(exposure_info) == 0 and len(sensitive_exposure_info) == 0:
                return verification_template
            else:
                base_url = "https://xposedornot.com/"
                email_param = f"email={user_email}"
                token_param = f"&token={verification_token}"
                breaches_link = (
                    base_url + "email-report.html?" + email_param + "&" + token_param
                )
                return render_template(
                    "email_success.html", breaches_link=breaches_link
                )

    except Exception as exception_details:
        log_except(request.url, exception_details)
        return error_template


@XON.route("/v1/send_verification", methods=["GET"])
@LIMITER.limit("50 per day;10 per hour;1 per second")
def send_verification():
    """Verify and send confirmation for report access."""
    try:
        verification_token = request.args.get("token", default="None")
        if (
            verification_token != "None"
            and not validate_variables(verification_token)
            or not validate_url()
        ):
            return make_response(jsonify({"status": "Failed"}), 200)

        user_email = request.args.get("email").lower()

        if (
            not verification_token
            or not validate_email_with_tld(user_email)
            or not validate_variables(verification_token)
            or not validate_url()
        ):
            return make_response(jsonify({"status": "Failed"}), 200)
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", user_email)
        alert_task = datastore_client.get(alert_key)

        if alert_task["verified"] and alert_task["token"] == verification_token:
            now_str = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            verification_timestamp_str = alert_task["verify_timestamp"].strftime(
                "%Y-%m-%dT%H:%M:%S"
            )

            now_in_seconds = time.mktime(time.strptime(now_str, "%Y-%m-%dT%H:%M:%S"))
            verification_timestamp_in_seconds = time.mktime(
                time.strptime(verification_timestamp_str, "%Y-%m-%dT%H:%M:%S")
            )

            time_diff_hours = (
                now_in_seconds - verification_timestamp_in_seconds
            ) / 3600

            if time_diff_hours < 24:
                ds_xon = datastore.Client()
                xon_key = ds_xon.key("xon", user_email)
                xon_record = ds_xon.get(xon_key)
                if xon_record is not None:
                    site = str(xon_record["site"]) if "site" in xon_record else ""
                    sensitive_site = (
                        str(xon_record["sensitive_site"])
                        if "sensitive_site" in xon_record
                        else ""
                    )
                    if site or sensitive_site:
                        sensitive_site_breaches = (
                            get_breaches(sensitive_site) if sensitive_site else ""
                        )
                        breach_metrics = (
                            get_breaches_analytics(site, sensitive_site)
                            if site or sensitive_site
                            else {}
                        )
                    return make_response(
                        jsonify(
                            {
                                "status": "Success",
                                "sensitive_breach_details": sensitive_site_breaches,
                                "BreachMetrics": breach_metrics,
                            }
                        ),
                        200,
                    )

            else:
                return make_response(jsonify({"status": "Failed"}), 200)
        else:
            return make_response(jsonify({"status": "Failed"}), 200)

    except Exception as exception_details:
        log_except(request.url, exception_details)
        return make_response(jsonify({"status": "Failed"}), 200)


@XON.route("/v1/create-api-key/<token>", methods=["GET"])
@LIMITER.limit("50 per day;10 per hour;1 per second")
def create_api_key(token):
    """Generates or renews an API key for a user identified by a provided token"""
    try:
        if not token or not validate_variables(token) or not validate_url():
            return jsonify({"status": "error", "message": "Invalid token or URL"}), 400

        client = datastore.Client()
        query = client.query(kind="xon_domains_session")
        query.add_filter("domain_magic", "=", token)
        user = list(query.fetch())
        if not user:
            return jsonify({"status": "error", "message": "Invalid token"}), 400

        email = user[0].key.name
        api_key = secrets.token_hex(16)
        timestamp = datetime.datetime.utcnow()
        api_key_key = client.key("xon_api_key", email)
        api_key_entity = client.get(api_key_key)
        if api_key_entity:
            api_key_entity.update({"api_key": api_key, "updated_timestamp": timestamp})
        else:
            api_key_entity = datastore.Entity(key=api_key_key)
            api_key_entity.update(
                {
                    "api_key": api_key,
                    "insert_timestamp": timestamp,
                    "updated_timestamp": timestamp,
                }
            )
        client.put(api_key_entity)
        return jsonify({"status": "success", "api_key": api_key}), 200

    except Exception as exception_details:
        log_except(request.url, exception_details)
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Unfortunately an error occurred while creating/renewing the API key",
                }
            ),
            500,
        )


@XON.route("/v1/get-api-key/<token>", methods=["GET"])
@LIMITER.limit("100 per day;50 per hour;2 per second")
def get_api_key(token):
    """Retrieves the existing API key for a user identified by a provided token."""
    try:
        if not token or not validate_variables(token) or not validate_url():
            return jsonify({"status": "error", "message": "Invalid token or URL"}), 400

        client = datastore.Client()
        query = client.query(kind="xon_domains_session")
        query.add_filter("domain_magic", "=", token)
        user = list(query.fetch())
        if not user:
            return jsonify({"status": "error", "message": "Invalid token"}), 400

        email = user[0].key.name
        api_key_key = client.key("xon_api_key", email)
        api_key_entity = client.get(api_key_key)
        if api_key_entity:
            api_key = api_key_entity.get("api_key")
            return jsonify({"status": "success", "api_key": api_key}), 200
        else:
            return jsonify({"status": "error", "message": "API key not found"}), 404

    except Exception as exception_details:
        log_except(request.url, exception_details)
        return jsonify({"status": "error", "message": "API key not found"}), 404


@CSRF.exempt
@XON.route("/v1/domain-breaches/", methods=["POST"])
@LIMITER.limit("500 per day;100 per hour;1 per second")
def protected():
    """Retrieves the data breaches and related metrics for an API-key"""
    try:
        # TODO: Validation
        api_key = request.headers.get("x-api-key")
        if not api_key or api_key.strip() == "" or not validate_url():
            return (
                jsonify({"status": "error", "message": "Invalid or missing API key"}),
                401,
            )

        # Instantiate a datastore client
        datastore_client = datastore.Client()

        # Create a query against the kind 'xon_api_key'
        query = datastore_client.query(kind="xon_api_key")

        # Filter for entries where the api_key field matches the api key from the request header
        query.add_filter("api_key", "=", api_key)

        # Run the query
        results = list(query.fetch())

        if not results:
            return (
                jsonify({"status": "error", "message": "Invalid or missing API key"}),
                401,
            )

        # If the key is valid, return the associated email
        email = results[0].key.name

        # Additional operations
        query = datastore_client.query(kind="xon_domains")
        query.add_filter("email", "=", email)
        verified_domains = [entity["domain"] for entity in query.fetch()]

        current_year = datetime.datetime.utcnow().year
        yearly_summary = defaultdict(int)
        yearly_summary = {str(year): 0 for year in range(2007, current_year + 1)}

        yearly_breach_summary = {
            str(year): defaultdict(int) for year in range(2007, current_year + 1)
        }

        breach_summary = defaultdict(int)
        domain_summary = defaultdict(int)
        detailed_breach_info = {}
        breach_details = []

        for domain in verified_domains:
            query = datastore_client.query(kind="xon_domains_summary")
            query.add_filter("domain", "=", domain)
            # Initialize domain count to 0
            domain_summary[domain] = 0
            for entity in query.fetch():
                if entity["breach"] == "No_Breaches":
                    continue
                # fetch the breach to get the breach date and details
                breach_key = datastore_client.key("xon_breaches", entity["breach"])
                breach = datastore_client.get(breach_key)
                breach_year = breach["breached_date"].strftime("%Y")
                yearly_summary[breach_year] += entity["email_count"]
                yearly_breach_summary[breach_year][entity["breach"]] += entity[
                    "email_count"
                ]
                # count the occurrences of each breach
                breach_summary[entity["breach"]] += entity["email_count"]
                domain_summary[domain] += entity["email_count"]
                # save the detailed breach info
                detailed_breach_info[entity["breach"]] = {
                    "breached_date": breach["breached_date"],
                    "logo": breach["logo"],
                    "password_risk": breach["password_risk"],
                    "searchable": breach["searchable"],
                    "xposed_data": breach["xposed_data"],
                    "xposed_records": breach["xposed_records"],
                    "xposure_desc": breach["xposure_desc"],
                }
            query = datastore_client.query(kind="xon_domains_details")
            query.add_filter("domain", "=", domain)
            for entity in query.fetch():
                breach_details.append(
                    {
                        "email": entity["email"],
                        "domain": entity["domain"],
                        "breach": entity["breach"],
                    }
                )
        top10_breaches = sorted(
            breach_summary.items(), key=itemgetter(1), reverse=True
        )[:10]
        metrics = {
            "Yearly_Metrics": dict(yearly_summary),
            "Domain_Summary": dict(domain_summary),
            "Breach_Summary": dict(breach_summary),
            "Breaches_Details": breach_details,
            "Top10_Breaches": dict(top10_breaches),
            "Detailed_Breach_Info": detailed_breach_info,
        }
        return jsonify({"status": "success", "metrics": metrics}), 200

    except Exception as exception_details:
        log_except(request.url, exception_details)
        return (
            jsonify(
                {"status": "error", "message": "An error occurred during processing"}
            ),
            500,
        )


@CSRF.exempt
@XON.route("/v1/integrations/verify-api-key/<domain>", methods=["POST"])
@LIMITER.limit("500 per day;50 per hour;2 per second")
def verify_api_key(domain):
    """Verifies the provided API key for a specific domain"""
    try:
        api_key = request.headers.get("x-api-key")
        if not api_key or api_key.strip() == "":
            return jsonify({"status": "error", "message": "Missing API key"}), 400

        datastore_client = datastore.Client()

        # Verify API key and fetch associated email
        key_query = datastore_client.query(kind="xon_api_key")
        key_query.add_filter("api_key", "=", api_key)
        key_results = list(key_query.fetch())

        if not key_results:
            return jsonify({"status": "error", "message": "Invalid API key"}), 401

        email = key_results[0].key.name

        # Check if the email is associated with the specified domain
        domain_query = datastore_client.query(kind="xon_domains")
        domain_query.add_filter("email", "=", email)
        domain_query.add_filter("domain", "=", domain)
        domain_results = list(domain_query.fetch())

        if not domain_results:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "API key not associated with this domain",
                    }
                ),
                403,
            )

        return (
            jsonify(
                {
                    "status": "success",
                    "message": "API key is valid and associated with the domain",
                }
            ),
            200,
        )

    except Exception as exception_details:
        log_except(request.url, exception_details)
        return (
            jsonify(
                {"status": "error", "message": "An error occurred during processing"}
            ),
            500,
        )


@CSRF.exempt
@XON.route("/v1/integrations/exposed-breaches/<domain>", methods=["POST"])
@LIMITER.limit("500 per day;50 per hour;2 per second")
def get_exposed_breaches(domain):
    """Returns all exposed breaches for the specified domain associated with the provided API key's email"""
    try:
        api_key = request.headers.get("x-api-key")
        if not api_key:
            return jsonify({"status": "error", "message": "API key is required"}), 401

        datastore_client = datastore.Client()

        # Verify API key and fetch associated email
        key_query = datastore_client.query(kind="xon_api_key")
        key_query.add_filter("api_key", "=", api_key)
        key_results = list(key_query.fetch())

        if not key_results:
            return jsonify({"status": "error", "message": "Invalid API key"}), 401

        email = key_results[0].key.name

        # Fetch breaches associated with the specified domain
        breach_query = datastore_client.query(kind="xon")
        breach_query.add_filter("domain", "=", domain)
        breach_results = list(breach_query.fetch())

        if not breach_results:
            return (
                jsonify({"status": "error", "message": "No breaches found for domain"}),
                404,
            )

        breach_summary = {"record_count": 0, "records": []}
        for result in breach_results:
            breach_email = result.key.name
            sites = result["site"].split(";")
            for site in sites:
                breach_summary["records"].append(
                    {"email": breach_email, "breach_name": site}
                )
                breach_summary["record_count"] += 1

        return (
            jsonify(
                {
                    "status": "success",
                    "total_records": breach_summary["record_count"],
                    "breaches": breach_summary["records"],
                }
            ),
            200,
        )

    except Exception as exception_details:
        log_except(request.url, exception_details)
        return jsonify({"status": "error", "message": "An error occurred"}), 500


@XON.route("/v1/domain-alert/<user_email>", methods=["GET"])
@LIMITER.limit("50 per day;10 per hour;1 per second")
def domain_alert(user_email):
    """Initiate domain breaches dashboard access and send confirmation email."""
    try:
        user_email = user_email.lower()
        if (
            not user_email
            or not validate_email_with_tld(user_email)
            or not validate_url()
        ):
            return make_response(jsonify({"Error": "Not found"}), 404)

        datastore_client = datastore.Client()

        # Check if the user exists in xon_domains
        query = datastore_client.query(kind="xon_domains")
        query.add_filter("email", "=", user_email)
        domain_task = list(query.fetch())

        if domain_task:
            alert_key = datastore_client.key("xon_domains_session", user_email)
            alert_task = datastore_client.get(alert_key)

            verification_token = generate_confirmation_token(user_email)
            confirmation_url = url_for(
                "domain_verify", verification_token=verification_token, _external=True
            )

            alert_task_data = datastore.Entity(
                datastore_client.key("xon_domains_session", user_email)
            )
            alert_task_data.update(
                {
                    "magic_timestamp": datetime.datetime.now(),
                    "domain_magic": verification_token,
                }
            )
            datastore_client.put(alert_task_data)

            if "X-Forwarded-For" in request.headers:
                client_ip_address = (
                    request.headers["X-Forwarded-For"].split(",")[0].strip()
                )
            elif "X-Real-IP" in request.headers:
                client_ip_address = request.headers["X-Real-IP"].strip()
            else:
                client_ip_address = request.remote_addr

            preferred_ip = get_preferred_ip_address(client_ip_address)

            if preferred_ip:
                location = fetch_location_by_ip(preferred_ip)
            else:
                # To be revisited
                pass
            user_agent_string = request.headers.get("User-Agent")
            user_agent = parse(user_agent_string)
            browser_type = (
                user_agent.browser.family + " " + user_agent.browser.version_string
            )
            client_platform = user_agent.os.family

            send_dashboard_email_confirmation(
                user_email,
                confirmation_url,
                f"{client_ip_address} ({location})",
                browser_type,
                client_platform,
            )

        # response for all cases
        return make_response(jsonify({"Success": "Domain Alert Successful"}), 200)

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/domain-verify/<verification_token>", methods=["GET"])
@LIMITER.limit("50 per day;10 per hour;1 per second")
def domain_verify(verification_token):
    """Verify domain alerts using MAGIC and send breaches if any."""
    # TODO: all templates here to be revisited
    try:
        error_template = render_template("domain_dashboard_error.html")
        if (
            not verification_token
            or not validate_variables(verification_token)
            or not validate_url()
        ):
            return error_template
        user_email = confirm_token(verification_token)

        if user_email:
            base_url = "https://xposedornot.com/"
            email_param = f"email={user_email}"
            token_param = f"&token={verification_token}"
            dashboard_link = (
                base_url + "breach-dashboard.html?" + email_param + "&" + token_param
            )
            success_template = render_template(
                "domain_dashboard_success.html", link=dashboard_link
            )
            return success_template
        else:
            return error_template

    except Exception as exception_details:
        log_except(request.url, exception_details)
        return error_template


@XON.route("/v1/send_domain_breaches", methods=["GET"])
@LIMITER.limit("500 per day;100 per hour;1 per second")
def send_domain_breaches():
    """Retrieves and sends the data breaches validated by token and email"""
    try:
        email = request.args.get("email")
        verification_token = request.args.get("token")

        # Check for presence of email and token
        if email is None or verification_token is None:
            return make_response(jsonify({"Error": "Missing email or token"}), 400)

        # Validate email and token
        if (
            not validate_email_with_tld(email)
            or not validate_variables(verification_token)
            or not validate_url()
        ):
            return make_response(jsonify({"Error": "Invalid email or token"}), 400)

        # Check for matching session in xon_domains_session
        client = datastore.Client()
        alert_key = client.key("xon_domains_session", email)
        alert_task = client.get(alert_key)
        if not alert_task or alert_task.get("domain_magic") != verification_token:
            return make_response(jsonify({"Error": "Invalid session"}), 400)
        if datetime.datetime.utcnow() - alert_task.get("magic_timestamp").replace(
            tzinfo=None
        ) > timedelta(hours=24):
            return make_response(jsonify({"Error": "Session expired"}), 400)

        query = client.query(kind="xon_domains")
        query.add_filter("email", "=", email)
        verified_domains = [entity["domain"] for entity in query.fetch()]
        current_year = datetime.datetime.utcnow().year
        yearly_summary = defaultdict(int)
        domain_summary = defaultdict(int)
        yearly_summary = {str(year): 0 for year in range(current_year, 2006, -1)}

        yearly_breach_summary = {
            str(year): defaultdict(int) for year in range(current_year, 2006, -1)
        }

        breach_summary = defaultdict(int)
        breach_details = []
        detailed_breach_info = {}
        all_breaches_logo = {}
        for domain in verified_domains:
            domain_summary[domain] = 0
            query = client.query(kind="xon_domains_summary")
            query.add_filter("domain", "=", domain)
            for entity in query.fetch():
                if entity["breach"] == "No_Breaches":
                    continue
                breach_key = client.key("xon_breaches", entity["breach"])
                breach = client.get(breach_key)

                default_breach_info = {
                    "breached_date": None,
                    "logo": "",
                    "password_risk": "",
                    "searchable": "",
                    "xposed_data": "",
                    "xposed_records": "",
                    "xposure_desc": "",
                }

                if breach:
                    for key in default_breach_info.keys():
                        if key not in breach or breach[key] is None:
                            breach[key] = default_breach_info[
                                key
                            ]  # Set to default value if missing or None

                    all_breaches_logo[entity["breach"]] = breach["logo"]
                    breach_logo = breach["logo"]
                    breach_year = (
                        breach["breached_date"].strftime("%Y")
                        if breach["breached_date"]
                        else "Unknown Year"
                    )

                    yearly_summary[breach_year] += entity["email_count"]
                    yearly_breach_summary[breach_year][entity["breach"]] += entity[
                        "email_count"
                    ]
                    breach_summary[entity["breach"]] += entity["email_count"]
                    domain_summary[domain] += entity["email_count"]
                    detailed_breach_info[entity["breach"]] = {
                        "breached_date": breach["breached_date"],
                        "logo": breach["logo"],
                        "password_risk": breach["password_risk"],
                        "searchable": breach["searchable"],
                        "xposed_data": breach["xposed_data"],
                        "xposed_records": breach["xposed_records"],
                        "xposure_desc": breach["xposure_desc"],
                    }

            # fetch the breach details for the given domain
            query = client.query(kind="xon_domains_details")
            query.add_filter("domain", "=", domain)
            for entity in query.fetch():
                breach_details.append(
                    {
                        "email": entity["email"],
                        "domain": entity["domain"],
                        "breach": entity["breach"],
                    }
                )

        yearly_breach_hierarchy = {"description": "Data Breaches", "children": []}
        for year, breaches in yearly_breach_summary.items():
            year_node = {"description": year, "children": []}
            for breach, count in breaches.items():
                breach_logo = all_breaches_logo[breach]
                details = (
                    "<img src='" + breach_logo + "' style='height:40px;width:65px;' />"
                    "<a target='_blank' href='https://xposedornot.com/xposed/#"
                    + breach
                    + "'> &nbsp;"
                    + "Details</a>"
                )
                breach_node = {
                    "description": details,
                    "tooltip": "Click here for " + breach + " details👇",
                    "children": [],
                }
                year_node["children"].append(breach_node)
            yearly_breach_hierarchy["children"].append(year_node)
        top10_breaches = sorted(
            breach_summary.items(), key=itemgetter(1), reverse=True
        )[:5]
        metrics = {
            "Yearly_Metrics": dict(yearly_summary),
            "Domain_Summary": dict(domain_summary),
            "Breach_Summary": dict(breach_summary),
            "Breaches_Details": breach_details,
            "Top10_Breaches": dict(top10_breaches),
            "Detailed_Breach_Info": detailed_breach_info,
            "Verified_Domains": verified_domains,
        }
        metrics["Yearly_Breach_Hierarchy"] = yearly_breach_hierarchy

        return jsonify(metrics)

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/shield-on/<email>", methods=["GET"])
@LIMITER.limit("50 per day;10 per hour;1 per second")
def activate_shield(email):
    """Enable privacy shield for public searches and return status."""
    try:
        email = email.lower()
        if not email or not validate_email_with_tld(email) or not validate_url():
            return make_response(jsonify({"Error": "Not found"}), 404)
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", email)
        alert_task = datastore_client.get(alert_key)
        token_shield = generate_confirmation_token(email)
        confirmation_url = url_for(
            "verify_shield", token_shield=token_shield, _external=True
        )
        if alert_task is None or not alert_task["shieldOn"]:
            alert_entity = datastore.Entity(
                datastore_client.key("xon_alert", email),
                exclude_from_indexes=[
                    "insert_timestamp",
                    "verify_timestamp",
                    "verified",
                    "unSubscribeOn",
                    "shieldOn",
                ],
            )

            if alert_task is None:
                alert_entity.update(
                    {
                        "insert_timestamp": datetime.datetime.now(),
                        "verified": False,
                        "shieldOn": False,
                        "unSubscribeOn": False,
                    }
                )
                datastore_client.put(alert_entity)

            if "X-Forwarded-For" in request.headers:
                client_ip_address = (
                    request.headers["X-Forwarded-For"].split(",")[0].strip()
                )
            elif "X-Real-IP" in request.headers:
                client_ip_address = request.headers["X-Real-IP"].strip()
            else:
                client_ip_address = request.remote_addr

            preferred_ip = get_preferred_ip_address(client_ip_address)

            if preferred_ip:
                location = fetch_location_by_ip(preferred_ip)
            else:
                pass
            user_agent_string = request.headers.get("User-Agent")
            user_agent = parse(user_agent_string)
            browser_type = (
                str(user_agent.browser.family) + " " + str(user_agent.browser)
            )
            client_platform = user_agent.os.family

            send_shield_email(
                email,
                confirmation_url,
                client_ip_address + location,
                browser_type,
                client_platform,
            )
            return make_response(jsonify({"Success": "ShieldAdded"}), 200)

        elif alert_task["shieldOn"]:
            return make_response(jsonify({"Success": "AlreadyOn"}), 200)

        elif not alert_task["shieldOn"]:
            send_shield_email(
                email,
                confirmation_url,
                client_ip_address + location,
                browser_type,
                client_platform,
            )
            return make_response(jsonify({"Success": "ShieldAdded"}), 200)

        else:
            abort(404)

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/verify-shield/<token_shield>", methods=["GET"])
@LIMITER.limit("50 per day;10 per hour;1 per second")
def verify_shield(token_shield):
    """Verify privacy shield for public searches and return status."""
    try:
        if (
            not token_shield
            or not validate_variables(token_shield)
            or not validate_url()
        ):
            return render_template("email_shield_error.html")

        email = confirm_token(token_shield)

        if not email:
            return render_template("email_shield_error.html")

        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", email)
        alert_task = datastore_client.get(alert_key)

        if alert_task:
            alert_task["shield_timestamp"] = datetime.datetime.now()
            alert_task["shieldOn"] = True
            datastore_client.put(alert_task)
        else:
            alert_task = datastore.Entity(key=alert_key)
            alert_task["insert_timestamp"] = datetime.datetime.now()
            alert_task["shield_timestamp"] = datetime.datetime.now()
            alert_task["shieldOn"] = True
            datastore_client.put(alert_task)

        return render_template("email_shield_verify.html")

    except Exception as exception_details:
        log_except(request.url, exception_details)
        return render_template("email_shield_error.html")


@XON.route("/v1/unsubscribe-on/<email>", methods=["GET"])
@LIMITER.limit("20 per day;5 per hour;1 per second")
def unsubscribe(email):
    """Unsubscribe from alerts and return status."""
    try:
        email = email.lower()
        if not email or not validate_email_with_tld(email) or not validate_url():
            return make_response(jsonify({"Error": "Not found"}), 404)

        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", email)
        alert_task = datastore_client.get(alert_key)

        if alert_task is None or not alert_task["unSubscribeOn"]:
            task_entity = datastore.Entity(
                datastore_client.key("xon_alert", email),
                exclude_from_indexes=[
                    "insert_timestamp",
                    "verify_timestamp",
                    "verified",
                    "unSubscribeOn",
                    "shieldOn",
                ],
            )
            if alert_task is None:
                task_entity.update({"unSubscribeOn": False})
                datastore_client.put(task_entity)

            unsubscribe_token = generate_confirmation_token(email)
            confirm_url = url_for(
                "verify_unsubscribe",
                unsubscribe_token=unsubscribe_token,
                _external=True,
            )
            send_unsub_email(email, confirm_url)

            return make_response(jsonify({"Success": "UnSubscribed"}), 200)

        elif alert_task["unSubscribeOn"]:
            return make_response(jsonify({"Success": "AlreadyUnSubscribed"}), 200)

        else:
            abort(404)
    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/verify_unsub/<unsub_token>", methods=["GET"])
@LIMITER.limit("20 per day;5 per hour;1 per second")
def verify_unsubscribe(unsubscribe_token):
    """Returns response based on verification for unsubscribe token."""
    error_template = render_template("email_unsub_error.html")
    verification_template = render_template("email_unsub_verify.html")

    if (
        not unsubscribe_token
        or not validate_variables(unsubscribe_token)
        or not validate_url()
    ):
        return error_template

    try:
        email = confirm_token(unsubscribe_token)
        datastore_client = datastore.Client()
        alert_key = datastore_client.key("xon_alert", email)
        alert_task = datastore_client.get(alert_key)

        if alert_task["unSubscribeOn"]:
            return error_template

        alert_task["unSubscribe_timestamp"] = datetime.datetime.now()
        alert_task["unSubscribeOn"] = True
        datastore_client.put(alert_task)
    except Exception as exception_details:
        log_except(request.url, exception_details)
        return error_template

    return verification_template


@XON.route("/v1/domain-breach-summary", methods=["GET"])
@LIMITER.limit("50 per day;10 per hour;1 per second")
def get_xdomains():
    """Returns exposed data at domain level"""
    try:
        domain = request.args.get("d").lower()
        if domain is None or not validate_domain(domain) or not validate_url():
            return make_response(jsonify({"Error": "Not found"}), 404)
        ds_xon = datastore.Client()
        xon_rec = ds_xon.query(kind="xon")
        xon_rec.add_filter("domain", "=", domain.strip())
        query_xon = xon_rec.fetch()
        total = emails_count = 0
        breaches_dict = {"breaches_details": []}
        for entity_xon in query_xon:
            if emails_count <= 50:
                emails_count += 1
        ds_paste = datastore.Client()
        paste_rec = ds_paste.query(kind="xon_paste")
        paste_rec.add_filter("domain", "=", domain.strip())
        query_paste = paste_rec.fetch()
        pastes_count = 0
        for entity_paste in query_paste:
            if pastes_count >= 50:
                exit
            else:
                pastes_count += 1
        total = emails_count + pastes_count
        breaches_dict["breaches_details"].append(
            {
                "breachid": domain,
                "breach_pastes": pastes_count,
                "breach_emails": emails_count,
                "breach_total": total,
            }
        )
        return jsonify({"sendDomains": breaches_dict, "SearchStatus": "Success"})
    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/domain_verification", methods=["GET"])
@LIMITER.limit("50 per day;20 per hour;1 per second")
def domain_verification():
    """Used for validating domain ownership/authority"""
    try:
        command = request.args.get("z")
        domain = request.args.get("d")
        email = request.args.get("a", "catch-all@xposedornot.com").lower()
        code = request.args.get("v", "xon-is-good")

        if not validate_variables([command, domain, email, code]):
            return make_response(jsonify({"Error": "Invalid input"}), 400)

        prefix = "xon_verification"
        if (
            not validate_domain(domain)
            or not validate_email_with_tld(email)
            or not validate_url()
        ):
            return make_response(jsonify({"Error": "Not found"}), 404)

        command_dict = {
            "c": lambda: check_emails(domain),
            "d": lambda: verify_email(domain, email),
            "e": lambda: verify_dns(domain, email, code, prefix),
            "a": lambda: verify_html(domain, email, code, prefix),
        }

        if command in command_dict:
            return command_dict[command]()
        else:
            return jsonify({"domainVerification": "Failure"})

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)

    return jsonify({"domainVerification": "Failure"})


@CSRF.exempt
@XON.route("/v1/teams-channel-setup", methods=["POST"])
def xon_alerts_teams():
    """Used for Teams channel initial setup"""
    try:
        # Extracting data from the request
        data = request.json

        token = data.get("token")
        domain = data.get("domain")
        webhook = data.get("webhook")
        action = data.get("action")

        # Validate mandatory fields
        if not validate_variables([token, domain, webhook, action]):
            return (
                jsonify({"status": "error", "message": "Invalid input variables"}),
                400,
            )

        # Session validation
        client = datastore.Client()
        query = client.query(kind="xon_domains_session")
        query.add_filter("domain_magic", "=", token)
        user_session = list(query.fetch())

        if not user_session:
            return jsonify({"status": "error", "message": "Invalid session token"}), 400

        email = user_session[0].key.name

        # Domain verification check
        domain_query = client.query(kind="xon_domains")
        domain_query.add_filter("domain", "=", domain)
        domain_query.add_filter("email", "=", email)
        domain_record = list(domain_query.fetch())

        if not domain_record or not domain_record[0].get("verified"):
            return (
                jsonify(
                    {"status": "error", "message": "Domain not verified for this email"}
                ),
                400,
            )
        record_key = client.key("xon_teams_channel", f"{email}_{domain}")

        if action == "init":
            record = client.get(record_key)

            # Check if channel is already verified
            if record and record.get("status") == "verified":
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Channel already exists and is verified",
                        }
                    ),
                    400,
                )

            encrypted_webhook = encrypt_data(webhook)

            if record:
                record.update({"updated_timestamp": datetime.datetime.utcnow()})
                verify_token = record.get("verify_token")
            else:
                verify_token = secrets.token_hex(16)
                record = datastore.Entity(key=record_key)
                record.update(
                    {
                        "tokens": data.get("tokens"),
                        "domain": domain,
                        "webhook": encrypted_webhook,
                        "status": "init",
                        "verify_token": verify_token,
                        "insert_timestamp": datetime.datetime.utcnow(),
                        "updated_timestamp": datetime.datetime.utcnow(),
                    }
                )

            client.put(record)

            # Send a message to Teams channel
            decrypted_webhook = decrypt_data(encrypted_webhook)
            message_content = (
                f"🌟 **Welcome to XposedOrNot Data Breach Alerts!** 🌟\n\n"
                f"🔑 Your verification token is: `{verify_token}`\n\n"
                f"\n\n✅ **What to do next?**\n"
                f"\n\n1️⃣ Copy this verification token.\n"
                f"\n\n2️⃣ Paste it back into your Channel verification page to complete the verification process.\n\n"
                f"\n\n_Thank you for using XON!_"
            )
            message = {"text": message_content}
            response = requests.post(decrypted_webhook, json=message)
            if response.status_code != 200:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Failed to send message to Teams channel",
                        }
                    ),
                    500,
                )

            return jsonify({"status": "initiated"}), 200

        elif action == "verify":
            verify_token = data.get("verify_token")
            if not verify_token:
                return (
                    jsonify(
                        {"status": "error", "message": "Missing verification token"}
                    ),
                    400,
                )

            record = client.get(record_key)
            if not record:
                return jsonify({"status": "error", "message": "Record not found"}), 404

            if record.get("verify_token") == verify_token:
                record.update({"status": "verified"})
                client.put(record)
                # Create a success message
                success_message_content = (
                    f"🎉 **Verification Successful!** 🎉\n\n"
                    f"🚀 Your Teams channel is now successfully connected to XposedOrNot.\n"
                    f"🔔 You will start receiving new data breach notifications here.\n\n"
                    f"_Thank you for setting up Notifications!_"
                )

                decrypted_webhook = decrypt_data(record.get("webhook"))
                success_message = {"text": success_message_content}
                response = requests.post(decrypted_webhook, json=success_message)
                return (
                    jsonify(
                        {"status": "success", "message": "Verification successful"}
                    ),
                    200,
                )
            else:
                record.update({"status": "failed"})
                client.put(record)
                return (
                    jsonify({"status": "error", "message": "Verification failed"}),
                    400,
                )

        else:
            return (
                jsonify({"status": "error", "message": "Invalid action provided"}),
                400,
            )

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@CSRF.exempt
@XON.route("/v1/slack-channel-setup", methods=["POST"])
def xon_alerts_slack():
    """Used for initial Slack channel setup"""
    try:
        data = request.json
        token = data.get("token")
        domain = data.get("domain")
        webhook = data.get("webhook")
        action = data.get("action")

        if not validate_variables([token, domain, webhook, action]):
            return (
                jsonify({"status": "error", "message": "Invalid input variables"}),
                400,
            )

        client = datastore.Client()
        query = client.query(kind="xon_domains_session")
        query.add_filter("domain_magic", "=", token)
        user_session = list(query.fetch())

        if not user_session:
            return jsonify({"status": "error", "message": "Invalid session token"}), 400

        email = user_session[0].key.name

        domain_query = client.query(kind="xon_domains")
        domain_query.add_filter("domain", "=", domain)
        domain_query.add_filter("email", "=", email)
        domain_record = list(domain_query.fetch())

        if not domain_record or not domain_record[0].get("verified"):
            return (
                jsonify(
                    {"status": "error", "message": "Domain not verified for this email"}
                ),
                400,
            )

        record_key = client.key("xon_slack_channel", f"{email}_{domain}")

        if action == "init":
            record = client.get(record_key)

            if record and record.get("status") == "verified":
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Channel already exists and is verified",
                        }
                    ),
                    400,
                )

            encrypted_webhook = encrypt_data(webhook)

            if record:
                record.update({"updated_timestamp": datetime.datetime.utcnow()})
                verify_token = record.get("verify_token")
            else:
                verify_token = secrets.token_hex(16)
                record = datastore.Entity(key=record_key)
                record.update(
                    {
                        "tokens": data.get("tokens"),
                        "domain": domain,
                        "webhook": encrypted_webhook,
                        "status": "init",
                        "verify_token": verify_token,
                        "insert_timestamp": datetime.datetime.utcnow(),
                        "updated_timestamp": datetime.datetime.utcnow(),
                    }
                )

            client.put(record)

            decrypted_webhook = decrypt_data(encrypted_webhook)
            message_content = {
                "text": "Welcome to XposedOrNot Data Breach Alerts!",
                "attachments": [
                    {
                        "color": "#36a64f",
                        "title": "Verification Required",
                        "text": "Your verification token is: `{}`".format(verify_token),
                        "fields": [
                            {
                                "title": "What to do next?",
                                "value": "Copy this token and paste it back into your Channel verification page to complete the verification process.",
                                "short": False,
                            }
                        ],
                        "footer": "XposedOrNot",
                        "ts": datetime.datetime.utcnow().timestamp(),
                    }
                ],
            }
            response = requests.post(decrypted_webhook, json=message_content)
            if response.status_code != 200:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Failed to send message to Slack channel",
                        }
                    ),
                    500,
                )

            return jsonify({"status": "initiated"}), 200

        elif action == "verify":
            verify_token = data.get("verify_token")
            if not verify_token:
                return (
                    jsonify(
                        {"status": "error", "message": "Missing verification token"}
                    ),
                    400,
                )

            record = client.get(record_key)
            if not record:
                return jsonify({"status": "error", "message": "Record not found"}), 404

            if record.get("verify_token") == verify_token:
                record.update({"status": "verified"})
                client.put(record)

                decrypted_webhook = decrypt_data(record.get("webhook"))
                success_message_content = {
                    "text": " 🎉 Verification Successful! Your Slack channel is now successfully connected to XposedOrNot. You will start receiving new data breach notifications here. 🎉"
                }
                response = requests.post(
                    decrypted_webhook, json=success_message_content
                )
                return (
                    jsonify(
                        {"status": "success", "message": "Verification successful"}
                    ),
                    200,
                )
            else:
                record.update({"status": "failed"})
                client.put(record)
                return (
                    jsonify({"status": "error", "message": "Verification failed"}),
                    400,
                )

        else:
            return (
                jsonify({"status": "error", "message": "Invalid action provided"}),
                400,
            )

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@CSRF.exempt
@XON.route("/v1/webhook-setup", methods=["POST"])
def webhook_setup():
    """Used for webhook initial setup for data breach notifications."""
    try:
        data = request.json
        token = data.get("token")
        domain = data.get("domain")
        webhook_url = data.get("webhook")
        secret = data.get("secret")
        action = data.get("action")

        # Validate mandatory fields
        if not all([token, domain, webhook_url, secret, action]):
            return (
                jsonify({"status": "error", "message": "Missing required fields"}),
                400,
            )

        client = datastore.Client()

        # Session validation
        session_query = client.query(kind="xon_domains_session")
        session_query.add_filter("domain_magic", "=", token)
        user_session = list(session_query.fetch())

        if not user_session:
            return (
                jsonify({"status": "error", "message": "Session not found or invalid"}),
                400,
            )

        user_email = user_session[0].key.name

        # Domain verification check
        domain_query = client.query(kind="xon_domains")
        domain_query.add_filter("domain", "=", domain)
        domain_query.add_filter("email", "=", user_email)
        domain_record = list(domain_query.fetch())

        if not domain_record or not domain_record[0].get("verified"):
            return jsonify({"status": "error", "message": "Domain not verified"}), 400

        webhook_key = client.key("xon_webhook", f"{user_email}_{domain}")

        if action == "init":
            encrypted_webhook_url = encrypt_data(webhook_url)
            encrypted_secret = encrypt_data(secret)
            verify_token = secrets.token_hex(16)
            entity = datastore.Entity(key=webhook_key)
            entity.update(
                {
                    "webhook_url": encrypted_webhook_url,
                    "secret": encrypted_secret,
                    "status": "init",
                    "verify_token": verify_token,
                    "timestamp": datetime.datetime.utcnow(),
                }
            )
            client.put(entity)

            return jsonify({"status": "initiated", "verify_token": verify_token}), 200
        elif action == "verify":
            verify_token = data.get("verify_token")
            if not verify_token:
                return (
                    jsonify(
                        {"status": "error", "message": "Missing verification token"}
                    ),
                    400,
                )

            entity = client.get(webhook_key)
            if not entity or entity.get("verify_token") != verify_token:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Invalid or expired verification token",
                        }
                    ),
                    400,
                )

            entity.update({"status": "verified"})
            client.put(entity)

            return (
                jsonify(
                    {"status": "success", "message": "Webhook verified successfully"}
                ),
                200,
            )
        else:
            return jsonify({"status": "error", "message": "Unsupported action"}), 400
    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/teams-channel-config", methods=["GET"])
def get_teams_channel_config():
    """Used for Teams channel configuration update"""
    try:
        email = request.args.get("email")
        domain = request.args.get("domain")
        token = request.args.get("token")

        if not all([email, domain, token]):
            return (
                jsonify({"status": "error", "message": "Missing required parameters"}),
                400,
            )
        # validation for email,domain,token needed
        client = datastore.Client()
        query = client.query(kind="xon_domains_session")
        query.add_filter("domain_magic", "=", token)
        user_session = list(query.fetch())

        if not user_session:
            return jsonify({"status": "error", "message": "Invalid session token"}), 400

        domain_query = client.query(kind="xon_domains")
        domain_query.add_filter("domain", "=", domain)
        temp_domain_records = list(domain_query.fetch())

        # Filter the results based on the second field
        domain_record = [
            record for record in temp_domain_records if record.get("email") == email
        ]

        # Proceed with the rest of your logic
        if not domain_record or not domain_record[0].get("verified"):
            return (
                jsonify(
                    {"status": "error", "message": "Domain not verified for this email"}
                ),
                400,
            )
        query = client.query(kind="xon_teams_channel")
        query.add_filter("domain", "=", domain)
        temp_channel_configs = list(query.fetch())

        # Extract email from the key and filter the results
        channel_config = None
        for config in temp_channel_configs:
            # Split the key to get the email part
            key_email = config.key.name.split("_")[0]
            if key_email == email:
                channel_config = config
                break

        # Proceed with the rest of your logic
        if not user_session:
            return jsonify({"status": "error", "message": "Invalid session token"}), 400

        if channel_config:
            encrypted_webhook = channel_config.get("webhook")

            decrypted_webhook = decrypt_data(encrypted_webhook)

            config_data = {
                "domain": channel_config.get("domain"),
                "webhook": decrypted_webhook,
            }
            return jsonify({"status": "success", "data": config_data}), 200
        else:
            return (
                jsonify({"status": "error", "message": "Configuration not found"}),
                404,
            )

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/slack-channel-config", methods=["GET"])
def get_slack_channel_config():
    """Used for Slack channel configuration update"""
    try:
        email = request.args.get("email")
        domain = request.args.get("domain")
        token = request.args.get("token")

        if not all([email, domain, token]):
            return (
                jsonify({"status": "error", "message": "Missing required parameters"}),
                400,
            )

        # validation for email,domain,token needed
        client = datastore.Client()
        query = client.query(kind="xon_domains_session")
        query.add_filter("domain_magic", "=", token)
        user_session = list(query.fetch())

        if not user_session:
            return jsonify({"status": "error", "message": "Invalid session token"}), 400

        domain_query = client.query(kind="xon_domains")
        domain_query.add_filter("domain", "=", domain)
        temp_domain_records = list(domain_query.fetch())

        # Filter the results based on the second field
        domain_record = [
            record for record in temp_domain_records if record.get("email") == email
        ]

        if not domain_record or not domain_record[0].get("verified"):
            return (
                jsonify(
                    {"status": "error", "message": "Domain not verified for this email"}
                ),
                400,
            )

        query = client.query(kind="xon_slack_channel")
        query.add_filter("domain", "=", domain)
        temp_channel_configs = list(query.fetch())

        # Extract email from the key and filter the results
        channel_config = None
        for config in temp_channel_configs:
            key_email = config.key.name.split("_")[0]
            if key_email == email:
                channel_config = config
                break

        if not user_session:
            return jsonify({"status": "error", "message": "Invalid session token"}), 400

        if channel_config:
            encrypted_webhook = channel_config.get("webhook")
            decrypted_webhook = decrypt_data(encrypted_webhook)

            config_data = {
                "domain": channel_config.get("domain"),
                "webhook": decrypted_webhook,
            }
            return jsonify({"status": "success", "data": config_data}), 200
        else:
            return (
                jsonify({"status": "error", "message": "Configuration not found"}),
                404,
            )

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/webhook-config", methods=["GET"])
def get_webhook_config():
    """Used for retrieving webhook configuration"""
    try:
        email = request.args.get("email")
        domain = request.args.get("domain")
        token = request.args.get("token")

        if not all([email, domain, token]):
            return (
                jsonify({"status": "error", "message": "Missing required parameters"}),
                400,
            )

        client = datastore.Client()

        # Validate session
        query = client.query(kind="xon_domains_session")
        query.add_filter("domain_magic", "=", token)
        user_session = list(query.fetch())

        if not user_session:
            return jsonify({"status": "error", "message": "Invalid session token"}), 400

        # Domain verification check
        domain_query = client.query(kind="xon_domains")
        domain_query.add_filter("domain", "=", domain)
        domain_record = list(domain_query.fetch())

        domain_record = [
            record for record in domain_record if record.get("email") == email
        ]

        if not domain_record or not domain_record[0].get("verified"):
            return (
                jsonify(
                    {"status": "error", "message": "Domain not verified for this email"}
                ),
                400,
            )

        # Retrieve webhook configuration
        query = client.query(kind="xon_webhook")
        query.add_filter("domain", "=", domain)
        temp_config = list(query.fetch())

        webhook_config = None
        for config in temp_config:
            key_email = config.key.name.split("_")[0]
            if key_email == email:
                webhook_config = config
                break

        if not webhook_config:
            return (
                jsonify(
                    {"status": "error", "message": "Webhook configuration not found"}
                ),
                404,
            )

        decrypted_webhook_url = decrypt_data(webhook_config.get("webhook_url"))

        config_data = {
            "domain": webhook_config.get("domain"),
            "webhook_url": decrypted_webhook_url,
        }

        return jsonify({"status": "success", "data": config_data}), 200

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/breaches", methods=["GET"])
@LIMITER.limit("100 per day;50 per hour;1 per second")
def get_xposed_breaches():
    """
    Fetches and returns the details of data breaches for a specified domain,
    or for all domains if no domain is specified.
    """
    try:
        client = datastore.Client()
        domain = request.args.get("domain")
        breachID = request.args.get("breachID")
        query = client.query(kind="xon_breaches")

        if breachID:
            if not validate_variables(breachID):
                return jsonify({"status": "error", "message": "Invalid Breach ID"}), 400
            query.key_filter(client.key("xon_breaches", breachID), "=")
        elif domain:
            if not validate_domain(domain):
                return jsonify({"status": "error", "message": "Invalid Domain"}), 400
            query.add_filter("domain", "=", domain)
        else:
            query.order = ["-timestamp"]

        latest_entity = list(query.fetch(limit=1))

        if latest_entity:
            latest_timestamp = latest_entity[0]["timestamp"]
            if_modified_since_str = request.headers.get("If-Modified-Since")
            if if_modified_since_str:
                if_modified_since = datetime.datetime.strptime(
                    if_modified_since_str, "%a, %d %b %Y %H:%M:%S GMT"
                )
                if latest_timestamp.replace(tzinfo=None) <= if_modified_since:
                    return make_response("", 304)

        entities = query.fetch()

        if not entities:
            return (
                jsonify(
                    {
                        "status": "Not Found",
                        "message": "No breaches found for the provided criteria",
                    }
                ),
                404,
            )

        fields = [
            "breached_date",
            "domain",
            "industry",
            "logo",
            "password_risk",
            "searchable",
            "sensitive",
            "verified",
            "xposed_data",
            "xposed_records",
            "xposure_desc",
        ]

        labels = {
            "Name/ID": "breachID",
            "breached_date": "breachedDate",
            "domain": "domain",
            "industry": "industry",
            "logo": "logo",
            "password_risk": "passwordRisk",
            "searchable": "searchable",
            "sensitive": "sensitive",
            "verified": "verified",
            "xposed_data": "exposedData",
            "xposed_records": "exposedRecords",
            "xposure_desc": "exposureDescription",
        }
        data = []
        for entity in entities:
            entity_dict = {
                labels[field]: entity[field] for field in fields if field in entity
            }

            for bool_field in ["searchable", "sensitive", "verified"]:
                if bool_field in entity_dict:
                    entity_dict[bool_field] = string_to_boolean(entity_dict[bool_field])

            if "exposedData" in entity_dict:
                entity_dict["exposedData"] = entity_dict["exposedData"].split(";")

            entity_dict[labels["breached_date"]] = (
                entity_dict[labels["breached_date"]].replace(microsecond=0).isoformat()
            )
            entity_dict = {
                labels["Name/ID"]: entity.key.name or entity.key.id,
                **entity_dict,
            }
            entity_dict["referenceURL"] = entity.get("references", "")

            data.append(entity_dict)

        if not data and domain:
            response = {
                "status": "notFound",
                "message": f"No breaches found for domain {domain}",
            }
        else:
            response = {
                "status": "success",
                "exposedBreaches": data,
            }

        return jsonify(response)

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


def string_to_boolean(value):
    """
    Converts a string to a boolean.
    'Yes' becomes True, 'No' becomes False, and trims any whitespace/newlines.
    """
    trimmed_value = value.strip()
    if trimmed_value.lower() == "yes":
        return True
    elif trimmed_value.lower() == "no":
        return False
    else:
        return None


@XON.route("/v1/xon-pulse", methods=["GET"])
@LIMITER.limit("1000 per day;100 per hour;2 per second")
def get_data():
    """Generate news feed for presenting all data breaches news"""
    try:
        client = datastore.Client()
        query = client.query(kind="xon-pulse")
        results = list(query.fetch())

        data = []
        for entity in results:
            item = {
                "title": entity.get("title"),
                "date": entity.get("date").strftime("%Y-%b-%d"),
                "summary": entity.get("description"),
                "url": entity.get("url"),
            }
            data.append(item)

        return jsonify(data)
    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


@XON.route("/v1/rss", methods=["GET"])
@LIMITER.limit("100 per day;50 per hour;1 per second")
def rss_feed():
    """Generate RSS feed for presenting all data breaches in XoN"""
    try:
        feed_generator = FeedGenerator()
        feed_generator.title("XposedOrNot Data Breaches")
        feed_generator.description("Live updates of uploaded data breaches")
        feed_generator.link(href="https://xposedornot.com/xposed")
        feed_generator.contributor(
            name="Devanand Premkumar", email="deva@xposedornot.com"
        )

        datastore_client = datastore.Client()
        query = datastore_client.query(kind="xon_breaches")
        query_iter = query.fetch()

        for entity in query_iter:
            feed_entry = feed_generator.add_entry()
            entity_key = entity.key
            parts = str(entity_key).split(",")
            entity_key = parts[1][:-2][2:]

            feed_entry.id(entity_key)
            feed_entry.title(entity_key)
            feed_entry.link(href="https://xposedornot.com/xposed#" + entity_key)

            description = (
                str(entity["xposure_desc"])
                + ". Exposed data: "
                + str(entity["xposed_data"])
            )
            feed_entry.description(description=description)
            feed_entry.pubDate(entity["timestamp"])
            feed_entry.guid(guid=entity_key, permalink=True)

        response = make_response(feed_generator.rss_str())
        response.headers.set("Content-Type", "application/rss+xml")
        return response

    except Exception as exception_details:
        log_except(request.url, exception_details)
        abort(404)


if __name__ == "__main__":
    XON.run(host="0.0.0.0", port=1806)
    print("Connected and ready to serve the world !")
