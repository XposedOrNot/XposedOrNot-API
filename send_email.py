#!/usr/bin/python
# -*- coding: utf-8 -*-

""" XposedOrNot Mailer Sub-module API module using Mailjet """

import os
import time
from mailjet_rest import Client

API_KEY = os.environ["MJ_API_KEY"]
API_SECRET = os.environ["MJ_API_SECRET"]
mailjet = Client(auth=(API_KEY, API_SECRET), version="v3.1")
FROM_EMAIL = "notifications@xposedornot.com"
FROM_NAME = "XposedOrNot Notifications"


def send_shield_email(email, confirm_url, ip_address, browser, platform):
    """Sends initial XposedOrNot Shield Email"""
    data = {
        "Messages": [
            {
                "From": {
                    "Email": FROM_EMAIL,
                    "Name": FROM_NAME,
                },
                "To": [
                    {
                        "Email": email,
                    }
                ],
                "TemplateID": 320580,
                "TemplateLanguage": True,
                "Subject": "XposedOrNo: Privacy Shield Confirmation",
                "Variables": {
                    "confirm_url": confirm_url,
                    "ip": ip_address,
                    "browser": browser,
                    "platform": platform,
                },
            }
        ]
    }
    result = mailjet.send.create(data=data)


def send_alert_confirmation(email, confirm_url, ip_address, browser, platform):
    """Sends XposedOrNot Alert Me Confirmation Email"""
    data = {
        "Messages": [
            {
                "From": {
                    "Email": FROM_EMAIL,
                    "Name": FROM_NAME,
                },
                "To": [
                    {
                        "Email": email,
                    }
                ],
                "TemplateID": 275596,
                "TemplateLanguage": True,
                "Subject": "XposedOrNot: DataBreach Alert Me Confirmation",
                "Variables": {
                    "confirm_url": confirm_url,
                    "ip": ip_address,
                    "browser": browser,
                    "platform": platform,
                },
            }
        ]
    }
    result = mailjet.send.create(data=data)


def send_dashboard_email_confirmation(
    email, confirm_url, ip_address, browser, platform
):
    """Sends XposedOrNot dashboard-email Confirmation Email"""
    data = {
        "Messages": [
            {
                "From": {
                    "Email": FROM_EMAIL,
                    "Name": FROM_NAME,
                },
                "To": [
                    {
                        "Email": email,
                    }
                ],
                "TemplateID": 4897532,
                "TemplateLanguage": True,
                "Subject": "XposedOrNot: Passwordless Databreach Dashboard",
                "Variables": {
                    "confirm_url": confirm_url,
                    "ip": ip_address,
                    "browser": browser,
                    "platform": platform,
                },
            }
        ]
    }
    result = mailjet.send.create(data=data)


def send_exception_email(api):
    """Sends Exception email to admin"""
    rate_limit = 5
    error_window = 60
    error_count = 0
    last_error_time = 0
    current_time = time.time()
    if current_time - last_error_time <= error_window:
        error_count += 1
        if error_count > rate_limit:
            return
    else:
        error_count = 0
    last_error_time = current_time
    try:
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": FROM_EMAIL,
                        "Name": FROM_NAME,
                    },
                    "To": [
                        {
                            "Email": "deva@xposedornot.com",
                        }
                    ],
                    "TemplateID": 4318335,
                    "TemplateLanguage": True,
                    "Subject": "Xonnie API exception",
                    "Variables": {
                        "api": api,
                    },
                }
            ]
        }
        result = mailjet.send.create(data=data)
    except Exception as e:
        print("Error sending exception email: {}".format(e))


def send_domain_confirmation(email, confirm_url, ip_address, browser, platform):
    """Sends XposedOrNot Domain Confirmation Email"""
    data = {
        "Messages": [
            {
                "From": {
                    "Email": FROM_EMAIL,
                    "Name": FROM_NAME,
                },
                "To": [
                    {
                        "Email": email,
                    }
                ],
                "TemplateID": 1625322,
                "TemplateLanguage": True,
                "Subject": "XposedOrNot: Domain Verification Confirmation",
                "Variables": {
                    "confirm_url": confirm_url,
                    "ip": ip_address,
                    "browser": browser,
                    "platform": platform,
                },
            }
        ]
    }
    result = mailjet.send.create(data=data)
    print(result)


def send_unsub_email(email, confirm_url):
    """Sends XposedOrNot Unsubcribe Email"""
    data = {
        "Messages": [
            {
                "From": {
                    "Email": FROM_EMAIL,
                    "Name": FROM_NAME,
                },
                "To": [
                    {
                        "Email": email,
                    }
                ],
                "TemplateID": 320586,
                "TemplateLanguage": True,
                "Subject": "XposedOrNot: Un-Subscribe from XposedOrNot",
                "Variables": {"confirm_url": confirm_url},
            }
        ]
    }
    result = mailjet.send.create(data=data)


def send_domain_email(email, confirm_url):
    """Sends XposedOrNot Domain Email with Breach Data"""
    data = {
        "Messages": [
            {
                "From": {
                    "Email": FROM_EMAIL,
                    "Name": FROM_NAME,
                },
                "To": [
                    {
                        "Email": email,
                    }
                ],
                "TemplateID": 357300,
                "TemplateLanguage": True,
                "Subject": "XposedOrNot: Domain Data Breaches",
                "Variables": {"confirm_url": confirm_url},
            }
        ]
    }
    return mailjet.send.create(data=data)


def send_alert_email(email, confirm_url):
    """Sends XposedOrNot Breach Data for AlertMe Confirmation"""
    data = {
        "Messages": [
            {
                "From": {
                    "Email": FROM_EMAIL,
                    "Name": FROM_NAME,
                },
                "To": [
                    {
                        "Email": email,
                    }
                ],
                "TemplateID": 324635,
                "TemplateLanguage": True,
                "Subject": "XposedOrNot: New Databreach Notification",
                "Variables": {"confirm_url": confirm_url},
            }
        ]
    }
    return mailjet.send.create(data=data)


def send_subscribe_leaks_initial(email, confirm_url):
    """Sends XposedOrNot initial leak"""
    data = {
        "Messages": [
            {
                "From": {
                    "Email": FROM_EMAIL,
                    "Name": FROM_NAME,
                },
                "To": [
                    {
                        "Email": email,
                    }
                ],
                "TemplateID": 10886213,
                "TemplateLanguage": True,
                "Subject": "XposedOrNot: Data Breaches Report",
                "Variables": {"confirm_url": confirm_url},
            }
        ]
    }
    return mailjet.send.create(data=data)


def send_databreach_alertme(
    email, confirm_url, breach, date, description
):
    """Sends XposedOrNot Data Breach Alert"""
    data = {
        "Messages": [
            {
                "From": {
                    "Email": FROM_EMAIL,
                    "Name": FROM_NAME,
                },
                "To": [
                    {
                        "Email": email,
                    }
                ],
                "TemplateID": 11789921,  
                "TemplateLanguage": True,
                "Subject": "XposedOrNot: Data Breach Alert",
                "Variables": {
                    "breach": breach,         
                    "date": date,             
                    "description": description
                },
            }
        ]
    }
    result = mailjet.send.create(data=data)
    return result

send_databreach_alertme("deva.security@gmail.com", "https://xposedornot.com", "Flipkart", "Mar-2024", "Flipkart data breach data ...")

