#!/usr/bin/python
# -*- coding: utf-8 -*-

""" XposedOrNot Cloudflare API module """

import json
import datetime
import time
import os
import hashlib
import requests
import dateutil.parser as dp
from google.cloud import datastore

AUTH_EMAIL = os.environ["AUTH_EMAIL"]
AUTH_KEY = os.environ["AUTHKEY"]


def update_cf_trans(ip_address):
    """
    Update the Cloud Firestore transaction with the given IP address.

    This function generates a unique key based on the MD5 hash of the IP address.
    It then creates or updates a record in the Cloud Firestore with the current timestamp,
    a blank release timestamp, and the IP address itself as the transaction data.

    Parameters:
    ip_address (str): The IP address to be logged in the transaction.

    Returns:
    None: The function doesn't return anything but updates the datastore with the provided
    IP address.
    """
    key = hashlib.md5(ip_address).hexdigest()
    datastore_client = datastore.Client()
    task_cnt = datastore.Entity(
        datastore_client.key("xon_cf", key),
        exclude_from_indexes=["insrt_tmpstmp", "cf_data"],
    )
    task_cnt.update(
        {
            "insert_timestamp": datetime.datetime.now(),
            "release_timestamp": "",
            "cf_data": ip_address,
        }
    )
    datastore_client.put(task_cnt)


def block_hour(ip_address):
    """
    Block an IP address for one hour using the Cloudflare API, unless the ISP is "Cloudflare."

    Parameters:
    ip_address (str): The IP address to be blocked.

    Returns:
    None: The function performs an API request to block an IP address if necessary.
    """
    isp_info = get_isp_from_ip(ip_address)
    if isp_info and "Cloudflare" in isp_info:

        return

    url = "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules"
    headers = {
        "X-Auth-Email": AUTH_EMAIL,
        "X-Auth-Key": AUTH_KEY,
        "Content-Type": "application/json",
    }
    payload = {
        "mode": "challenge",
        "configuration": {"target": "ip", "value": ip_address},
        "notes": "Hour block enforced",
    }
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=20)

        if response.status_code in [200, 201]:
            update_cf_trans(response.content)
        else:
            print(
                f"Failed to block IP {ip_address}. Status code: {response.status_code}"
            )
    except Exception as e:
        print(f"Error while blocking IP {ip_address}: {e}")


def block_day(ip_address):
    """
    Block an IP address for one day using the Cloudflare API, unless the ISP is "Cloudflare."

    This function sends a POST request to the Cloudflare API to block the given IP address.
    It uses predefined authentication details (AUTH_EMAIL and AUTH_KEY) and sets the mode
    to 'block', targeting the specified IP address. The function logs the action by
    calling `update_cf_trans` with the response content if the request is successful.

    Parameters:
    ip_address (str): The IP address to be blocked.

    Returns:
    None: The function performs an API request to block an IP address if necessary.
    """

    isp_info = get_isp_from_ip(ip_address)
    if isp_info and "Cloudflare" in isp_info:
        print(f"IP {ip_address} belongs to Cloudflare. Skipping block.")
        return

    url = "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules"
    headers = {
        "X-Auth-Email": AUTH_EMAIL,
        "X-Auth-Key": AUTH_KEY,
        "Content-Type": "application/json",
    }
    payload = {
        "mode": "block",
        "configuration": {"target": "ip", "value": ip_address},
        "notes": "Day block enforced",
    }
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=20)

        if response.status_code in [200, 201]:
            update_cf_trans(response.content)
        else:
            print(
                f"Failed to block IP {ip_address}. Status code: {response.status_code}"
            )
    except Exception as e:
        print(f"Error while blocking IP {ip_address}: {e}")


def unblock():
    """
    Unblocks IP addresses that have been blocked for over an hour using the Cloudflare API.

    This function iterates through entities in a Cloud Firestore database, identified by
    the 'xon_cf' kind,looking for entities without a release timestamp. It then checks if
    the blocked IP address has been blocked for more than an hour. If so, it sends a DELETE
    request to the Cloudflare API to unblock the IP address and updates the entity in the
    Cloud Firestore with the current UTC timestamp as the release timestamp.

    Returns:
    bool: Returns True if the function completes execution without errors.
    """

    base_url = "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules/"
    headers = {
        "X-Auth-Email": AUTH_EMAIL,
        "X-Auth-Key": AUTH_KEY,
        "Content-Type": "application/json",
    }
    datastore_client = datastore.Client()
    query = datastore_client.query(kind="xon_cf")
    query.add_filter("release_timestamp", "=", "")
    query_iter = query.fetch()
    for entity in query_iter:
        config = json.loads(entity["cf_data"])
        firewall_rule_id = config["result"]["id"]
        created = config["result"]["created_on"]
        parsed_created = dp.parse(created)
        created_time_in_seconds = parsed_created.strftime("%s")
        current_time_stamp = time.time()
        if float(current_time_stamp) - float(created_time_in_seconds) > 3600:
            url = base_url + firewall_rule_id
            response = requests.request("DELETE", url, headers=headers, timeout=20)
            if response.status_code != 200:
                raise Exception(
                    f"Failed to delete firewall rule: {firewall_rule_id}. "
                    f"Response code: {response.status_code}, "
                    f"Response: {response.text}"
                )
            entity.update({"release_timestamp": datetime.datetime.utcnow().isoformat()})
            datastore_client.put(entity)
    return True


def get_isp_from_ip(ip_address):
    """
    Fetch the ISP for a given IP address using the ipinfo.io API or a similar service.

    Parameters:
    ip_address (str): The IP address to check.

    Returns:
    str: The name of the ISP for the given IP address.
    """
    try:
        url = f"https://ipinfo.io/{ip_address}/org"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text.strip()
        else:
            print(
                f"Failed to fetch ISP for IP {ip_address}. Status code: {response.status_code}"
            )
            return None
    except Exception as e:
        print(f"Error fetching ISP for IP {ip_address}: {e}")
        return None
