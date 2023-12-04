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
    url = "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules"
    headers = {
        "X-Auth-Email": AUTH_EMAIL,
        "X-Auth-Key": AUTH_KEY,
        "Content-Type": "application/json",
    }
    payload = (
        '{"mode":"challenge","configuration":{"target":"ip","value":"'
        + ip_address
        + '"},"notes":"Hour block enforced"}'
    )
    response = requests.post(url, headers=headers, data=payload)
    #update_cf_trans(response.content)
    if response.status_code in [200, 201]:
        update_cf_trans(response.content)


def block_day(ip_address):
    url = "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules"
    headers = {
        "X-Auth-Email": AUTH_EMAIL,
        "X-Auth-Key": AUTH_KEY,
        "Content-Type": "application/json",
    }
    payload = (
        '{"mode":"block","configuration":{"target":"ip","value":"'
        + ip_address
        + '"},"notes":"Day block enforced"}'
    )
    response = requests.post(url, headers=headers, data=payload)
    #update_cf_trans(response.content)
    if response.status_code in [200, 201]:
        update_cf_trans(response.content)


def unblock():
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
            response = requests.request("DELETE", url, headers=headers)
            if response.status_code != 200:
                raise Exception(f"Failed to delete firewall rule: {firewall_rule_id}. Response code: {response.status_code}, Response: {response.text}")
            entity.update({
                'release_timestamp': datetime.datetime.utcnow().isoformat()
            })
            datastore_client.put(entity)
    return True

