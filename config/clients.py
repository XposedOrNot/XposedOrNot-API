"""Shared per-process client singletons for Datastore and Redis."""

from google.cloud import datastore
from redis import Redis

from config.settings import REDIS_DB, REDIS_HOST, REDIS_PASSWORD, REDIS_PORT

ds_client = datastore.Client()

redis_client = Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    password=REDIS_PASSWORD,
    decode_responses=True,
)
