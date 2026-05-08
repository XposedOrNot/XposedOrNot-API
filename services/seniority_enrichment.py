"""Trigger seniority enrichment for a domain via the internal enrichment service."""

import logging

import httpx

from config.settings import SENIORITY_ENRICH_SECRET, SENIORITY_ENRICH_URL

logger = logging.getLogger(__name__)


def enrich_domain_seniority(domain: str) -> None:
    """Fire-and-forget call to the internal seniority enrichment endpoint.

    No-op when the env vars are not configured (e.g. open-source deployments).
    Failures are logged and swallowed so they never break the verification flow.
    """
    if not SENIORITY_ENRICH_URL or not SENIORITY_ENRICH_SECRET:
        return

    try:
        with httpx.Client(timeout=60) as client:
            client.post(
                f"{SENIORITY_ENRICH_URL.rstrip('/')}/v1/domain-seniority/enrich-domain",
                headers={
                    "Content-Type": "application/json",
                    "X-Internal-Secret": SENIORITY_ENRICH_SECRET,
                },
                json={"domain": domain},
            )
    except Exception as err:  # pylint: disable=broad-except
        logger.warning("Seniority enrichment failed for %s: %s", domain, err)
