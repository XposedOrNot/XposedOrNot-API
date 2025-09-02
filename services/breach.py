"""Breach-related service functions."""

# Standard library imports
from typing import Dict, List, Any

# Third-party imports
from google.cloud import datastore
from google.api_core import exceptions as api_exceptions
from fastapi import HTTPException

# Initialize datastore client
ds_client = datastore.Client()


async def get_combined_breach_data(email: str) -> Dict[str, Any]:
    """Get combined breach data for a given email."""
    try:
        client = datastore.Client()
        key = client.key("xon", email)
        entity = client.get(key)

        if not entity:
            return {}

        # Get breach data
        breach_data = {
            "site": entity.get("site", ""),
            "breach_date": entity.get("breach_date", ""),
            "xposed_data": entity.get("xposed_data", ""),
            "xposed_records": entity.get("xposed_records", 0),
            "xposure_desc": entity.get("xposure_desc", ""),
            "password_risk": entity.get("password_risk", ""),
            "searchable": entity.get("searchable", ""),
            "sensitive": entity.get("sensitive", ""),
            "verified": entity.get("verified", ""),
            "references": entity.get("references", ""),
            "domain": entity.get("domain", ""),
            "industry": entity.get("industry", ""),
            "logo": entity.get("logo", ""),
        }

        # Get sensitive data from xon_sensitive table
        sensitive_key = client.key("xon_sensitive", email)
        sensitive_entity = client.get(sensitive_key)

        if sensitive_entity:
            sensitive_data = {
                "site": sensitive_entity.get("site", ""),
                "breach_date": sensitive_entity.get("breach_date", ""),
                "xposed_data": sensitive_entity.get("xposed_data", ""),
                "xposed_records": sensitive_entity.get("xposed_records", 0),
                "xposure_desc": sensitive_entity.get("xposure_desc", ""),
                "password_risk": sensitive_entity.get("password_risk", ""),
                "searchable": sensitive_entity.get("searchable", ""),
                "sensitive": sensitive_entity.get("sensitive", ""),
                "verified": sensitive_entity.get("verified", ""),
                "references": sensitive_entity.get("references", ""),
                "domain": sensitive_entity.get("domain", ""),
                "industry": sensitive_entity.get("industry", ""),
                "logo": sensitive_entity.get("logo", ""),
            }
            breach_data.update(sensitive_data)

        return breach_data

    except api_exceptions.NotFound as e:
        raise HTTPException(status_code=404, detail="Entity not found") from e
    except api_exceptions.GoogleAPIError as e:
        raise HTTPException(status_code=500, detail="Datastore error") from e
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=400, detail="Invalid input") from e
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error") from e


async def get_exposure(user_email: str) -> Dict[str, Any]:
    """Returns breach data for a given email."""

    try:
        datastore_client = datastore.Client()
        search_key = datastore_client.key("xon", user_email)

        user_data = datastore_client.get(search_key)
        if user_data is not None:
            return dict(user_data)

        return {}
    except api_exceptions.GoogleAPIError:
        return {}
    except (ValueError, TypeError):
        return {}
    except Exception as e:
        raise


async def get_sensitive_exposure(user_email: str) -> Dict[str, Any]:
    """Get sensitive exposure data for a user."""
    try:
        datastore_client = datastore.Client()
        search_key = datastore_client.key("xon_sensitive", user_email)
        user_data = datastore_client.get(search_key)
        if user_data is not None:
            return dict(user_data)

        return {}
    except api_exceptions.GoogleAPIError:
        return {}
    except (ValueError, TypeError):
        return {}
    except Exception as e:
        raise


def get_breaches(breaches: str) -> Dict[str, List[Dict[str, Any]]]:
    """Returns the exposed breaches with details including records, domain, industry,
    and other metadata."""
    breaches_output = {"breaches_details": []}
    breach_list = breaches.split(";")

    for breach in breach_list:
        try:
            key = ds_client.key("xon_breaches", breach)
            query_result = ds_client.get(key)

            if query_result is not None:
                xposed_records = query_result.get("xposed_records", 0)
                breach_details = {
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
                }
                breaches_output["breaches_details"].append(breach_details)
            else:
                raise HTTPException(status_code=404, detail="Breach not found")

        except api_exceptions.NotFound as e:
            raise HTTPException(status_code=404, detail="Breach not found") from e
        except api_exceptions.GoogleAPIError as e:
            raise HTTPException(status_code=500, detail="Datastore error") from e

    return breaches_output
