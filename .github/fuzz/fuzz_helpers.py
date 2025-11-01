#!/usr/bin/env python3
"""Atheris fuzz targets for helper functions."""

import sys
import os
import atheris

# Add project root to path
project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, project_root)

from utils.helpers import (
    validate_domain,
    is_valid_domain_name,
    is_valid_ip,
    get_preferred_ip_address,
    generate_request_hash,
    string_to_boolean,
)


@atheris.instrument_func
def TestValidateDomain(data):
    """Fuzz test for validate_domain function."""
    fdp = atheris.FuzzedDataProvider(data)
    domain = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 253))

    try:
        result = validate_domain(domain)
        assert isinstance(result, bool), "validate_domain must return a boolean"
    except Exception as e:
        if not isinstance(e, AssertionError):
            raise


@atheris.instrument_func
def TestIsValidDomainName(data):
    """Fuzz test for is_valid_domain_name function."""
    fdp = atheris.FuzzedDataProvider(data)
    domain = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 253))

    try:
        result = is_valid_domain_name(domain)
        assert isinstance(result, bool), "is_valid_domain_name must return a boolean"
    except Exception as e:
        if not isinstance(e, AssertionError):
            raise


@atheris.instrument_func
def TestIsValidIP(data):
    """Fuzz test for is_valid_ip function."""
    fdp = atheris.FuzzedDataProvider(data)
    ip_address = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 45))

    try:
        result = is_valid_ip(ip_address)
        assert isinstance(result, bool), "is_valid_ip must return a boolean"
    except Exception as e:
        if not isinstance(e, AssertionError):
            raise


@atheris.instrument_func
def TestGetPreferredIPAddress(data):
    """Fuzz test for get_preferred_ip_address function."""
    fdp = atheris.FuzzedDataProvider(data)
    x_forwarded_for = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))

    try:
        result = get_preferred_ip_address(x_forwarded_for)
        assert result is None or isinstance(
            result, str
        ), "get_preferred_ip_address must return None or str"
    except Exception as e:
        if not isinstance(e, AssertionError):
            raise


@atheris.instrument_func
def TestGenerateRequestHash(data):
    """Fuzz test for generate_request_hash function."""
    fdp = atheris.FuzzedDataProvider(data)

    # Generate a random dictionary
    dict_size = fdp.ConsumeIntInRange(0, 10)
    test_dict = {}
    for _ in range(dict_size):
        key = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
        value = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))
        test_dict[key] = value

    try:
        result = generate_request_hash(test_dict)
        assert isinstance(result, str), "generate_request_hash must return a string"
        assert len(result) == 64, "SHA256 hash should be 64 characters"
    except Exception as e:
        if not isinstance(e, AssertionError):
            raise


@atheris.instrument_func
def TestStringToBoolean(data):
    """Fuzz test for string_to_boolean function."""
    fdp = atheris.FuzzedDataProvider(data)
    value = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 50))

    try:
        result = string_to_boolean(value)
        assert isinstance(result, bool), "string_to_boolean must return a boolean"
    except Exception as e:
        if not isinstance(e, AssertionError):
            raise


def main():
    """Main fuzzing entry point."""
    atheris.Setup(sys.argv, TestValidateDomain)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
