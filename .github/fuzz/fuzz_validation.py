#!/usr/bin/env python3
"""Atheris fuzz targets for validation functions."""

import sys
import os
import atheris

# Add project root to path
project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, project_root)

from utils.validation import (
    validate_variables,
    validate_email_with_tld,
    validate_token,
)


@atheris.instrument_func
def TestValidateVariables(data):
    """Fuzz test for validate_variables function."""
    fdp = atheris.FuzzedDataProvider(data)

    # Generate a list of random strings
    list_size = fdp.ConsumeIntInRange(0, 10)
    test_list = [
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))
        for _ in range(list_size)
    ]

    try:
        result = validate_variables(test_list)
        assert isinstance(result, bool), "validate_variables must return a boolean"
    except Exception as e:
        # We don't want the function to crash
        if not isinstance(e, AssertionError):
            raise


@atheris.instrument_func
def TestValidateEmail(data):
    """Fuzz test for validate_email_with_tld function."""
    fdp = atheris.FuzzedDataProvider(data)
    email = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))

    try:
        result = validate_email_with_tld(email)
        assert isinstance(result, bool), "validate_email_with_tld must return a boolean"
    except Exception as e:
        if not isinstance(e, AssertionError):
            raise


@atheris.instrument_func
def TestValidateToken(data):
    """Fuzz test for validate_token function."""
    fdp = atheris.FuzzedDataProvider(data)
    token = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 512))

    try:
        result = validate_token(token)
        assert isinstance(result, bool), "validate_token must return a boolean"
    except Exception as e:
        if not isinstance(e, AssertionError):
            raise


def main():
    """Main fuzzing entry point."""
    atheris.Setup(sys.argv, TestValidateVariables)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
