"""Fuzzing tests for validation utilities using Hypothesis."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hypothesis import given, strategies as st, settings
from hypothesis import HealthCheck

from utils.validation import validate_email_with_tld, validate_variables


class TestValidationFuzzing:
    """Fuzzing tests for validation utility functions."""

    @given(st.text())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_validate_email_never_crashes(self, email_input):
        """Test that validate_email_with_tld never crashes on any text input."""
        try:
            result = validate_email_with_tld(email_input)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_email_with_tld crashed on input: {repr(email_input)}"
            ) from e

    @given(st.emails())
    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    def test_validate_email_with_valid_emails(self, email):
        """Test validate_email_with_tld with valid email format."""
        try:
            result = validate_email_with_tld(email)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_email_with_tld crashed on valid email: {repr(email)}"
            ) from e

    @given(st.lists(st.text(), min_size=0, max_size=10))
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_validate_variables_never_crashes(self, variables):
        """Test that validate_variables never crashes on any list input."""
        try:
            result = validate_variables(variables)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_variables crashed on input: {repr(variables)}"
            ) from e

    @given(
        st.lists(
            st.one_of(
                st.text(),
                st.integers(),
                st.floats(allow_nan=False, allow_infinity=False),
                st.none(),
            ),
            min_size=1,
            max_size=5,
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_validate_variables_mixed_types(self, variables):
        """Test validate_variables with mixed input types."""
        try:
            result = validate_variables(variables)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_variables crashed on mixed types: {repr(variables)}"
            ) from e

    @given(
        st.text(
            alphabet=st.characters(blacklist_characters=["\x00", "\n", "\r", "\t"]),
            min_size=0,
            max_size=100,
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_validate_variables_single_string(self, text_input):
        """Test validate_variables with single string input in list."""
        try:
            result = validate_variables([text_input])
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_variables crashed on text: {repr(text_input)}"
            ) from e

    @given(
        st.sampled_from(
            [
                "user@example.com",
                "test.user@domain.co.uk",
                "admin+tag@company.org",
                "simple@test.io",
            ]
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_validate_email_common_valid_formats(self, email):
        """Test that common valid email formats are handled correctly."""
        try:
            result = validate_email_with_tld(email)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_email_with_tld crashed on common format: {repr(email)}"
            ) from e

    @given(
        st.sampled_from(
            [
                "notanemail",
                "missing@tld",
                "@nodomain.com",
                "spaces in@email.com",
                "double@@domain.com",
            ]
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_validate_email_invalid_formats(self, invalid_email):
        """Test that invalid email formats are rejected."""
        try:
            result = validate_email_with_tld(invalid_email)
            assert isinstance(result, bool)
            assert result is False, f"Should reject invalid email: {invalid_email}"
        except Exception as e:
            raise AssertionError(
                f"validate_email_with_tld crashed on invalid email: {repr(invalid_email)}"
            ) from e
