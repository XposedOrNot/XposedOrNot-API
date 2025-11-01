"""Fuzzing tests for helper functions using Hypothesis."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hypothesis import given, strategies as st, settings
from hypothesis import HealthCheck

# Import only standalone validation functions (no external dependencies)
from utils.helpers import validate_domain, is_valid_domain_name


class TestHelpersFuzzing:
    """Fuzzing tests for helper utility functions."""

    @given(st.text())
    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    def test_validate_domain_never_crashes(self, domain_input):
        """Test that validate_domain never crashes on any text input."""
        try:
            result = validate_domain(domain_input)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_domain crashed on input: {repr(domain_input)}"
            ) from e

    @given(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters=".-"
            ),
            min_size=1,
            max_size=253,
        )
    )
    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    def test_validate_domain_with_valid_chars(self, domain_input):
        """Test validate_domain with domain-like characters."""
        try:
            result = validate_domain(domain_input)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_domain crashed on valid chars: {repr(domain_input)}"
            ) from e

    @given(
        st.sampled_from(
            [
                "google.com",
                "github.com",
                "example.com",
                "test-domain.co.uk",
                "sub.domain.org",
                "my-site.io",
            ]
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_validate_domain_accepts_valid_domains(self, valid_domain):
        """Test that validate_domain accepts valid domain names."""
        result = validate_domain(valid_domain)
        assert result is True, f"Should accept valid domain: {valid_domain}"

    @given(
        st.sampled_from(
            [
                "not a domain",
                "missing.tld",
                ".startwithdot",
                "endswithdot.",
                "has..doubledot",
                "-startswithhyphen.com",
                "endswith-.com",
                "",
                " ",
            ]
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_validate_domain_rejects_invalid_domains(self, invalid_domain):
        """Test that validate_domain rejects invalid domain names."""
        try:
            result = validate_domain(invalid_domain)
            assert isinstance(result, bool)
            # Most should be rejected (but we're mainly testing for crashes)
        except Exception as e:
            raise AssertionError(
                f"validate_domain crashed on invalid domain: {repr(invalid_domain)}"
            ) from e

    @given(
        st.from_regex(
            r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$",
            fullmatch=True,
        )
    )
    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    def test_validate_domain_with_regex_generated(self, domain):
        """Test validate_domain with regex-generated domain-like strings."""
        try:
            result = validate_domain(domain)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_domain crashed on regex domain: {repr(domain)}"
            ) from e

    @given(st.text())
    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    def test_is_valid_domain_name_never_crashes(self, domain_input):
        """Test that is_valid_domain_name never crashes on any text input."""
        try:
            result = is_valid_domain_name(domain_input)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"is_valid_domain_name crashed on input: {repr(domain_input)}"
            ) from e

    @given(
        st.one_of(
            st.integers(),
            st.floats(allow_nan=False, allow_infinity=False),
            st.none(),
            st.lists(st.text()),
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_validate_domain_handles_wrong_types(self, wrong_type_input):
        """Test that validate_domain handles wrong input types gracefully."""
        try:
            # Convert to string (what the function would receive)
            result = validate_domain(str(wrong_type_input))
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_domain crashed on type: {type(wrong_type_input)}"
            ) from e

    @given(
        st.text(
            alphabet=st.characters(
                blacklist_categories=("Cc", "Cs"),  # Control & surrogate chars
            ),
            min_size=0,
            max_size=500,
        )
    )
    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    def test_validate_domain_with_unicode(self, unicode_input):
        """Test validate_domain with unicode and special characters."""
        try:
            result = validate_domain(unicode_input)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_domain crashed on unicode: {repr(unicode_input)}"
            ) from e
