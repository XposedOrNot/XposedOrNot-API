"""Fuzzing tests for domain validation using Hypothesis."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hypothesis import given, strategies as st, assume, settings
from hypothesis import HealthCheck

from utils.helpers import validate_domain
from api.v1.domain_verification import is_safe_domain


class TestDomainValidationFuzzing:
    """Fuzzing tests for domain validation functions."""

    @given(st.text())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
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
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
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
        st.from_regex(
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            fullmatch=True,
        )
    )
    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    def test_validate_domain_with_valid_format(self, domain):
        """Test that properly formatted domains are handled correctly."""
        assume(len(domain) >= 3)
        assume("." in domain)

        try:
            result = validate_domain(domain)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_domain crashed on valid format: {repr(domain)}"
            ) from e

    @given(st.text())
    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=50,
    )
    def test_is_safe_domain_never_crashes(self, domain_input):
        """Test that is_safe_domain never crashes on any text input."""
        try:
            result = is_safe_domain(domain_input)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"is_safe_domain crashed on input: {repr(domain_input)}"
            ) from e

    @given(
        st.sampled_from(
            [
                "localhost",
                "127.0.0.1",
                "192.168.1.1",
                "10.0.0.1",
                "172.16.0.1",
                "169.254.169.254",
                "::1",
                "0.0.0.0",
            ]
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_is_safe_domain_blocks_private_ips(self, dangerous_domain):
        """Test that is_safe_domain blocks known dangerous domains/IPs."""
        result = is_safe_domain(dangerous_domain)
        assert result is False, f"Should block dangerous domain: {dangerous_domain}"

    @given(
        st.sampled_from(
            [
                "google.com",
                "github.com",
                "example.com",
                "cloudflare.com",
            ]
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_is_safe_domain_allows_public_domains(self, public_domain):
        """Test that is_safe_domain allows legitimate public domains."""
        result = is_safe_domain(public_domain)
        assert result is True, f"Should allow public domain: {public_domain}"

    @given(
        st.one_of(
            st.text(min_size=1, max_size=10),
            st.integers(),
            st.floats(allow_nan=False, allow_infinity=False),
            st.none(),
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_validate_domain_type_safety(self, invalid_input):
        """Test that validate_domain handles various input types safely."""
        try:
            result = validate_domain(str(invalid_input))
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"validate_domain crashed on type: {type(invalid_input)}"
            ) from e
