"""Fuzzing tests for SSRF protection using Hypothesis."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hypothesis import given, strategies as st, settings
from hypothesis import HealthCheck

from api.v1.domain_verification import is_safe_domain


class TestSSRFProtectionFuzzing:
    """Fuzzing tests for SSRF protection in domain verification."""

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
                "127.1",
                "10.1.1.1",
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
                "pypi.org",
            ]
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_is_safe_domain_allows_public_domains(self, public_domain):
        """Test that is_safe_domain allows legitimate public domains."""
        result = is_safe_domain(public_domain)
        assert result is True, f"Should allow public domain: {public_domain}"

    @given(
        st.from_regex(
            r"^(192\.168\.\d{1,3}\.\d{1,3})|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})$",
            fullmatch=True,
        )
    )
    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=50,
    )
    def test_is_safe_domain_blocks_private_ip_ranges(self, private_ip):
        """Test that is_safe_domain blocks private IP address ranges."""
        result = is_safe_domain(private_ip)
        assert result is False, f"Should block private IP: {private_ip}"

    @given(
        st.text(
            alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
            min_size=1,
            max_size=100,
        )
    )
    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=50,
    )
    def test_is_safe_domain_with_alphanumeric(self, alphanumeric_input):
        """Test is_safe_domain with alphanumeric strings."""
        try:
            result = is_safe_domain(alphanumeric_input)
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"is_safe_domain crashed on alphanumeric: {repr(alphanumeric_input)}"
            ) from e

    @given(
        st.sampled_from(
            [
                "",
                " ",
                ".",
                "..",
                "...",
                "-.com",
                "domain.-com",
                "test..com",
            ]
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_is_safe_domain_rejects_malformed_domains(self, malformed_domain):
        """Test that is_safe_domain handles malformed domains safely."""
        try:
            result = is_safe_domain(malformed_domain)
            assert isinstance(result, bool)
            # Should reject malformed domains (return False)
        except Exception as e:
            raise AssertionError(
                f"is_safe_domain crashed on malformed: {repr(malformed_domain)}"
            ) from e

    @given(
        st.one_of(
            st.integers(),
            st.floats(allow_nan=False, allow_infinity=False),
            st.none(),
        )
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_is_safe_domain_handles_wrong_types(self, wrong_type_input):
        """Test that is_safe_domain handles wrong input types gracefully."""
        try:
            result = is_safe_domain(str(wrong_type_input))
            assert isinstance(result, bool)
        except Exception as e:
            raise AssertionError(
                f"is_safe_domain crashed on type: {type(wrong_type_input)}"
            ) from e
