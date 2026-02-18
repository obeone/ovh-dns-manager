"""
Tests for the credentials module.

Covers: load/save, domain/subdomain validation, key masking,
OvhCredentials NamedTuple, and the fallthrough bug fix.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from credentials import (
    OvhCredentials,
    load_credentials,
    mask_key,
    validate_domain,
    validate_subdomain,
)


# ========= mask_key ============


class TestMaskKey:
    """Tests for the mask_key helper."""

    def test_long_key(self):
        assert mask_key("abcdefgh1234") == "***1234"

    def test_exactly_five_chars(self):
        assert mask_key("abcde") == "***bcde"

    def test_four_chars(self):
        assert mask_key("abcd") == "***"

    def test_short_key(self):
        assert mask_key("ab") == "***"

    def test_empty_key(self):
        assert mask_key("") == "***"


# ========= validate_domain ============


class TestValidateDomain:
    """Tests for domain validation."""

    @pytest.mark.parametrize("domain", [
        "example.com",
        "sub.example.com",
        "my-domain.co.uk",
        "a.io",
        "test-123.example.org",
    ])
    def test_valid_domains(self, domain):
        assert validate_domain(domain) is True

    @pytest.mark.parametrize("domain", [
        "",
        "localhost",
        "-bad.com",
        "bad-.com",
        "no spaces.com",
        ".leading-dot.com",
        "a" * 64 + ".com",  # label too long
    ])
    def test_invalid_domains(self, domain):
        assert validate_domain(domain) is False


# ========= validate_subdomain ============


class TestValidateSubdomain:
    """Tests for subdomain validation."""

    @pytest.mark.parametrize("subdomain", [
        "www",
        "api",
        "my-app",
        "sub.domain",
        "a",
        "test-123",
    ])
    def test_valid_subdomains(self, subdomain):
        assert validate_subdomain(subdomain) is True

    @pytest.mark.parametrize("subdomain", [
        "",
        "-invalid",
        "invalid-",
        "has space",
        "a" * 64,  # label too long
    ])
    def test_invalid_subdomains(self, subdomain):
        assert validate_subdomain(subdomain) is False


# ========= OvhCredentials ============


class TestOvhCredentials:
    """Tests for the OvhCredentials NamedTuple."""

    def test_creation(self):
        creds = OvhCredentials(
            endpoint="ovh-eu",
            application_key="key123",
            application_secret="secret",
            consumer_key="consumer",
            domain="example.com",
        )
        assert creds.endpoint == "ovh-eu"
        assert creds.domain == "example.com"

    def test_unpacking(self):
        creds = OvhCredentials("ovh-eu", "key", "secret", "consumer", "example.com")
        endpoint, app_key, app_secret, cons_key, domain = creds
        assert endpoint == "ovh-eu"
        assert domain == "example.com"


# ========= load_credentials ============


class TestLoadCredentials:
    """Tests for loading credentials from .env file."""

    def test_load_valid_env(self, tmp_env_file):
        with patch("credentials.ENV_FILE", tmp_env_file):
            creds = load_credentials()

        assert creds is not None
        assert isinstance(creds, OvhCredentials)
        assert creds.endpoint == "ovh-eu"
        assert creds.application_key == "test_app_key_1234"
        assert creds.domain == "example.com"

    def test_load_missing_file(self, tmp_path):
        missing = tmp_path / "nonexistent.env"
        with patch("credentials.ENV_FILE", missing):
            assert load_credentials() is None

    def test_load_incomplete_env(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("OVH_ENDPOINT=ovh-eu\n")  # Missing other fields
        with patch("credentials.ENV_FILE", env_file):
            assert load_credentials() is None

    def test_load_empty_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("")
        with patch("credentials.ENV_FILE", env_file):
            assert load_credentials() is None

    def test_load_with_comments(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# This is a comment\n"
            "OVH_ENDPOINT=ovh-eu\n"
            "OVH_APPLICATION_KEY=key\n"
            "OVH_APPLICATION_SECRET=secret\n"
            "OVH_CONSUMER_KEY=consumer\n"
            "# Another comment\n"
            "OVH_DOMAIN=example.com\n"
        )
        with patch("credentials.ENV_FILE", env_file):
            creds = load_credentials()
        assert creds is not None
        assert creds.endpoint == "ovh-eu"


# ========= Fallthrough bug fix ============


class TestCredentialsFallthrough:
    """
    Test that save failure in choice '1' correctly falls through to manual entry.

    This is a regression test for the bug where the code used 'if choice == "2"'
    instead of 'elif', causing the fallthrough to be skipped.
    """

    @patch("credentials.Prompt.ask")
    @patch("credentials.save_credentials", return_value=False)
    @patch("credentials.load_credentials", return_value=None)
    def test_fallthrough_after_save_failure(
        self, mock_load, mock_save, mock_prompt
    ):
        # First call: user chooses "1" (save)
        # Subsequent calls: manual entry prompts
        mock_prompt.side_effect = [
            "1",        # Choice: save
            "ovh-eu",   # Endpoint
            "mykey",    # Application Key
            "secret",   # Application Secret
            "consumer", # Consumer Key
            "test.com", # Domain
        ]

        with patch("credentials.Confirm"):
            from credentials import get_credentials_interactive
            creds = get_credentials_interactive()

        assert creds is not None
        assert creds.endpoint == "ovh-eu"
        assert creds.domain == "test.com"
