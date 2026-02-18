"""
Tests for the credentials module.

Covers: load/save, OvhCredentials NamedTuple, and the fallthrough bug fix.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from ovh_dns_manager.credentials import (
    OvhCredentials,
    load_credentials,
)


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
        with patch("ovh_dns_manager.credentials.ENV_FILE", tmp_env_file):
            creds = load_credentials()

        assert creds is not None
        assert isinstance(creds, OvhCredentials)
        assert creds.endpoint == "ovh-eu"
        assert creds.application_key == "test_app_key_1234"
        assert creds.domain == "example.com"

    def test_load_missing_file(self, tmp_path):
        missing = tmp_path / "nonexistent.env"
        with patch("ovh_dns_manager.credentials.ENV_FILE", missing):
            assert load_credentials() is None

    def test_load_incomplete_env(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("OVH_ENDPOINT=ovh-eu\n")  # Missing other fields
        with patch("ovh_dns_manager.credentials.ENV_FILE", env_file):
            assert load_credentials() is None

    def test_load_empty_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("")
        with patch("ovh_dns_manager.credentials.ENV_FILE", env_file):
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
        with patch("ovh_dns_manager.credentials.ENV_FILE", env_file):
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

    @patch("ovh_dns_manager.credentials.Prompt.ask")
    @patch("ovh_dns_manager.credentials.save_credentials", return_value=False)
    @patch("ovh_dns_manager.credentials.load_credentials", return_value=None)
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

        with patch("ovh_dns_manager.credentials.Confirm"):
            from ovh_dns_manager.credentials import get_credentials_interactive
            creds = get_credentials_interactive()

        assert creds is not None
        assert creds.endpoint == "ovh-eu"
        assert creds.domain == "test.com"
