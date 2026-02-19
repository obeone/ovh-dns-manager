"""
Tests for the client module.

Covers: OVH client creation, connection testing, and error handling.

Copyright (c) 2026 Snapp'
Author: Yannis Duvignau (yduvignau@snapp.fr)
"""

from unittest.mock import MagicMock, patch

import ovh.exceptions
import pytest

from ovh_dns_manager.client import (
    _test_ovh_connection,
    create_ovh_client,
)


class TestCreateOvhClient:
    """Tests for OVH client creation and connection testing."""

    @patch("ovh_dns_manager.client._test_ovh_connection")
    @patch("ovh.Client")
    def test_successful_connection(self, mock_client_cls, mock_test_conn):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_test_conn.return_value = {"credentialId": 42}

        result = create_ovh_client("ovh-eu", "key", "secret", "consumer")

        assert result is mock_client
        mock_test_conn.assert_called_once_with(mock_client)

    @patch("ovh_dns_manager.client._test_ovh_connection")
    @patch("ovh.Client")
    def test_invalid_credentials_exits(self, mock_client_cls, mock_test_conn):
        mock_client_cls.return_value = MagicMock()
        mock_test_conn.side_effect = ovh.exceptions.InvalidCredential("bad creds")

        with pytest.raises(SystemExit) as exc_info:
            create_ovh_client("ovh-eu", "key", "secret", "consumer")

        assert exc_info.value.code == 1

    @patch("ovh_dns_manager.client._test_ovh_connection")
    @patch("ovh.Client")
    def test_network_error_exits(self, mock_client_cls, mock_test_conn):
        mock_client_cls.return_value = MagicMock()
        mock_test_conn.side_effect = ovh.exceptions.NetworkError("timeout")

        with pytest.raises(SystemExit) as exc_info:
            create_ovh_client("ovh-eu", "key", "secret", "consumer")

        assert exc_info.value.code == 1
