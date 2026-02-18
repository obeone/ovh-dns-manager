"""
Tests for the main module.

Covers: IP validation, IPv6 detection, connection testing,
delete filtering by record type, and specific exception handling.
"""

import ipaddress
from unittest.mock import MagicMock, patch, call

import ovh.exceptions
import pytest

import main as main_module
from main import (
    _test_ovh_connection,
    create_ovh_client,
    setup_logging,
)


# ========= IP validation ============


class TestIPValidation:
    """Tests for IP address validation used in create_dns_entries."""

    @pytest.mark.parametrize("ip,expected_type", [
        ("1.2.3.4", "A"),
        ("192.168.1.1", "A"),
        ("10.0.0.1", "A"),
        ("255.255.255.255", "A"),
    ])
    def test_valid_ipv4_detected_as_A(self, ip, expected_type):
        ip_obj = ipaddress.ip_address(ip)
        record_type = "AAAA" if isinstance(ip_obj, ipaddress.IPv6Address) else "A"
        assert record_type == expected_type

    @pytest.mark.parametrize("ip,expected_type", [
        ("::1", "AAAA"),
        ("2001:db8::1", "AAAA"),
        ("fe80::1", "AAAA"),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "AAAA"),
    ])
    def test_valid_ipv6_detected_as_AAAA(self, ip, expected_type):
        ip_obj = ipaddress.ip_address(ip)
        record_type = "AAAA" if isinstance(ip_obj, ipaddress.IPv6Address) else "A"
        assert record_type == expected_type

    @pytest.mark.parametrize("ip", [
        "not.an.ip",
        "999.999.999.999",
        "1.2.3",
        "",
        "abc",
        "1.2.3.4.5",
    ])
    def test_invalid_ip_rejected(self, ip):
        with pytest.raises(ValueError):
            ipaddress.ip_address(ip.strip())


# ========= Connection test ============


class TestCreateOvhClient:
    """Tests for OVH client creation and connection testing."""

    @patch("main._test_ovh_connection")
    @patch("ovh.Client")
    def test_successful_connection(self, mock_client_cls, mock_test_conn):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_test_conn.return_value = {"credentialId": 42}

        result = create_ovh_client("ovh-eu", "key", "secret", "consumer")

        assert result is mock_client
        mock_test_conn.assert_called_once_with(mock_client)

    @patch("main._test_ovh_connection")
    @patch("ovh.Client")
    def test_invalid_credentials_exits(self, mock_client_cls, mock_test_conn):
        mock_client_cls.return_value = MagicMock()
        mock_test_conn.side_effect = ovh.exceptions.InvalidCredential("bad creds")

        with pytest.raises(SystemExit) as exc_info:
            create_ovh_client("ovh-eu", "key", "secret", "consumer")

        assert exc_info.value.code == 1

    @patch("main._test_ovh_connection")
    @patch("ovh.Client")
    def test_network_error_exits(self, mock_client_cls, mock_test_conn):
        mock_client_cls.return_value = MagicMock()
        mock_test_conn.side_effect = ovh.exceptions.NetworkError("timeout")

        with pytest.raises(SystemExit) as exc_info:
            create_ovh_client("ovh-eu", "key", "secret", "consumer")

        assert exc_info.value.code == 1


# ========= Delete filtering ============


class TestDeleteFiltering:
    """
    Tests that delete_dns_entries correctly filters by record type.

    This is a regression test for the bug where ALL record types were deleted.
    """

    @patch("main.Confirm.ask", return_value=True)
    @patch("main.Prompt.ask")
    def test_delete_only_a_records(self, mock_prompt, mock_confirm, mock_ovh_client, sample_dns_entries):
        # Setup prompts: subdomains, then record type choice "1" (A only)
        mock_prompt.side_effect = ["www", "1"]

        # Mock API: return all entry IDs, then individual entries
        mock_ovh_client.get.side_effect = [
            [e["id"] for e in sample_dns_entries],  # list all IDs
            sample_dns_entries[0],  # id=1 A www
            sample_dns_entries[1],  # id=2 AAAA www
            sample_dns_entries[2],  # id=3 CNAME mail
            sample_dns_entries[3],  # id=4 TXT www
            sample_dns_entries[4],  # id=5 A api
        ]

        main_module.delete_dns_entries(mock_ovh_client, "example.com")

        # Only the A record for "www" (id=1) should be deleted
        mock_ovh_client.delete.assert_called_once_with(
            "/domain/zone/example.com/record/1"
        )

    @patch("main.Confirm.ask", return_value=True)
    @patch("main.Prompt.ask")
    def test_delete_a_and_aaaa(self, mock_prompt, mock_confirm, mock_ovh_client, sample_dns_entries):
        # Record type choice "3" (A + AAAA)
        mock_prompt.side_effect = ["www", "3"]

        mock_ovh_client.get.side_effect = [
            [e["id"] for e in sample_dns_entries],
            sample_dns_entries[0],  # id=1 A www
            sample_dns_entries[1],  # id=2 AAAA www
            sample_dns_entries[2],  # id=3 CNAME mail
            sample_dns_entries[3],  # id=4 TXT www
            sample_dns_entries[4],  # id=5 A api
        ]

        main_module.delete_dns_entries(mock_ovh_client, "example.com")

        # Both A and AAAA for "www" should be deleted (ids 1 and 2)
        assert mock_ovh_client.delete.call_count == 2
        mock_ovh_client.delete.assert_any_call("/domain/zone/example.com/record/1")
        mock_ovh_client.delete.assert_any_call("/domain/zone/example.com/record/2")

    @patch("main.Confirm.ask", return_value=True)
    @patch("main.Prompt.ask")
    def test_delete_skips_other_types(self, mock_prompt, mock_confirm, mock_ovh_client, sample_dns_entries):
        # Delete only A records for "www"
        mock_prompt.side_effect = ["www", "1"]

        mock_ovh_client.get.side_effect = [
            [e["id"] for e in sample_dns_entries],
            sample_dns_entries[0],
            sample_dns_entries[1],
            sample_dns_entries[2],
            sample_dns_entries[3],
            sample_dns_entries[4],
        ]

        main_module.delete_dns_entries(mock_ovh_client, "example.com")

        # CNAME (id=3) and TXT (id=4) must NOT be deleted
        deleted_paths = [c.args[0] for c in mock_ovh_client.delete.call_args_list]
        assert "/domain/zone/example.com/record/3" not in deleted_paths
        assert "/domain/zone/example.com/record/4" not in deleted_paths


# ========= Setup logging ============


class TestSetupLogging:
    """Tests for logging configuration."""

    def test_default_level(self):
        setup_logging(verbose=False)
        # No crash is sufficient; coloredlogs configures the root logger

    def test_verbose_level(self):
        setup_logging(verbose=True)
        # No crash is sufficient
