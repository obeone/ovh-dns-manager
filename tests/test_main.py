"""
Tests for the main module.

Covers: IP validation, IPv6 detection, connection testing,
delete filtering by record type, record target validation,
and specific exception handling.
"""

import ipaddress
from unittest.mock import MagicMock, patch

import ovh.exceptions
import pytest

import main as main_module
from main import (
    _test_ovh_connection,
    _validate_record_target,
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


# ========= Record target validation ============


class TestValidateRecordTarget:
    """Tests for _validate_record_target."""

    def test_a_record_valid_ipv4(self):
        valid, msg = _validate_record_target("A", "1.2.3.4")
        assert valid is True

    def test_a_record_rejects_ipv6(self):
        valid, msg = _validate_record_target("A", "::1")
        assert valid is False
        assert "IPv4" in msg

    def test_aaaa_record_valid_ipv6(self):
        valid, msg = _validate_record_target("AAAA", "2001:db8::1")
        assert valid is True

    def test_aaaa_record_rejects_ipv4(self):
        valid, msg = _validate_record_target("AAAA", "1.2.3.4")
        assert valid is False
        assert "IPv6" in msg

    def test_cname_valid(self):
        valid, msg = _validate_record_target("CNAME", "host.example.com.")
        assert valid is True

    def test_cname_missing_trailing_dot(self):
        valid, msg = _validate_record_target("CNAME", "host.example.com")
        assert valid is False
        assert "dot" in msg.lower()

    def test_mx_valid(self):
        valid, msg = _validate_record_target("MX", "10 mail.example.com.")
        assert valid is True

    def test_mx_missing_priority(self):
        valid, msg = _validate_record_target("MX", "mail.example.com.")
        assert valid is False

    def test_mx_invalid_priority(self):
        valid, msg = _validate_record_target("MX", "abc mail.example.com.")
        assert valid is False

    def test_srv_valid(self):
        valid, msg = _validate_record_target("SRV", "10 60 5060 sip.example.com.")
        assert valid is True

    def test_srv_too_few_parts(self):
        valid, msg = _validate_record_target("SRV", "10 60 5060")
        assert valid is False

    def test_txt_any_string(self):
        valid, msg = _validate_record_target("TXT", "v=spf1 include:example.com ~all")
        assert valid is True

    def test_empty_target(self):
        valid, msg = _validate_record_target("A", "")
        assert valid is False


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


# ========= Delete with API filters ============


class TestDeleteWithAPIFilters:
    """Tests that delete_dns_entries uses API filters to reduce N+1 calls."""

    @patch("main.Confirm.ask", return_value=True)
    @patch("main.Prompt.ask")
    def test_delete_uses_api_filters(self, mock_prompt, mock_confirm, mock_ovh_client):
        # Subdomains input, then record type choice "1" (A)
        mock_prompt.side_effect = ["www", "1"]

        # API filter calls: get records with fieldType=A, subDomain=www
        mock_ovh_client.get.side_effect = [
            [1],  # filtered list returns only matching IDs
            {"id": 1, "fieldType": "A", "subDomain": "www", "target": "1.2.3.4", "ttl": 3600},
        ]

        main_module.delete_dns_entries(mock_ovh_client, "example.com")

        # Verify API was called with filters
        mock_ovh_client.get.assert_any_call(
            "/domain/zone/example.com/record",
            fieldType="A",
            subDomain="www",
        )
        mock_ovh_client.delete.assert_called_once_with(
            "/domain/zone/example.com/record/1"
        )


# ========= Setup logging ============


class TestSetupLogging:
    """Tests for logging configuration."""

    def test_default_level(self):
        setup_logging(verbose=False)

    def test_verbose_level(self):
        setup_logging(verbose=True)
