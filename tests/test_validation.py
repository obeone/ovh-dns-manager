"""
Tests for the validation module.

Covers: IP validation, record target validation, mask_key,
domain validation, and subdomain validation.

Copyright (c) 2026 Snapp'
Author: Yannis Duvignau (yduvignau@snapp.fr)
"""

import ipaddress
from unittest.mock import patch

import pytest

from ovh_dns_manager.validation import (
    mask_key,
    validate_domain,
    validate_record_target,
    validate_subdomain,
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
    """Tests for validate_record_target."""

    def test_a_record_valid_ipv4(self):
        valid, msg = validate_record_target("A", "1.2.3.4")
        assert valid is True

    def test_a_record_rejects_ipv6(self):
        valid, msg = validate_record_target("A", "::1")
        assert valid is False
        assert "IPv4" in msg

    def test_aaaa_record_valid_ipv6(self):
        valid, msg = validate_record_target("AAAA", "2001:db8::1")
        assert valid is True

    def test_aaaa_record_rejects_ipv4(self):
        valid, msg = validate_record_target("AAAA", "1.2.3.4")
        assert valid is False
        assert "IPv6" in msg

    def test_cname_valid(self):
        valid, msg = validate_record_target("CNAME", "host.example.com.")
        assert valid is True

    def test_cname_missing_trailing_dot(self):
        valid, msg = validate_record_target("CNAME", "host.example.com")
        assert valid is False
        assert "dot" in msg.lower()

    def test_mx_valid(self):
        valid, msg = validate_record_target("MX", "10 mail.example.com.")
        assert valid is True

    def test_mx_missing_priority(self):
        valid, msg = validate_record_target("MX", "mail.example.com.")
        assert valid is False

    def test_mx_invalid_priority(self):
        valid, msg = validate_record_target("MX", "abc mail.example.com.")
        assert valid is False

    def test_srv_valid(self):
        valid, msg = validate_record_target("SRV", "10 60 5060 sip.example.com.")
        assert valid is True

    def test_srv_too_few_parts(self):
        valid, msg = validate_record_target("SRV", "10 60 5060")
        assert valid is False

    def test_txt_any_string(self):
        valid, msg = validate_record_target("TXT", "v=spf1 include:example.com ~all")
        assert valid is True

    def test_empty_target(self):
        valid, msg = validate_record_target("A", "")
        assert valid is False


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
