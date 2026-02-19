"""
Input validation utilities for the OVH DNS Manager.

Provides validation functions for domains, subdomains, DNS record targets,
and a helper to mask sensitive API keys for display purposes.

Copyright (c) 2026 Snapp'
Author: Yannis Duvignau (yduvignau@snapp.fr)
"""

import ipaddress
import logging

from ovh_dns_manager.constants import DOMAIN_REGEX, SUBDOMAIN_REGEX

logger = logging.getLogger(__name__)


def mask_key(key: str) -> str:
    """
    Mask a sensitive key, showing only the last 4 characters.

    Parameters:
        key: The key to mask

    Returns:
        The masked key (e.g. "***abcd")
    """
    if len(key) <= 4:
        return "***"
    return "***" + key[-4:]


def validate_domain(domain: str) -> bool:
    """
    Validate a domain name against RFC 1123.

    Parameters:
        domain: The domain name to validate

    Returns:
        True if the domain is valid
    """
    return bool(DOMAIN_REGEX.match(domain))


def validate_subdomain(subdomain: str) -> bool:
    """
    Validate a subdomain label.

    Parameters:
        subdomain: The subdomain label to validate

    Returns:
        True if the subdomain is valid
    """
    return bool(SUBDOMAIN_REGEX.match(subdomain))


def validate_record_target(record_type: str, target: str) -> tuple[bool, str]:
    """
    Validate the target value based on the record type.

    Parameters:
        record_type: DNS record type (A, AAAA, CNAME, TXT, MX, SRV)
        target: The target value to validate

    Returns:
        Tuple of (is_valid, error_message). error_message is empty if valid.
    """
    if not target.strip():
        return False, "Target cannot be empty"

    target = target.strip()

    if record_type == "A":
        try:
            ip_obj = ipaddress.ip_address(target)
            if not isinstance(ip_obj, ipaddress.IPv4Address):
                return False, "A record requires an IPv4 address, got IPv6"
        except ValueError:
            return False, "Invalid IPv4 address"

    elif record_type == "AAAA":
        try:
            ip_obj = ipaddress.ip_address(target)
            if not isinstance(ip_obj, ipaddress.IPv6Address):
                return False, "AAAA record requires an IPv6 address, got IPv4"
        except ValueError:
            return False, "Invalid IPv6 address"

    elif record_type == "CNAME":
        if not target.endswith("."):
            return False, "CNAME target must be a FQDN ending with a dot (e.g. host.example.com.)"

    elif record_type == "MX":
        parts = target.split(maxsplit=1)
        if len(parts) != 2:
            return False, "MX record must be 'priority target' (e.g. '10 mail.example.com.')"
        try:
            priority = int(parts[0])
            if priority < 0 or priority > 65535:
                return False, "MX priority must be between 0 and 65535"
        except ValueError:
            return False, "MX priority must be a number"

    elif record_type == "SRV":
        parts = target.split()
        if len(parts) != 4:
            return False, "SRV record must be 'priority weight port target' (e.g. '10 60 5060 sip.example.com.')"
        try:
            for name, val in zip(["priority", "weight", "port"], parts[:3]):
                num = int(val)
                if num < 0 or num > 65535:
                    return False, f"SRV {name} must be between 0 and 65535"
        except ValueError:
            return False, "SRV priority, weight and port must be numbers"

    # TXT: no special validation needed, any string is valid

    return True, ""
