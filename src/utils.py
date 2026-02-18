"""
Utility functions for OVH DNS Manager.
"""

import ipaddress
import re


def validate_ip(ip: str) -> bool:
    """
    Validate an IP address (IPv4 or IPv6).

    Parameters:
        ip: The IP address string to validate

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """
    Validate a domain name format.

    Parameters:
        domain: The domain name string to validate

    Returns:
        bool: True if valid, False otherwise
    """
    # Simple domain regex
    pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$"
    return bool(re.match(pattern, domain))


def validate_subdomain(subdomain: str) -> bool:
    """
    Validate a subdomain label.

    Parameters:
        subdomain: The subdomain label string to validate

    Returns:
        bool: True if valid, False otherwise
    """
    if not subdomain or subdomain == "@":
        return True
    # Subdomain label regex (RFC 1035)
    pattern = r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    return bool(re.match(pattern, subdomain))
