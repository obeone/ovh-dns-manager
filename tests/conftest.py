"""
Shared pytest fixtures for OVH DNS Manager tests.
"""

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_ovh_client():
    """
    Create a mock OVH API client with common method stubs.

    Returns:
        MagicMock: A mock object mimicking ovh.Client
    """
    client = MagicMock()
    client.get.return_value = {"credentialId": 12345}
    client.post.return_value = {"id": 1}
    client.delete.return_value = None
    return client


@pytest.fixture
def sample_dns_entries():
    """
    Sample DNS entry data for testing list and delete operations.

    Returns:
        list[dict]: List of DNS record dictionaries
    """
    return [
        {"id": 1, "fieldType": "A", "subDomain": "www", "target": "1.2.3.4", "ttl": 3600},
        {"id": 2, "fieldType": "AAAA", "subDomain": "www", "target": "::1", "ttl": 3600},
        {"id": 3, "fieldType": "CNAME", "subDomain": "mail", "target": "mail.example.com.", "ttl": 3600},
        {"id": 4, "fieldType": "TXT", "subDomain": "www", "target": "v=spf1 ...", "ttl": 3600},
        {"id": 5, "fieldType": "A", "subDomain": "api", "target": "5.6.7.8", "ttl": 600},
    ]


@pytest.fixture
def tmp_env_file(tmp_path):
    """
    Create a temporary .env file with valid credentials.

    Parameters:
        tmp_path: pytest tmp_path fixture

    Returns:
        Path: Path to the temporary .env file
    """
    env_file = tmp_path / ".env"
    env_file.write_text(
        "OVH_ENDPOINT=ovh-eu\n"
        "OVH_APPLICATION_KEY=test_app_key_1234\n"
        "OVH_APPLICATION_SECRET=test_secret\n"
        "OVH_CONSUMER_KEY=test_consumer_key\n"
        "OVH_DOMAIN=example.com\n"
    )
    return env_file
