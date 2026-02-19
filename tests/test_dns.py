"""
Tests for the dns module.

Covers: delete filtering by record type using API filters.
"""

from unittest.mock import patch

import ovh_dns_manager.dns as dns_module


class TestDeleteWithAPIFilters:
    """Tests that delete_dns_entries uses API filters to reduce N+1 calls."""

    @patch("ovh_dns_manager.dns.Confirm.ask", return_value=True)
    @patch("ovh_dns_manager.dns.Prompt.ask")
    def test_delete_uses_api_filters(self, mock_prompt, mock_confirm, mock_ovh_client):
        # Subdomains input, then record type choice "1" (A)
        mock_prompt.side_effect = ["www", "1"]

        # API filter calls: get records with fieldType=A, subDomain=www
        mock_ovh_client.get.side_effect = [
            [1],  # filtered list returns only matching IDs
            {"id": 1, "fieldType": "A", "subDomain": "www", "target": "1.2.3.4", "ttl": 3600},
        ]

        dns_module.delete_dns_entries(mock_ovh_client, "example.com")

        # Verify API was called with filters
        mock_ovh_client.get.assert_any_call(
            "/domain/zone/example.com/record",
            fieldType="A",
            subDomain="www",
        )
        mock_ovh_client.delete.assert_called_once_with(
            "/domain/zone/example.com/record/1"
        )
