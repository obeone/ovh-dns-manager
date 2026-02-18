from unittest.mock import MagicMock

from src.main import delete_dns_entries


def test_delete_dns_entries_optimized(mocker):
    # Mock client
    mock_client = MagicMock()
    mock_client.get.side_effect = [
        ["123"],  # first get ids for sub1
        {"id": 123, "fieldType": "A", "target": "1.1.1.1"},  # get detail for 123
        [],  # get ids for sub2 (empty)
    ]

    # Mock UI components to avoid hanging or outputting too much
    mocker.patch("src.main.Prompt.ask", return_value="sub1, sub2")
    mocker.patch(
        "src.main.Confirm.ask", side_effect=[True, False]
    )  # confirm proceed, then don't refresh
    mocker.patch("src.main.Progress", MagicMock())

    delete_dns_entries(mock_client, "example.com")

    # Verify that client.get was called with subDomain filter
    # Calls should be:
    # 1. get(f"/domain/zone/example.com/record", subDomain="sub1")
    # 2. get(f"/domain/zone/example.com/record/123")
    # 3. get(f"/domain/zone/example.com/record", subDomain="sub2")

    calls = mock_client.get.call_args_list
    assert any(
        c.args[0].endswith("/record") and c.kwargs.get("subDomain") == "sub1"
        for c in calls
    )
    assert any(
        c.args[0].endswith("/record") and c.kwargs.get("subDomain") == "sub2"
        for c in calls
    )
    mock_client.delete.assert_called_once_with("/domain/zone/example.com/record/123")
