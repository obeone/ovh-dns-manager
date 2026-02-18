from pathlib import Path
from unittest.mock import patch

from src.credentials import load_credentials


def test_load_credentials_success(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "OVH_ENDPOINT=ovh-eu\n"
        "OVH_APPLICATION_KEY=key\n"
        "OVH_APPLICATION_SECRET=secret\n"
        "OVH_CONSUMER_KEY=consumer\n"
        "OVH_DOMAIN=example.com\n"
    )

    with patch("src.credentials.ENV_FILE", env_file):
        # We need to mock os.getenv because load_dotenv might not work with
        # tmp_path easily in this context or we can rely on load_dotenv but
        # it affects the process env.
        # Patching os.getenv is safer for unit tests.
        mock_env = {
            "OVH_ENDPOINT": "ovh-eu",
            "OVH_APPLICATION_KEY": "key",
            "OVH_APPLICATION_SECRET": "secret",
            "OVH_CONSUMER_KEY": "consumer",
            "OVH_DOMAIN": "example.com",
        }
        with patch("os.getenv", side_effect=mock_env.get):
            creds = load_credentials()
            assert creds is not None
            assert creds.endpoint == "ovh-eu"
            assert creds.domain == "example.com"


def test_load_credentials_missing_file():
    with patch("src.credentials.ENV_FILE", Path("/non/existent")):
        creds = load_credentials()
        assert creds is None


def test_load_credentials_incomplete(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("OVH_ENDPOINT=ovh-eu\n")

    with (
        patch("src.credentials.ENV_FILE", env_file),
        patch("os.getenv", side_effect={"OVH_ENDPOINT": "ovh-eu"}.get),
    ):
        creds = load_credentials()
        assert creds is None
