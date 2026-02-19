"""
OVH API client creation and connection management.

Provides factory functions to create an authenticated OVH API client
with retry logic on transient network errors.

Copyright (c) 2026 Snapp'
Author: Yannis Duvignau (yduvignau@snapp.fr)
"""

import logging
import sys

import ovh
import ovh.exceptions
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

logger = logging.getLogger(__name__)

console = Console()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((
        ovh.exceptions.NetworkError,
        ConnectionError,
    )),
    reraise=True,
)
def _test_ovh_connection(client: ovh.Client) -> dict:
    """
    Test OVH API connectivity by fetching current credentials.

    Retries up to 3 times with exponential backoff on network errors.

    Parameters:
        client: OVH API client instance

    Returns:
        API response dict from /auth/currentCredential

    Raises:
        ovh.exceptions.NetworkError: On persistent network failures
        ovh.exceptions.InvalidCredential: On invalid API credentials
    """
    return client.get("/auth/currentCredential")


def create_ovh_client(
    endpoint: str,
    application_key: str,
    application_secret: str,
    consumer_key: str,
) -> ovh.Client:
    """
    Create and test OVH API client with retry logic.

    Parameters:
        endpoint: OVH API endpoint
        application_key: Application key
        application_secret: Application secret
        consumer_key: Consumer key

    Returns:
        Configured and tested OVH client
    """
    try:
        client = ovh.Client(
            endpoint=endpoint,
            application_key=application_key,
            application_secret=application_secret,
            consumer_key=consumer_key,
        )
        logger.debug("OVH client instantiated for endpoint %s", endpoint)

        # Actually test the connection by calling the API
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            progress.add_task(description="Connecting to OVH API...", total=None)
            result = _test_ovh_connection(client)

        console.print("[bold green]✓[/bold green] Successfully connected to OVH API\n")
        logger.info(
            "Connected to OVH API (credential ID: %s)",
            result.get("credentialId", "unknown"),
        )
        return client

    except ovh.exceptions.InvalidCredential as e:
        console.print(f"[bold red]✗[/bold red] Invalid API credentials: {e}")
        logger.critical("Invalid OVH credentials: %s", e)
        sys.exit(1)
    except ovh.exceptions.NetworkError as e:
        console.print(f"[bold red]✗[/bold red] Network error connecting to OVH API: {e}")
        logger.critical("Network error after retries: %s", e, exc_info=True)
        sys.exit(1)
    except ovh.exceptions.APIError as e:
        console.print(f"[bold red]✗[/bold red] OVH API error: {e}")
        logger.critical("OVH API error: %s", e, exc_info=True)
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to connect to OVH API: {e}")
        logger.critical("Unexpected error connecting to OVH: %s", e, exc_info=True)
        sys.exit(1)
