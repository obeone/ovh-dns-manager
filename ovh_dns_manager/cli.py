"""
CLI entry point for the OVH DNS Manager.

Provides the main application loop, argument parsing, logging setup,
and menu display for the interactive DNS management interface.
"""

import argparse
import logging
import sys

import coloredlogs
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from ovh_dns_manager.client import create_ovh_client
from ovh_dns_manager.credentials import get_credentials_interactive
from ovh_dns_manager.dns import create_dns_entries, list_dns_entries, delete_dns_entries

logger = logging.getLogger(__name__)

console = Console()


def setup_logging(verbose: bool = False) -> None:
    """
    Configure logging with coloredlogs.

    Parameters:
        verbose: If True, set log level to DEBUG; otherwise INFO
    """
    level = "DEBUG" if verbose else "INFO"
    coloredlogs.install(
        level=level,
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        logger=logging.getLogger(),
    )
    logger.debug("Logging configured at %s level", level)


def print_header() -> None:
    """Display the application header."""
    console.print(Panel.fit(
        "[bold cyan]OVH DNS Manager[/bold cyan]\n"
        "[dim]Manage your DNS entries easily[/dim]",
        border_style="cyan"
    ))


def display_menu() -> str:
    """
    Display the main menu and get user choice.

    Returns:
        User's menu choice as a string
    """
    console.print("[bold cyan]📝 Menu[/bold cyan]")
    console.print("  1. [green]Create[/green] DNS entry")
    console.print("  2. [blue]List[/blue] DNS entries")
    console.print("  3. [red]Delete[/red] DNS entry")
    console.print("  4. [yellow]Exit[/yellow]\n")

    choice = Prompt.ask("Your choice", choices=["1", "2", "3", "4"])
    return choice


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="OVH DNS Manager - Manage DNS entries via OVH API",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging output",
    )
    return parser.parse_args()


def main() -> None:
    """Main application entry point."""
    args = parse_args()
    setup_logging(verbose=args.verbose)

    logger.debug("Application starting")
    print_header()

    # Get credentials (from .env or prompt)
    creds = get_credentials_interactive()
    logger.debug("Credentials obtained for domain %s", creds.domain)

    # Create client
    client = create_ovh_client(
        creds.endpoint,
        creds.application_key,
        creds.application_secret,
        creds.consumer_key,
    )

    # Main loop
    while True:
        try:
            choice = display_menu()

            if choice == "1":
                create_dns_entries(client, creds.domain)
            elif choice == "2":
                list_dns_entries(client, creds.domain)
            elif choice == "3":
                delete_dns_entries(client, creds.domain)
            elif choice == "4":
                console.print("\n[bold cyan]👋 Goodbye![/bold cyan]\n")
                logger.info("User exited normally")
                sys.exit(0)

            # Separator before next action
            console.print("\n" + "─" * 60 + "\n")

        except KeyboardInterrupt:
            console.print("\n\n[yellow]⚠[/yellow] Operation cancelled by user")
            if Confirm.ask("\nDo you want to exit?", default=True):
                console.print("\n[bold cyan]👋 Goodbye![/bold cyan]\n")
                logger.info("User exited via keyboard interrupt")
                sys.exit(0)
        except Exception as e:
            console.print(f"\n[red]✗[/red] Unexpected error: {e}")
            logger.error("Unhandled error in main loop: %s", e, exc_info=True)
            if not Confirm.ask("\nContinue?", default=True):
                sys.exit(1)
