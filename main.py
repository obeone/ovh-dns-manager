"""
OVH DNS Manager - A CLI tool for managing DNS entries via OVH API.

Author: Yannis Duvignau (yduvignau@snapp.fr)
"""

# ========= IMPORTS ============
import argparse
import ipaddress
import logging
import sys

import coloredlogs
import ovh
import ovh.exceptions
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from credentials import OvhCredentials, get_credentials_interactive, validate_subdomain

# ========= LOGGING ============
logger = logging.getLogger(__name__)

# ========= CONSOLE SETUP ============
console = Console()

# ========= CONSTANTS ============
SUPPORTED_RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX", "SRV"]


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


def _prompt_record_type() -> str:
    """
    Prompt the user to select a DNS record type.

    Returns:
        Selected record type string (e.g. "A", "AAAA", "CNAME", etc.)
    """
    console.print("\nSelect record type:")
    for i, rtype in enumerate(SUPPORTED_RECORD_TYPES, 1):
        console.print(f"  {i}. [cyan]{rtype}[/cyan]")
    console.print()

    choices = [str(i) for i in range(1, len(SUPPORTED_RECORD_TYPES) + 1)]
    type_choice = Prompt.ask("Your choice", choices=choices, default="1")
    return SUPPORTED_RECORD_TYPES[int(type_choice) - 1]


def _validate_record_target(record_type: str, target: str) -> tuple[bool, str]:
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


def create_dns_entries(client: ovh.Client, domain: str) -> None:
    """
    Create DNS records for specified subdomains.

    Supports A, AAAA, CNAME, TXT, MX, and SRV record types.
    For A/AAAA, auto-detects the type from the IP address.

    Parameters:
        client: OVH API client
        domain: Domain name
    """
    console.print("\n[bold green]➕ Create DNS Entries[/bold green]\n")

    # Get subdomain input
    subdomains_input = Prompt.ask("Subdomains (comma separated) [dim]e.g. visio,livekit,keycloak[/dim]")
    subdomains = [s.strip() for s in subdomains_input.split(",") if s.strip()]

    if not subdomains:
        console.print("[yellow]⚠[/yellow] No subdomains provided")
        return

    # Validate subdomain labels
    invalid = [s for s in subdomains if not validate_subdomain(s)]
    if invalid:
        console.print(f"[red]✗[/red] Invalid subdomain(s): {', '.join(invalid)}")
        logger.warning("Invalid subdomains rejected: %s", invalid)
        return

    # Select record type
    record_type = _prompt_record_type()

    # Auto-detect A vs AAAA if user picks one of those
    if record_type in ("A", "AAAA"):
        target = Prompt.ask("Target IP address")
        try:
            ip_obj = ipaddress.ip_address(target.strip())
        except ValueError:
            console.print("[red]✗[/red] Invalid IP address format")
            logger.warning("Invalid IP address rejected: %s", target)
            return

        target = str(ip_obj)
        # Auto-correct the record type based on actual IP version
        record_type = "AAAA" if isinstance(ip_obj, ipaddress.IPv6Address) else "A"
        console.print(f"[dim]Detected {record_type} record for {target}[/dim]")
    else:
        # For other types, show type-specific hints
        hints = {
            "CNAME": "Target (FQDN with trailing dot) [dim]e.g. host.example.com.[/dim]",
            "TXT": "Target text [dim]e.g. v=spf1 include:_spf.google.com ~all[/dim]",
            "MX": "Priority and target [dim]e.g. 10 mail.example.com.[/dim]",
            "SRV": "Priority weight port target [dim]e.g. 10 60 5060 sip.example.com.[/dim]",
        }
        target = Prompt.ask(hints.get(record_type, "Target value"))

        is_valid, error_msg = _validate_record_target(record_type, target)
        if not is_valid:
            console.print(f"[red]✗[/red] {error_msg}")
            return
        target = target.strip()

    # Get TTL
    ttl_input = Prompt.ask("TTL (Time To Live in seconds)", default="3600")
    try:
        ttl = int(ttl_input)
    except ValueError:
        console.print("[yellow]⚠[/yellow] Invalid TTL, using default 3600")
        ttl = 3600

    # For MX records, split priority from target for the API
    api_target = target
    mx_priority = None
    if record_type == "MX":
        parts = target.split(maxsplit=1)
        mx_priority = int(parts[0])
        api_target = parts[1]

    # Summary
    console.print(f"\n[dim]Creating {len(subdomains)} DNS {record_type} record(s)...[/dim]")

    domain_endpoint = f"/domain/zone/{domain}"
    success_count = 0
    failed_count = 0

    for subdomain in subdomains:
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                progress.add_task(
                    description=f"Adding {subdomain}.{domain} → {target} ({record_type})",
                    total=None
                )

                post_kwargs: dict = {
                    "fieldType": record_type,
                    "subDomain": subdomain,
                    "target": api_target,
                    "ttl": ttl,
                }

                result = client.post(f"{domain_endpoint}/record", **post_kwargs)

            record_id = result.get('id', 'N/A')
            console.print(f"[green]✓[/green] Created: [cyan]{subdomain}.{domain}[/cyan] → {target} ({record_type}, ID: {record_id})")
            logger.info("Created %s record: %s.%s → %s (ID: %s)", record_type, subdomain, domain, target, record_id)
            success_count += 1

        except ovh.exceptions.ResourceConflictError as e:
            console.print(f"[red]✗[/red] Record already exists for {subdomain}.{domain}: {e}")
            logger.error("Conflict creating record %s.%s: %s", subdomain, domain, e)
            failed_count += 1
        except ovh.exceptions.NetworkError as e:
            console.print(f"[red]✗[/red] Network error creating {subdomain}.{domain}: {e}")
            logger.error("Network error: %s", e, exc_info=True)
            failed_count += 1
        except ovh.exceptions.APIError as e:
            console.print(f"[red]✗[/red] API error creating {subdomain}.{domain}: {e}")
            logger.error("API error: %s", e, exc_info=True)
            failed_count += 1
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to create {subdomain}.{domain}: {e}")
            logger.error("Unexpected error: %s", e, exc_info=True)
            failed_count += 1

    # Summary
    console.print(f"\n[bold]Summary:[/bold] {success_count} succeeded, {failed_count} failed")

    # Ask to refresh zone
    if success_count > 0:
        if Confirm.ask("\nRefresh DNS zone to apply changes?", default=True):
            refresh_zone(client, domain)


def list_dns_entries(client: ovh.Client, domain: str) -> None:
    """
    List DNS entries for the domain, optionally filtered by record type.

    Uses OVH API filters (fieldType, subDomain) to reduce the number of
    API calls instead of fetching all records and filtering client-side.

    Parameters:
        client: OVH API client
        domain: Domain name
    """
    console.print("\n[bold blue]📋 DNS Entries[/bold blue]\n")

    # Optional type filter
    console.print("Filter by record type? (leave empty for all)")
    type_filter = Prompt.ask(
        "Record type",
        default="",
    ).strip().upper()

    domain_endpoint = f"/domain/zone/{domain}"

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            progress.add_task(description="Fetching DNS entries...", total=None)

            # Use API filters to reduce N+1 calls
            get_kwargs: dict = {}
            if type_filter and type_filter in SUPPORTED_RECORD_TYPES:
                get_kwargs["fieldType"] = type_filter

            entry_ids = client.get(f"{domain_endpoint}/record", **get_kwargs)

        if not entry_ids:
            console.print("[yellow]ℹ[/yellow] No DNS entries found")
            return

        logger.debug("Fetched %d entry IDs for %s (filter: %s)", len(entry_ids), domain, type_filter or "none")

        # Create table
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("ID", style="dim", width=10)
        table.add_column("Type", width=8)
        table.add_column("Subdomain", style="cyan")
        table.add_column("Target", style="green")
        table.add_column("TTL", justify="right", width=8)

        for entry_id in entry_ids:
            try:
                entry = client.get(f"{domain_endpoint}/record/{entry_id}")
                table.add_row(
                    str(entry.get("id", "")),
                    entry.get("fieldType", ""),
                    entry.get("subDomain", "") or "@",
                    entry.get("target", ""),
                    str(entry.get("ttl", ""))
                )
            except ovh.exceptions.ResourceNotFoundError:
                logger.warning("Entry %d not found (may have been deleted)", entry_id)
            except ovh.exceptions.APIError as e:
                console.print(f"[red]✗[/red] Failed to fetch entry {entry_id}: {e}")
                logger.error("API error fetching entry %d: %s", entry_id, e)

        console.print(table)
        console.print(f"\n[dim]Total entries: {len(entry_ids)}[/dim]")

    except ovh.exceptions.NetworkError as e:
        console.print(f"[red]✗[/red] Network error listing DNS entries: {e}")
        logger.error("Network error listing entries: %s", e, exc_info=True)
    except ovh.exceptions.APIError as e:
        console.print(f"[red]✗[/red] API error listing DNS entries: {e}")
        logger.error("API error listing entries: %s", e, exc_info=True)
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to list DNS entries: {e}")
        logger.error("Unexpected error listing entries: %s", e, exc_info=True)


def delete_dns_entries(client: ovh.Client, domain: str) -> None:
    """
    Delete DNS entries for specified subdomains, filtered by record type.

    Uses OVH API filters (fieldType, subDomain) to fetch only matching
    records, avoiding unnecessary N+1 API calls.

    Parameters:
        client: OVH API client
        domain: Domain name
    """
    console.print("\n[bold red]🗑️  Delete DNS Entries[/bold red]\n")

    # Get subdomain input
    subdomains_input = Prompt.ask("Subdomains to delete (comma separated) [dim]e.g. visio,livekit,keycloak[/dim]")
    subdomains = [s.strip() for s in subdomains_input.split(",") if s.strip()]

    if not subdomains:
        console.print("[yellow]⚠[/yellow] No subdomains provided")
        return

    # Validate subdomain labels
    invalid = [s for s in subdomains if not validate_subdomain(s)]
    if invalid:
        console.print(f"[red]✗[/red] Invalid subdomain(s): {', '.join(invalid)}")
        logger.warning("Invalid subdomains rejected: %s", invalid)
        return

    # Ask which record type to delete
    console.print("\nWhich record type to delete?")
    for i, rtype in enumerate(SUPPORTED_RECORD_TYPES, 1):
        console.print(f"  {i}. [cyan]{rtype}[/cyan]")
    all_idx = len(SUPPORTED_RECORD_TYPES) + 1
    console.print(f"  {all_idx}. [cyan]All types[/cyan]\n")

    choices = [str(i) for i in range(1, all_idx + 1)]
    type_choice = Prompt.ask("Your choice", choices=choices, default=str(all_idx))
    choice_idx = int(type_choice)

    if choice_idx <= len(SUPPORTED_RECORD_TYPES):
        target_types = [SUPPORTED_RECORD_TYPES[choice_idx - 1]]
    else:
        target_types = list(SUPPORTED_RECORD_TYPES)

    type_label = "/".join(target_types) if len(target_types) <= 3 else "all"

    # Warning and confirmation
    console.print(f"\n[bold red]⚠ Warning:[/bold red] You are about to delete {type_label} records for:")
    for subdomain in subdomains:
        console.print(f"  • [cyan]{subdomain}.{domain}[/cyan]")

    if not Confirm.ask("\nAre you sure you want to proceed?", default=False):
        console.print("[yellow]ℹ[/yellow] Operation cancelled")
        return

    domain_endpoint = f"/domain/zone/{domain}"
    success_count = 0
    failed_count = 0
    skipped_types: set[str] = set()

    try:
        # Use API filters for each subdomain + type combination to minimize calls
        all_entries: list[tuple[int, dict]] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            progress.add_task(description="Fetching DNS entries...", total=None)

            for subdomain in subdomains:
                for rtype in target_types:
                    entry_ids = client.get(
                        f"{domain_endpoint}/record",
                        fieldType=rtype,
                        subDomain=subdomain,
                    )
                    for eid in entry_ids:
                        entry = client.get(f"{domain_endpoint}/record/{eid}")
                        all_entries.append((eid, entry))

        logger.debug("Found %d entries matching filters", len(all_entries))

        for entry_id, entry in all_entries:
            try:
                field_type = entry.get("fieldType", "")
                sub = entry.get("subDomain", "")

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    progress.add_task(
                        description=f"Deleting {sub}.{domain} ({field_type})",
                        total=None
                    )
                    client.delete(f"{domain_endpoint}/record/{entry_id}")

                console.print(
                    f"[green]✓[/green] Deleted: [cyan]{sub}.{domain}[/cyan] "
                    f"({field_type}) → {entry.get('target', 'N/A')} (ID: {entry_id})"
                )
                logger.info(
                    "Deleted %s record: %s.%s (ID: %d)",
                    field_type, sub, domain, entry_id,
                )
                success_count += 1

            except ovh.exceptions.ResourceNotFoundError:
                logger.warning("Entry %d not found (may have been already deleted)", entry_id)
            except ovh.exceptions.APIError as e:
                console.print(f"[red]✗[/red] Failed to delete entry {entry_id}: {e}")
                logger.error("API error deleting entry %d: %s", entry_id, e)
                failed_count += 1
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to delete entry {entry_id}: {e}")
                logger.error("Unexpected error deleting entry %d: %s", entry_id, e, exc_info=True)
                failed_count += 1

        # Summary
        console.print(f"\n[bold]Summary:[/bold] {success_count} deleted, {failed_count} failed")

        # Ask to refresh zone
        if success_count > 0:
            if Confirm.ask("\nRefresh DNS zone to apply changes?", default=True):
                refresh_zone(client, domain)

    except ovh.exceptions.NetworkError as e:
        console.print(f"[red]✗[/red] Network error deleting DNS entries: {e}")
        logger.error("Network error during delete: %s", e, exc_info=True)
    except ovh.exceptions.APIError as e:
        console.print(f"[red]✗[/red] API error deleting DNS entries: {e}")
        logger.error("API error during delete: %s", e, exc_info=True)
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to delete DNS entries: {e}")
        logger.error("Unexpected error during delete: %s", e, exc_info=True)


def refresh_zone(client: ovh.Client, domain: str) -> None:
    """
    Refresh the DNS zone to apply changes.

    Parameters:
        client: OVH API client
        domain: Domain name
    """
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            progress.add_task(description="Refreshing DNS zone...", total=None)
            client.post(f"/domain/zone/{domain}/refresh")

        console.print("[green]✓[/green] DNS zone refreshed successfully")
        logger.info("DNS zone refreshed for %s", domain)

    except ovh.exceptions.APIError as e:
        console.print(f"[red]✗[/red] Failed to refresh zone: {e}")
        logger.error("API error refreshing zone: %s", e, exc_info=True)
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to refresh zone: {e}")
        logger.error("Unexpected error refreshing zone: %s", e, exc_info=True)


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


if __name__ == "__main__":
    main()
