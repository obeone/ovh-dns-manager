"""
DNS record operations for the OVH DNS Manager.

Provides functions to create, list, delete DNS records and refresh
DNS zones through the OVH API.

Copyright (c) 2026 Snapp'
Author: Yannis Duvignau (yduvignau@snapp.fr)
"""

import ipaddress
import logging

import ovh
import ovh.exceptions
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from ovh_dns_manager.constants import SUPPORTED_RECORD_TYPES
from ovh_dns_manager.validation import validate_subdomain, validate_record_target

logger = logging.getLogger(__name__)

console = Console()


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

        is_valid, error_msg = validate_record_target(record_type, target)
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
