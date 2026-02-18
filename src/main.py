"""
OVH DNS Manager - A CLI tool for managing DNS entries via OVH API.

Author: Yannis Duvignau (yduvignau@snapp.fr)
"""

# ========= IMPORTS ============
import sys

import ovh
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .credentials import get_credentials_interactive
from .utils import validate_ip, validate_subdomain

# ========= CONSOLE SETUP ============
console = Console()


def print_header() -> None:
    """Display the application header."""
    console.print(
        Panel.fit(
            "[bold cyan]OVH DNS Manager[/bold cyan]\n"
            "[dim]Manage your DNS entries easily[/dim]",
            border_style="cyan",
        )
    )


def create_ovh_client(
    endpoint: str, application_key: str, application_secret: str, consumer_key: str
) -> ovh.Client:
    """
    Create and test OVH API client.

    Parameters:
        endpoint: OVH API endpoint
        application_key: Application key
        application_secret: Application secret
        consumer_key: Consumer key

    Returns:
        ovh.Client: Configured OVH client
    """
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description="Connecting to OVH API...", total=None)

            client = ovh.Client(
                endpoint=endpoint,
                application_key=application_key,
                application_secret=application_secret,
                consumer_key=consumer_key,
            )
            # Test connection by fetching some basic info
            client.get("/auth/time")

        console.print("[bold green]✓[/bold green] Successfully connected to OVH API\n")
        return client

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to connect to OVH API: {str(e)}")
        sys.exit(1)


def display_menu() -> str:
    """
    Display the main menu and get user choice.

    Returns:
        str: User's menu choice
    """
    console.print("[bold cyan]📝 Menu[/bold cyan]")
    console.print("  1. [green]Create[/green] DNS entry (A/AAAA record)")
    console.print("  2. [blue]List[/blue] DNS entries")
    console.print("  3. [red]Delete[/red] DNS entry")
    console.print("  4. [yellow]Exit[/yellow]\n")

    choice = Prompt.ask("Your choice", choices=["1", "2", "3", "4"])
    return choice


def create_dns_entries(client: ovh.Client, domain: str) -> None:
    """
    Create DNS A or AAAA records for specified subdomains.

    Parameters:
        client: OVH API client
        domain: Domain name
    """
    console.print("\n[bold green]➕ Create DNS Entries[/bold green]\n")

    # Get subdomain input
    subdomains_input = Prompt.ask(
        "Subdomains (comma separated) [dim]e.g. visio,livekit,keycloak[/dim]"
    )
    subdomains = [s.strip() for s in subdomains_input.split(",") if s.strip()]

    if not subdomains:
        console.print("[yellow]⚠[/yellow] No subdomains provided")
        return

    # Validate subdomains
    for sub in subdomains:
        if not validate_subdomain(sub):
            console.print(f"[red]✗[/red] Invalid subdomain format: [cyan]{sub}[/cyan]")
            return

    # Get target IP
    target = Prompt.ask("Target IP address")

    # Validate IP format
    if not validate_ip(target):
        console.print("[red]✗[/red] Invalid IP address format")
        return

    # Determine record type (A for IPv4, AAAA for IPv6)
    import ipaddress

    ip_obj = ipaddress.ip_address(target)
    record_type = "AAAA" if isinstance(ip_obj, ipaddress.IPv6Address) else "A"

    # Get TTL
    ttl_input = Prompt.ask("TTL (Time To Live in seconds)", default="3600")
    try:
        ttl = int(ttl_input)
    except ValueError:
        console.print("[yellow]⚠[/yellow] Invalid TTL, using default 3600")
        ttl = 3600

    # Summary
    console.print(
        f"\n[dim]Creating {len(subdomains)} DNS {record_type} record(s)...[/dim]"
    )

    domain_endpoint = f"/domain/zone/{domain}"
    success_count = 0
    failed_count = 0

    for subdomain in subdomains:
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task(
                    description=f"Adding {subdomain}.{domain} → {target}", total=None
                )

                result = client.post(
                    f"{domain_endpoint}/record",
                    fieldType=record_type,
                    subDomain=subdomain,
                    target=target,
                    ttl=ttl,
                )

            console.print(
                f"[green]✓[/green] Created: [cyan]{subdomain}.{domain}[/cyan] "
                f"→ {target} (ID: {result.get('id', 'N/A')})"
            )
            success_count += 1

        except Exception as e:
            console.print(
                f"[red]✗[/red] Failed to create {subdomain}.{domain}: {str(e)}"
            )
            failed_count += 1

    # Summary
    console.print(
        f"\n[bold]Summary:[/bold] {success_count} succeeded, {failed_count} failed"
    )

    # Ask to refresh zone
    if success_count > 0 and Confirm.ask(
        "\nRefresh DNS zone to apply changes?", default=True
    ):
        refresh_zone(client, domain)


def list_dns_entries(client: ovh.Client, domain: str) -> None:
    """
    List all DNS entries for the domain.

    Parameters:
        client: OVH API client
        domain: Domain name
    """
    console.print("\n[bold blue]📋 DNS Entries[/bold blue]\n")

    domain_endpoint = f"/domain/zone/{domain}"

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description="Fetching DNS entries...", total=None)

            entry_ids = client.get(f"{domain_endpoint}/record")

        if not entry_ids:
            console.print("[yellow]ℹ[/yellow] No DNS entries found")
            return

        # Create table
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("ID", style="dim", width=10)
        table.add_column("Type", width=8)
        table.add_column("Subdomain", style="cyan")
        table.add_column("Target", style="green")
        table.add_column("TTL", justify="right", width=8)

        # Optimization: fetch details
        for entry_id in entry_ids:
            try:
                entry = client.get(f"{domain_endpoint}/record/{entry_id}")
                table.add_row(
                    str(entry.get("id", "")),
                    entry.get("fieldType", ""),
                    entry.get("subDomain", "") or "@",
                    entry.get("target", ""),
                    str(entry.get("ttl", "")),
                )
            except Exception as e:
                console.print(
                    f"[red]✗[/red] Failed to fetch entry {entry_id}: {str(e)}"
                )

        console.print(table)
        console.print(f"\n[dim]Total entries: {len(entry_ids)}[/dim]")

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to list DNS entries: {str(e)}")


def delete_dns_entries(client: ovh.Client, domain: str) -> None:
    """
    Delete DNS entries for specified subdomains.

    Parameters:
        client: OVH API client
        domain: Domain name
    """
    console.print("\n[bold red]🗑️  Delete DNS Entries[/bold red]\n")

    # Get subdomain input
    subdomains_input = Prompt.ask(
        "Subdomains to delete (comma separated) [dim]e.g. visio,livekit,keycloak[/dim]"
    )
    subdomains = [s.strip() for s in subdomains_input.split(",") if s.strip()]

    if not subdomains:
        console.print("[yellow]⚠[/yellow] No subdomains provided")
        return

    # Warning and confirmation
    console.print(
        "\n[bold red]⚠ Warning:[/bold red] You are about to delete DNS entries for:"
    )
    for subdomain in subdomains:
        console.print(f"  • [cyan]{subdomain}.{domain}[/cyan]")

    if not Confirm.ask("\nAre you sure you want to proceed?", default=False):
        console.print("[yellow]ℹ[/yellow] Operation cancelled")
        return

    domain_endpoint = f"/domain/zone/{domain}"
    success_count = 0
    failed_count = 0

    try:
        # Optimization: Fetch only relevant records using subDomain filter
        for subdomain in subdomains:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task(
                    description=f"Searching records for {subdomain}.{domain}",
                    total=None,
                )
                entry_ids = client.get(f"{domain_endpoint}/record", subDomain=subdomain)

            if not entry_ids:
                console.print(f"[yellow]ℹ[/yellow] No records found for {subdomain}")
                continue

            for entry_id in entry_ids:
                try:
                    entry = client.get(f"{domain_endpoint}/record/{entry_id}")

                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        progress.add_task(
                            description=f"Deleting {subdomain}.{domain}",
                            total=None,
                        )
                        client.delete(f"{domain_endpoint}/record/{entry_id}")

                    console.print(
                        f"[green]✓[/green] Deleted: [cyan]{subdomain}.{domain}[/cyan] "
                        f"({entry.get('fieldType')}) → {entry.get('target', 'N/A')} "
                        f"(ID: {entry_id})"
                    )
                    success_count += 1

                except Exception as e:
                    console.print(
                        f"[red]✗[/red] Failed to delete entry {entry_id}: {str(e)}"
                    )
                    failed_count += 1

        # Summary
        console.print(
            f"\n[bold]Summary:[/bold] {success_count} deleted, {failed_count} failed"
        )

        # Ask to refresh zone
        if success_count > 0 and Confirm.ask(
            "\nRefresh DNS zone to apply changes?", default=True
        ):
            refresh_zone(client, domain)

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to delete DNS entries: {str(e)}")


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
            console=console,
        ) as progress:
            progress.add_task(description="Refreshing DNS zone...", total=None)
            client.post(f"/domain/zone/{domain}/refresh")

        console.print("[green]✓[/green] DNS zone refreshed successfully")

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to refresh zone: {str(e)}")


def main() -> None:
    """Main application entry point."""
    print_header()

    # Get credentials (from .env or prompt)
    creds = get_credentials_interactive()

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
                sys.exit(0)

            # Separator before next action
            console.print("\n" + "─" * 60 + "\n")

        except KeyboardInterrupt:
            console.print("\n\n[yellow]⚠[/yellow] Operation cancelled by user")
            if Confirm.ask("\nDo you want to exit?", default=True):
                console.print("\n[bold cyan]👋 Goodbye![/bold cyan]\n")
                sys.exit(0)
        except Exception as e:
            console.print(f"\n[red]✗[/red] Unexpected error: {str(e)}")
            if not Confirm.ask("\nContinue?", default=True):
                sys.exit(1)


if __name__ == "__main__":
    main()
