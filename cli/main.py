"""
cli/main.py — the real `cloudpath` CLI (ARCHITECTURE.md Section 35),
replacing scripts/run_scan_demo.py's role as a one-off demo script.
Talks to the FastAPI backend over HTTP using a saved auth session —
same architecture as aws-cli/gh cli, not a second reimplementation of
the scan engine.
"""
from __future__ import annotations

import getpass
import json as json_module
import sys

import click
from rich.console import Console
from rich.table import Table

from cli.client import APIError, CloudPathClient
from cli.config import CLIConfig, clear_config, load_config, save_config

console = Console()
error_console = Console(stderr=True, style="red")


def _client() -> CloudPathClient:
    config = load_config()
    if not config.access_token:
        error_console.print("Not logged in. Run `cloudpath login` first.")
        sys.exit(1)
    return CloudPathClient(config)


def _handle_api_error(exc: APIError) -> None:
    error_console.print(f"API error ({exc.status_code}): {exc.detail}")
    sys.exit(1)


@click.group()
@click.version_option(version="1.0.0", prog_name="cloudpath")
def cli() -> None:
    """CloudPath AI — AI-powered cloud attack path analyzer CLI."""


# ----------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------
@cli.command()
@click.option("--url", default="http://localhost:8000", help="CloudPath AI API base URL.")
@click.option("--username", prompt=True)
@click.option("--password", prompt=True, hide_input=True)
def login(url: str, username: str, password: str) -> None:
    """Log in and save a session for subsequent commands."""
    config = CLIConfig(api_url=url)
    with CloudPathClient(config) as client:
        try:
            result = client.login(username, password)
        except APIError as exc:
            _handle_api_error(exc)
            return

    config.access_token = result["access_token"]
    config.username = username
    config.role = result["role"]
    save_config(config)
    console.print(f"[green]Logged in as {username} ({result['role']}).[/green]")


@cli.command()
def logout() -> None:
    """Clear the saved session."""
    clear_config()
    console.print("Logged out.")


@cli.command()
def whoami() -> None:
    """Show the currently logged-in user."""
    config = load_config()
    if not config.access_token:
        console.print("Not logged in.")
        return
    console.print(f"{config.username} ({config.role}) — {config.api_url}")


# ----------------------------------------------------------------------
# Scanning
# ----------------------------------------------------------------------
@cli.group()
def scan() -> None:
    """Trigger and check cloud scans."""


@scan.command("aws")
@click.option("--region", default="us-east-1", show_default=True)
@click.option("--async", "run_async", is_flag=True, help="Return immediately; poll `cloudpath scan status` for progress.")
@click.option("--crown-jewel", "crown_jewels", multiple=True, help="Asset id to treat as a crown jewel (repeatable).")
def scan_aws(region: str, run_async: bool, crown_jewels: tuple[str, ...]) -> None:
    """Scan an AWS account for assets and attack paths."""
    with _client() as client:
        try:
            if run_async:
                result = client.create_scan_async(region=region, crown_jewel_ids=list(crown_jewels))
                console.print(f"Scan queued: [bold]{result['scan_id']}[/bold] (status: {result['status']})")
                console.print(f"Check progress with: cloudpath scan status {result['scan_id']}")
            else:
                console.print(f"Scanning region [bold]{region}[/bold] (this blocks until done)...")
                result = client.create_scan(region=region, crown_jewel_ids=list(crown_jewels))
                console.print(f"[green]Scan complete:[/green] {result['scan_id']}")
                console.print(f"  Account: {result['account_id']}")
                console.print(f"  Assets discovered: {result['asset_count']}")
                console.print(f"  Relationships: {result['relationship_count']}")
                if result["errors"]:
                    console.print(f"[yellow]  {len(result['errors'])} collector warnings:[/yellow]")
                    for err in result["errors"]:
                        console.print(f"    - {err}")
        except APIError as exc:
            _handle_api_error(exc)


@scan.command("status")
@click.argument("scan_id")
def scan_status(scan_id: str) -> None:
    """Check the status of a scan (especially useful after --async)."""
    with _client() as client:
        try:
            result = client.get_scan(scan_id)
        except APIError as exc:
            _handle_api_error(exc)
            return
    status_color = {"completed": "green", "running": "yellow", "pending": "yellow", "failed": "red"}.get(
        result["status"], "white"
    )
    console.print(f"Status: [{status_color}]{result['status']}[/{status_color}]")
    console.print(f"Assets: {result['asset_count']}, Relationships: {result['relationship_count']}")


@scan.command("wait")
@click.argument("scan_id")
@click.option("--interval", default=3, show_default=True, help="Seconds between status checks.")
@click.option("--timeout", default=300, show_default=True, help="Give up after this many seconds.")
def scan_wait(scan_id: str, interval: int, timeout: int) -> None:
    """Block and poll until an --async scan finishes (completed or
    failed), instead of running `scan status` repeatedly by hand."""
    import time

    with _client() as client:
        elapsed = 0
        with console.status(f"Waiting for scan {scan_id}...") as status_display:
            while elapsed < timeout:
                try:
                    result = client.get_scan(scan_id)
                except APIError as exc:
                    _handle_api_error(exc)
                    return

                state = result["status"]
                status_display.update(f"Waiting for scan {scan_id}... (status: {state}, {elapsed}s elapsed)")

                if state == "completed":
                    console.print(f"[green]Scan complete:[/green] {result['scan_id']}")
                    console.print(f"  Assets: {result['asset_count']}, Relationships: {result['relationship_count']}")
                    return
                if state == "failed":
                    error_console.print(f"Scan failed: {result.get('errors') or 'no error detail available'}")
                    sys.exit(1)

                time.sleep(interval)
                elapsed += interval

        error_console.print(f"Timed out after {timeout}s waiting for scan {scan_id} (last status: {state}).")
        error_console.print(f"It may still be running — check again with: cloudpath scan status {scan_id}")
        sys.exit(1)


# ----------------------------------------------------------------------
# Assets
# ----------------------------------------------------------------------
@cli.group()
def assets() -> None:
    """Inspect discovered cloud assets."""


@assets.command("list")
@click.option("--scan-id", default=None)
@click.option("--type", "type_filter", default=None, help="Filter by asset type (e.g. EC2, S3, ROLE).")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON instead of a table.")
def assets_list(scan_id: str | None, type_filter: str | None, as_json: bool) -> None:
    """List discovered assets."""
    with _client() as client:
        try:
            result = client.list_assets(scan_id=scan_id)
        except APIError as exc:
            _handle_api_error(exc)
            return

    if type_filter:
        result = [a for a in result if a["type"] == type_filter.upper()]

    if as_json:
        console.print(json_module.dumps(result, indent=2))
        return

    table = Table(title=f"Assets ({len(result)})")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Region")
    table.add_column("Public", justify="center")
    for a in result:
        table.add_row(a["name"], a["type"], a["region"] or "-", "[red]Yes[/red]" if a["public"] else "No")
    console.print(table)


# ----------------------------------------------------------------------
# Attack paths
# ----------------------------------------------------------------------
@cli.group()
def paths() -> None:
    """Inspect discovered attack paths."""


@paths.command("list")
@click.option("--scan-id", default=None)
@click.option("--min-severity", default=None, type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
@click.option("--json", "as_json", is_flag=True)
def paths_list(scan_id: str | None, min_severity: str | None, as_json: bool) -> None:
    """List attack paths, ranked by risk score."""
    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    with _client() as client:
        try:
            result = client.list_attack_paths(scan_id=scan_id)
        except APIError as exc:
            _handle_api_error(exc)
            return

    if min_severity:
        threshold = severity_rank[min_severity]
        result = [p for p in result if severity_rank.get(p["severity"], 0) >= threshold]

    if as_json:
        console.print(json_module.dumps(result, indent=2))
        return

    if not result:
        console.print("No attack paths found.")
        return

    table = Table(title=f"Attack Paths ({len(result)})")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Risk", justify="right")
    table.add_column("Confidence", justify="right")
    table.add_column("Hops", justify="right")
    table.add_column("Entry → Target")
    severity_colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "grey62"}
    for p in result:
        color = severity_colors.get(p["severity"], "white")
        table.add_row(
            p["id"],
            f"[{color}]{p['severity']}[/{color}]",
            f"{p['risk_score']}/100",
            f"{p['confidence']*100:.0f}%",
            str(p["hop_count"]),
            f"{p['entry']} → {p['target']}",
        )
    console.print(table)


@paths.command("show")
@click.argument("attack_path_id")
def paths_show(attack_path_id: str) -> None:
    """Show MITRE ATT&CK mappings and any existing AI analysis for a
    persisted attack path (requires a scan run with `--async`)."""
    with _client() as client:
        try:
            mitre = client.get_mitre_mappings(attack_path_id)
        except APIError as exc:
            _handle_api_error(exc)
            return

        if mitre:
            console.print("[bold]MITRE ATT&CK techniques:[/bold]")
            for m in mitre:
                console.print(f"  {m['technique_id']} — {m['technique_name']} (confidence {m['confidence']:.2f})")
        else:
            console.print("No MITRE techniques mapped for this path.")

        try:
            analysis = client.get_attack_path_analysis(attack_path_id)
            console.print("\n[bold]AI analysis:[/bold]")
            console.print(analysis["summary"])
            console.print(f"\nImpact: {analysis['impact']}")
            console.print(f"Remediation priority: {analysis['remediation_priority']}")
        except APIError as exc:
            if exc.status_code == 404:
                console.print("\n[dim]No AI analysis yet — run `cloudpath paths analyze <id>` to generate one.[/dim]")
            else:
                _handle_api_error(exc)


@paths.command("analyze")
@click.argument("attack_path_id")
def paths_analyze(attack_path_id: str) -> None:
    """Run AI analysis on a persisted attack path (requires an AI
    provider configured on the server — ANTHROPIC_API_KEY etc.)."""
    with _client() as client:
        console.print("Requesting AI analysis (this calls out to the configured LLM provider)...")
        try:
            result = client.analyze_attack_path(attack_path_id)
        except APIError as exc:
            _handle_api_error(exc)
            return
    console.print(f"[green]Analysis complete[/green] (model: {result.get('model_used', 'unknown')})")
    console.print(f"\n{result['summary']}")
    console.print(f"\nImpact: {result['impact']}")
    console.print(f"Remediation priority: {result['remediation_priority']}")
    if result.get("recommended_actions"):
        console.print("\nRecommended actions:")
        for action in result["recommended_actions"]:
            console.print(f"  - {action}")


# ----------------------------------------------------------------------
# What-if simulation
# ----------------------------------------------------------------------
@cli.command()
@click.option("--scan-id", default=None)
@click.option(
    "--remove", "removals", multiple=True, required=True,
    help="Edge to remove, format SOURCE:TARGET:EDGE_TYPE (repeatable).",
)
def simulate(scan_id: str | None, removals: tuple[str, ...]) -> None:
    """Run a what-if simulation: remove edges and see which attack paths
    get blocked. Never touches real cloud infrastructure."""
    remove_edges = []
    for r in removals:
        parts = r.split(":")
        if len(parts) != 3:
            error_console.print(f"Invalid --remove format: '{r}' (expected SOURCE:TARGET:EDGE_TYPE)")
            sys.exit(1)
        source, target, edge_type = parts
        remove_edges.append({"source_id": source, "target_id": target, "edge_type": edge_type})

    with _client() as client:
        try:
            result = client.simulate(remove_edges=remove_edges, scan_id=scan_id)
        except APIError as exc:
            _handle_api_error(exc)
            return

    console.print(f"Paths before: {result['paths_before_count']}")
    console.print(f"Paths after:  {result['paths_after_count']}")
    console.print(f"[green]Blocked: {result['paths_blocked_count']}[/green]")

    if result["blocked_paths"]:
        console.print("\n[bold]Blocked paths:[/bold]")
        for p in result["blocked_paths"]:
            console.print(f"  {p['entry']} → {p['target']} (was risk {p['risk_score']}/100)")

    if result["still_open_paths"]:
        console.print("\n[bold]Still open:[/bold]")
        for p in result["still_open_paths"]:
            console.print(f"  {p['entry']} → {p['target']} (risk {p['risk_score']}/100)")


# ----------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------
@cli.command()
@click.option("--scan-id", default=None)
@click.option("--format", "output_format", type=click.Choice(["json", "markdown"]), default="markdown")
@click.option("--output", "output_file", type=click.Path(), default=None, help="Write to a file instead of stdout.")
def report(scan_id: str | None, output_format: str, output_file: str | None) -> None:
    """Generate a summary report (statistics + attack paths) for a scan.

    This aggregates data from existing endpoints client-side — there is
    no dedicated /api/v1/reports endpoint on the server (ARCHITECTURE.md
    Section 34's report generation is not yet built server-side); this
    command is a legitimate, documented stand-in, not a claim that
    server-side reporting exists.
    """
    with _client() as client:
        try:
            stats = client.get_statistics(scan_id=scan_id)
            path_list = client.list_attack_paths(scan_id=scan_id)
        except APIError as exc:
            _handle_api_error(exc)
            return

    if output_format == "json":
        content = json_module.dumps({"statistics": stats, "attack_paths": path_list}, indent=2)
    else:
        lines = [
            "# CloudPath AI — Scan Report",
            "",
            "## Summary",
            f"- Assets: {stats['node_count']}",
            f"- Relationships: {stats['edge_count']}",
            f"- Attack paths found: {stats['attack_path_count']}",
            f"- Critical paths: {stats['critical_path_count']}",
            "",
            "## Attack Paths",
            "",
        ]
        if not path_list:
            lines.append("No attack paths found.")
        else:
            for p in sorted(path_list, key=lambda x: x["risk_score"], reverse=True):
                lines.append(f"### {p['entry']} → {p['target']}")
                lines.append(f"- Severity: **{p['severity']}** (risk {p['risk_score']}/100)")
                lines.append(f"- Confidence: {p['confidence']*100:.0f}%")
                lines.append(f"- Hops: {p['hop_count']}")
                lines.append("")
        content = "\n".join(lines)

    if output_file:
        with open(output_file, "w") as f:
            f.write(content)
        console.print(f"[green]Report written to {output_file}[/green]")
    else:
        console.print(content)


# ----------------------------------------------------------------------
# Health check (no auth required)
# ----------------------------------------------------------------------
@cli.command()
@click.option("--url", default=None, help="Override the configured API URL for this check.")
def status(url: str | None) -> None:
    """Check whether the CloudPath AI API is reachable."""
    config = load_config()
    if url:
        config = CLIConfig(api_url=url)
    with CloudPathClient(config) as client:
        try:
            result = client.health()
            console.print(f"[green]API reachable at {config.api_url}[/green] — status: {result['status']}")
        except Exception as exc:  # noqa: BLE001
            error_console.print(f"API not reachable at {config.api_url}: {exc}")
            sys.exit(1)


if __name__ == "__main__":
    cli()
