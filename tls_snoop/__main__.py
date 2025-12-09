"""Main entry point for TLS Snoop."""

import os
import signal
from pathlib import Path

import click

from .bpf import (
    load_bpf_program,
    create_bpf_filter,
    get_all_interfaces,
    MultiTCAttachment,
)
from .constants import DEFAULT_TLS_PORTS
from .event import handle_event, set_transaction_tracker, set_tls_ports, set_quiet_mode
from .metrics import start_metrics_server
from .transaction import TransactionTracker

# Perf buffer size: 256 pages = 1MB to handle large TLS records
PERF_BUFFER_PAGE_CNT = 256

# Global state for signal handler access
_tracker: TransactionTracker | None = None
_tc: MultiTCAttachment | None = None


def _handle_sigusr1(signum: int, frame) -> None:
    """Handle SIGUSR1 to reload: reopen log file and rescan interfaces."""
    click.echo("reloading ..")
    if _tracker:
        _tracker.reopen()
        click.echo("Reopened JSON output file", err=True)

    if _tc:
        new_ifaces = _tc.refresh()
        if new_ifaces:
            click.echo(f"Attached to new interfaces: {', '.join(new_ifaces)}", err=True)


@click.command()
@click.argument("interface", default=None, required=False)
@click.option(
    "--port",
    "-P",
    "ports",
    type=int,
    multiple=True,
    help="Destination port to capture TLS traffic on (can be repeated). Default: 443.",
)
@click.option(
    "--json",
    "-j",
    "json_file",
    type=click.Path(path_type=Path),
    help="Write JSON transactions to FILE (one JSON doc per line).",
)
@click.option(
    "--pidfile",
    "-p",
    type=click.Path(path_type=Path),
    help="Write PID to FILE (for daemon management).",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress stdout output (for daemon mode). Only write to JSON file.",
)
@click.option(
    "--metrics",
    "-m",
    is_flag=True,
    help="Enable Prometheus metrics endpoint.",
)
@click.option(
    "--metrics-host",
    default="localhost",
    show_default=True,
    help="Host to bind metrics server to.",
)
@click.option(
    "--metrics-port",
    default=12284,
    show_default=True,
    help="Port for metrics server.",
)
def main(
    interface: str | None,
    ports: tuple[int, ...],
    json_file: Path | None,
    pidfile: Path | None,
    quiet: bool,
    metrics: bool,
    metrics_host: str,
    metrics_port: int,
) -> None:
    """Capture TLS handshakes using eBPF.

    INTERFACE is the network interface to monitor. If not specified, listens on
    all interfaces (and auto-attaches to new interfaces on SIGUSR1).
    """
    global _tracker, _tc

    # Use default ports if none specified
    if not ports:
        ports = DEFAULT_TLS_PORTS

    # Set options for event handler
    set_tls_ports(ports)
    set_quiet_mode(quiet)

    # Determine interfaces to monitor
    if interface:
        interfaces = [interface]
        iface_str = interface
        auto_detect = False
    else:
        interfaces = get_all_interfaces()
        if not interfaces:
            raise click.ClickException("No network interfaces found")
        iface_str = ", ".join(interfaces)
        auto_detect = True

    ports_str = ", ".join(str(p) for p in ports)
    if not quiet:
        click.echo("TLS Snoop - Capturing TLS handshakes")
        click.echo(f"  Interfaces: {iface_str}")
        click.echo(f"  Ports: {ports_str}")
        if auto_detect:
            click.echo("Auto-detect mode: send SIGUSR1 to attach to new interfaces")
        if json_file:
            click.echo(f"  JSON output: {json_file}")
        if metrics:
            click.echo(f"  Metrics: http://{metrics_host}:{metrics_port}/metrics")
        if pidfile:
            click.echo(f"  PID file: {pidfile}")
        click.echo("Press Ctrl+C to stop")
        click.echo("Send SIGUSR1 to reopen JSON file for log rotation")

    # Start metrics server if enabled
    if metrics:
        start_metrics_server(metrics_host, metrics_port)

    # Write PID file
    if pidfile:
        pidfile.write_text(str(os.getpid()))

    # Set up signal handler for log rotation
    signal.signal(signal.SIGUSR1, _handle_sigusr1)

    # Load and compile BPF program
    try:
        bpf_source = load_bpf_program(list(ports))
        bpf = create_bpf_filter(bpf_source)
    except FileNotFoundError as e:
        raise click.ClickException(str(e))
    except Exception as e:
        raise click.ClickException(f"Error loading BPF program: {e}")

    # Set up transaction tracker for JSON output and metrics
    tracker = TransactionTracker(json_file)
    _tracker = tracker
    set_transaction_tracker(tracker)

    # Attach to TC (ingress and egress) for full visibility
    # Use None for auto-detect mode to enable refresh on SIGUSR1
    tc = MultiTCAttachment(bpf, None if auto_detect else interfaces)
    _tc = tc

    try:
        tc.attach()
    except Exception as e:
        tc.close()
        tracker.close()
        if pidfile:
            pidfile.unlink(missing_ok=True)
        raise click.ClickException(f"Error attaching to interface(s): {e}")

    # Open perf buffer
    bpf["tls_events"].open_perf_buffer(handle_event, page_cnt=PERF_BUFFER_PAGE_CNT)

    if not quiet:
        click.echo(f"Listening for TLS handshakes on port(s) {ports_str}...\n")

    try:
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        click.echo("\nStopping...")
    finally:
        tc.close()
        tracker.close()
        if pidfile:
            pidfile.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
