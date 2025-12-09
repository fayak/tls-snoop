"""Event handling and display."""

import ctypes
from typing import TYPE_CHECKING

from .constants import (
    TLSEvent,
    TLS_HANDSHAKE_CLIENT_HELLO,
    TLS_HANDSHAKE_SERVER_HELLO,
    DEFAULT_TLS_PORTS,
)
from .network import ipv4_to_str, ipv6_to_str, format_address
from .parsers import parse_tls_with_scapy
from .process import get_process_by_connection, get_process_by_connection6

if TYPE_CHECKING:
    from .transaction import TransactionTracker

# Global state (set by main)
_transaction_tracker: "TransactionTracker | None" = None
_tls_ports: set[int] = set(DEFAULT_TLS_PORTS)
_quiet_mode: bool = False


def set_transaction_tracker(tracker: "TransactionTracker | None") -> None:
    """Set the global transaction tracker."""
    global _transaction_tracker
    _transaction_tracker = tracker


def set_tls_ports(ports: tuple[int, ...]) -> None:
    """Set the TLS ports to monitor."""
    global _tls_ports
    _tls_ports = set(ports)


def set_quiet_mode(quiet: bool) -> None:
    """Set quiet mode (suppress stdout output)."""
    global _quiet_mode
    _quiet_mode = quiet


def handle_event(cpu, data, size) -> None:
    """Handle TLS events from kernel."""
    event = ctypes.cast(data, ctypes.POINTER(TLSEvent)).contents

    src_port = event.src_port
    dst_port = event.dst_port
    is_ipv6 = bool(event.is_ipv6)

    # Get IP addresses based on protocol
    if is_ipv6:
        src_ip_str = ipv6_to_str(event.src_ip6)
        dst_ip_str = ipv6_to_str(event.dst_ip6)
    else:
        src_ip_str = ipv4_to_str(event.src_ip)
        dst_ip_str = ipv4_to_str(event.dst_ip)

    src_addr_str = format_address(src_ip_str, src_port, is_ipv6)
    dst_addr_str = format_address(dst_ip_str, dst_port, is_ipv6)

    # Determine direction based on TLS ports
    is_outbound = dst_port in _tls_ports
    direction = ">>>" if is_outbound else "<<<"
    local_str = src_addr_str if is_outbound else dst_addr_str
    remote_str = dst_addr_str if is_outbound else src_addr_str

    # Look up process info
    proc_str = _lookup_process(event, is_ipv6, is_outbound)

    # Extract payload
    payload = bytes(event.payload[: event.payload_len])

    # Determine handshake type for the header
    handshake_type = _get_handshake_type(payload)
    hs_type_byte = payload[5] if len(payload) >= 6 else None

    # Track transaction for JSON output
    if _transaction_tracker and hs_type_byte:
        # Determine client/server based on direction
        if is_outbound:
            # Outbound: we are the client
            client_ip, client_port = src_ip_str, src_port
            server_ip, server_port = dst_ip_str, dst_port
        else:
            # Inbound: we are the server (or receiving response)
            client_ip, client_port = dst_ip_str, dst_port
            server_ip, server_port = src_ip_str, src_port

        if hs_type_byte == TLS_HANDSHAKE_CLIENT_HELLO:
            _transaction_tracker.add_client_hello(
                client_ip, client_port, server_ip, server_port, payload
            )
        elif hs_type_byte == TLS_HANDSHAKE_SERVER_HELLO:
            _transaction_tracker.add_server_hello(
                client_ip, client_port, server_ip, server_port, payload
            )

    # Print output (unless in quiet mode)
    if not _quiet_mode:
        _print_event(
            direction=direction,
            handshake_type=handshake_type,
            proc_str=proc_str,
            local_str=local_str,
            remote_str=remote_str,
            payload_len=event.payload_len,
            is_outbound=is_outbound,
        )

        # Parse TLS
        parse_tls_with_scapy(payload)


def _lookup_process(event: TLSEvent, is_ipv6: bool, is_outbound: bool) -> str:
    """Look up process info for the connection."""
    src_port = event.src_port
    dst_port = event.dst_port

    if is_ipv6:
        local_ip6 = event.src_ip6 if is_outbound else event.dst_ip6
        local_port = src_port if is_outbound else dst_port
        remote_ip6 = event.dst_ip6 if is_outbound else event.src_ip6
        remote_port = dst_port if is_outbound else src_port
        proc_info = get_process_by_connection6(
            local_ip6, local_port, remote_ip6, remote_port
        )
    else:
        local_ip = event.src_ip if is_outbound else event.dst_ip
        local_port = src_port if is_outbound else dst_port
        remote_ip = event.dst_ip if is_outbound else event.src_ip
        remote_port = dst_port if is_outbound else src_port
        proc_info = get_process_by_connection(
            local_ip, local_port, remote_ip, remote_port
        )

    if proc_info:
        pid, proc_name = proc_info
        return f"{proc_name} (PID {pid})"
    return "unknown"


def _get_handshake_type(payload: bytes) -> str:
    """Determine handshake type from payload."""
    if len(payload) >= 6:
        hs_type = payload[5]
        if hs_type == TLS_HANDSHAKE_CLIENT_HELLO:
            return "Client Hello"
        if hs_type == TLS_HANDSHAKE_SERVER_HELLO:
            return "Server Hello"
    return "TLS Handshake"


def _print_event(
    direction: str,
    handshake_type: str,
    proc_str: str,
    local_str: str,
    remote_str: str,
    payload_len: int,
    is_outbound: bool,
) -> None:
    """Print formatted event output."""
    arrow = "-->" if is_outbound else "<--"
    print()
    print(f"{direction} {handshake_type} {direction}")
    print(f"  Process:        {proc_str}")
    print(f"  {local_str} {arrow} {remote_str}")
    print(f"  Payload:        {payload_len} bytes")
