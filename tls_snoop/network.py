"""Network address conversion utilities."""

import socket
import struct


def ipv4_to_str(ip_int: int) -> str:
    """Convert integer IPv4 to dotted string."""
    return socket.inet_ntoa(struct.pack("I", ip_int))


def ipv6_to_str(ip6_bytes) -> str:
    """Convert IPv6 bytes to string."""
    return socket.inet_ntop(socket.AF_INET6, bytes(ip6_bytes))


def ipv4_to_hex(ip_int: int) -> str:
    """Convert integer IP to hex format used in /proc/net/tcp."""
    return f"{ip_int:08X}"


def ipv6_to_hex(ip6_bytes) -> str:
    """Convert IPv6 bytes to hex format used in /proc/net/tcp6.

    /proc/net/tcp6 uses a format where each 4-byte group is byte-swapped.
    """
    b = bytes(ip6_bytes)
    return "".join(
        f"{b[i+3]:02X}{b[i+2]:02X}{b[i+1]:02X}{b[i]:02X}"
        for i in range(0, 16, 4)
    )


def format_address(ip_str: str, port: int, is_ipv6: bool) -> str:
    """Format IP:port string, using brackets for IPv6."""
    if is_ipv6:
        return f"[{ip_str}]:{port}"
    return f"{ip_str}:{port}"
