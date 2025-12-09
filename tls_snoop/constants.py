"""Constants and ctypes structures for TLS Snoop."""

import ctypes

# Maximum TLS record size per spec (must match BPF program)
MAX_TLS_PAYLOAD = 16384

# Default TLS port
DEFAULT_TLS_PORTS = (443,)

# TLS handshake types
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_HANDSHAKE_SERVER_HELLO = 0x02

# TLS version mapping
TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


class TLSEvent(ctypes.Structure):
    """Structure matching the kernel tls_event struct."""

    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_ip6", ctypes.c_uint8 * 16),
        ("dst_ip6", ctypes.c_uint8 * 16),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("payload_len", ctypes.c_uint16),
        ("is_ipv6", ctypes.c_uint8),
        ("payload", ctypes.c_uint8 * MAX_TLS_PAYLOAD),
    ]
