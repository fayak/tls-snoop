"""TLS payload parsing functions."""

from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello

from .constants import TLS_VERSIONS, TLS_HANDSHAKE_SERVER_HELLO

# Extract cipher suite mapping from Scapy's TLSServerHello field definition
_cipher_field = next(f for f in TLSServerHello.fields_desc if f.name == "cipher")
CIPHER_SUITES = _cipher_field.i2s


def get_tls_version_str(version: int) -> str:
    """Convert TLS version number to human-readable string."""
    return TLS_VERSIONS.get(version, f"Unknown (0x{version:04x})")


def get_cipher_suite_name(cipher: int) -> str:
    """Convert cipher suite code to human-readable name using Scapy's database."""
    return CIPHER_SUITES.get(cipher, f"0x{cipher:04X}")


def parse_tls_manual(payload: bytes, prefix: str = "  ") -> None:
    """Manual TLS parsing fallback."""
    if len(payload) < 6:
        print(f"{prefix}[!] Payload too short for TLS")
        return

    handshake_type = payload[5]
    handshake_names = {0x01: "Client Hello", 0x02: "Server Hello"}
    print(
        f"{prefix}Handshake:      "
        f"{handshake_names.get(handshake_type, f'Unknown (0x{handshake_type:02x})')}"
    )

    if len(payload) < 11:
        return

    # Handshake header: type(1) + length(3) + version(2)
    hs_version = (payload[9] << 8) | payload[10]

    # For Server Hello, parse cipher suite and look for supported_versions extension
    if handshake_type == TLS_HANDSHAKE_SERVER_HELLO and len(payload) >= 44:
        # Offset: 5 (record hdr) + 4 (hs hdr) + 2 (version) + 32 (random) = 43
        session_id_len = payload[43]
        cipher_offset = 44 + session_id_len

        if len(payload) >= cipher_offset + 2:
            cipher = (payload[cipher_offset] << 8) | payload[cipher_offset + 1]
            print(f"{prefix}Cipher Suite:   {get_cipher_suite_name(cipher)}")

            # After cipher: compression (1 byte), then extensions
            comp_offset = cipher_offset + 2
            if len(payload) > comp_offset:
                compression = payload[comp_offset]
                comp_name = (
                    "none"
                    if compression == 0
                    else "DEFLATE"
                    if compression == 1
                    else f"0x{compression:02x}"
                )
                print(f"{prefix}Compression:    {comp_name}")

                # Extensions start after compression
                ext_len_offset = comp_offset + 1
                if len(payload) >= ext_len_offset + 2:
                    ext_len = (payload[ext_len_offset] << 8) | payload[ext_len_offset + 1]
                    ext_offset = ext_len_offset + 2

                    # Parse extensions to find supported_versions (0x002b = 43)
                    negotiated_version = None
                    end_offset = ext_len_offset + 2 + ext_len
                    while ext_offset + 4 <= len(payload) and ext_offset < end_offset:
                        ext_type = (payload[ext_offset] << 8) | payload[ext_offset + 1]
                        ext_size = (payload[ext_offset + 2] << 8) | payload[ext_offset + 3]

                        if ext_type == 0x002B and ext_size >= 2:  # supported_versions
                            negotiated_version = (
                                (payload[ext_offset + 4] << 8) | payload[ext_offset + 5]
                            )

                        ext_offset += 4 + ext_size

                    # Print the actual negotiated version (TLS 1.3 hides here)
                    version_to_print = negotiated_version or hs_version
                    print(f"{prefix}TLS Version:    {get_tls_version_str(version_to_print)}")
        else:
            print(f"{prefix}TLS Version:    {get_tls_version_str(hs_version)}")

    elif handshake_type == 0x01:  # Client Hello
        print(f"{prefix}TLS Version:    {get_tls_version_str(hs_version)}")


def parse_tls_with_scapy(payload: bytes, prefix: str = "  ") -> None:
    """Parse TLS payload using Scapy and print details."""
    try:
        tls_packet = TLS(payload)
    except Exception as e:
        print(f"{prefix}[!] Scapy parse failed: {e}")
        parse_tls_manual(payload, prefix)
        return

    # Walk through layers to find handshake messages
    layer = tls_packet
    found_message = False

    while layer:
        if isinstance(layer, (TLSClientHello, TLSServerHello)):
            _print_tls_message(layer, prefix)
            found_message = True
        elif hasattr(layer, "msg") and layer.msg:
            msgs = layer.msg if isinstance(layer.msg, list) else [layer.msg]
            for m in msgs:
                _print_tls_message(m, prefix)
                found_message = True

        # Move to next layer
        if hasattr(layer, "payload") and layer.payload and layer.payload != layer:
            layer = layer.payload
        else:
            layer = None

    if not found_message:
        parse_tls_manual(payload, prefix)


def _print_tls_message(msg, prefix: str = "  ") -> None:
    """Print details of a single TLS message."""
    if isinstance(msg, TLSServerHello):
        _print_server_hello(msg, prefix)
    elif isinstance(msg, TLSClientHello):
        _print_client_hello(msg, prefix)
    else:
        print(f"{prefix}Type: {msg.__class__.__name__}")


def _print_server_hello(msg: TLSServerHello, prefix: str) -> None:
    """Print Server Hello details."""
    print(f"{prefix}Handshake:      Server Hello")

    # Check for TLS 1.3 version in supported_versions extension first
    negotiated_version = _extract_negotiated_version(msg)

    # Print actual TLS version (prefer negotiated from extension)
    version = negotiated_version or msg.version
    print(f"{prefix}TLS Version:    {get_tls_version_str(version)}")

    # Cipher suite
    if hasattr(msg, "cipher") and msg.cipher:
        print(f"{prefix}Cipher Suite:   {get_cipher_suite_name(msg.cipher)}")

    # Session ID
    if hasattr(msg, "sid") and msg.sid:
        sid_hex = msg.sid.hex()
        if len(sid_hex) > 32:
            sid_hex = sid_hex[:32] + "..."
        print(f"{prefix}Session ID:     {sid_hex}")

    # Compression
    if hasattr(msg, "comp") and msg.comp is not None:
        comp_val = msg.comp[0] if isinstance(msg.comp, (list, bytes)) else msg.comp
        comp_name = (
            "none"
            if comp_val == 0
            else "DEFLATE"
            if comp_val == 1
            else f"0x{comp_val:02x}"
        )
        print(f"{prefix}Compression:    {comp_name}")

    # Extensions as comma-separated list
    if hasattr(msg, "ext") and msg.ext:
        ext_names = [ext.__class__.__name__.replace("TLS_Ext_", "") for ext in msg.ext]
        print(f"{prefix}Extensions:     {', '.join(ext_names)}")


def _print_client_hello(msg: TLSClientHello, prefix: str) -> None:
    """Print Client Hello details."""
    print(f"{prefix}Handshake:      Client Hello")
    print(f"{prefix}TLS Version:    {get_tls_version_str(msg.version)}")

    # Cipher suites offered
    if hasattr(msg, "ciphers") and msg.ciphers:
        print(f"{prefix}Cipher Suites:  {len(msg.ciphers)} offered")

    # SNI extraction
    sni = _extract_sni(msg)
    if sni:
        print(f"{prefix}SNI:            {sni}")

    # Extensions as comma-separated list
    if hasattr(msg, "ext") and msg.ext:
        ext_names = [ext.__class__.__name__.replace("TLS_Ext_", "") for ext in msg.ext]
        print(f"{prefix}Extensions:     {', '.join(ext_names)}")


def _extract_negotiated_version(msg: TLSServerHello) -> int | None:
    """Extract negotiated TLS version from supported_versions extension."""
    if not hasattr(msg, "ext") or not msg.ext:
        return None

    for ext in msg.ext:
        ext_name = ext.__class__.__name__
        if "SupportedVersion" in ext_name or "supported_version" in ext_name.lower():
            for attr in ["version", "versions", "selected_version"]:
                if hasattr(ext, attr):
                    val = getattr(ext, attr)
                    if isinstance(val, int):
                        return val
                    if isinstance(val, (list, tuple)) and val:
                        return val[0]
    return None


def _extract_sni(msg: TLSClientHello) -> str | None:
    """Extract SNI from Client Hello extensions."""
    if not hasattr(msg, "ext") or not msg.ext:
        return None

    for ext in msg.ext:
        ext_name = ext.__class__.__name__
        if "ServerName" in ext_name and hasattr(ext, "servernames"):
            for sn in ext.servernames:
                if hasattr(sn, "servername"):
                    return sn.servername.decode("utf-8", errors="ignore")
    return None
