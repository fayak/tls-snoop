"""TLS transaction tracking and JSON output."""

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello

from .metrics import record_handshake
from .parsers import get_tls_version_str, get_cipher_suite_name, get_named_group


@dataclass
class ClientHelloData:
    """Parsed Client Hello data."""

    timestamp: float
    payload_len: int
    cipher_suites_offered: list[str]
    extensions: list[str]
    supported_groups: list[str]
    sni: str | None = None


@dataclass
class TransactionData:
    """Complete TLS transaction data."""

    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_hello: ClientHelloData
    server_hello_payload_len: int
    tls_version: str
    cipher_suite: str
    compression: str
    server_extensions: list[str]
    key_share_group: str | None = None


# Connection key: (client_ip, client_port, server_ip, server_port)
ConnectionKey = tuple[str, int, str, int]


class TransactionTracker:
    """Track TLS transactions and write JSON output."""

    # Timeout for incomplete transactions (seconds)
    TRANSACTION_TIMEOUT = 30.0

    def __init__(self, output_file: Path | None = None):
        self._pending: dict[ConnectionKey, ClientHelloData] = {}
        self._output_file: TextIO | None = None
        self._output_path: Path | None = output_file
        if output_file:
            self._output_file = open(output_file, "a")

    def reopen(self) -> None:
        """Reopen output file (for log rotation)."""
        if self._output_path:
            if self._output_file:
                self._output_file.close()
            self._output_file = open(self._output_path, "a")

    def close(self) -> None:
        """Close output file."""
        if self._output_file:
            self._output_file.close()
            self._output_file = None

    def add_client_hello(
        self,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        payload: bytes,
    ) -> None:
        """Record a Client Hello for later matching."""
        self._cleanup_stale()

        key = (client_ip, client_port, server_ip, server_port)
        data = self._parse_client_hello(payload)
        if data:
            self._pending[key] = data

    def add_server_hello(
        self,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        payload: bytes,
    ) -> None:
        """Match Server Hello with Client Hello and write transaction."""
        key = (client_ip, client_port, server_ip, server_port)

        client_data = self._pending.pop(key, None)
        if not client_data:
            # No matching Client Hello, skip
            return

        server_data = self._parse_server_hello(payload)
        if not server_data:
            return

        transaction = TransactionData(
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            client_hello=client_data,
            server_hello_payload_len=server_data["payload_len"],
            tls_version=server_data["tls_version"],
            cipher_suite=server_data["cipher_suite"],
            compression=server_data["compression"],
            server_extensions=server_data["extensions"],
            key_share_group=server_data["key_share_group"],
        )

        self._record_transaction(transaction)

    def _parse_client_hello(self, payload: bytes) -> ClientHelloData | None:
        """Parse Client Hello and extract relevant fields."""
        try:
            tls_packet = TLS(payload)
        except Exception:
            return None

        msg = self._find_handshake_message(tls_packet, TLSClientHello)
        if not msg:
            return None

        # Extract cipher suites offered
        cipher_suites = []
        if hasattr(msg, "ciphers") and msg.ciphers:
            cipher_suites = [get_cipher_suite_name(c) for c in msg.ciphers]

        # Extract extensions
        extensions = []
        supported_groups = []
        sni = None
        if hasattr(msg, "ext") and msg.ext:
            for ext in msg.ext:
                ext_name = ext.__class__.__name__.replace("TLS_Ext_", "")
                extensions.append(ext_name)

                # Extract SNI
                if "ServerName" in ext.__class__.__name__:
                    if hasattr(ext, "servernames"):
                        for sn in ext.servernames:
                            if hasattr(sn, "servername"):
                                sni = sn.servername.decode("utf-8", errors="ignore")
                                break

                # Extract supported groups (named curves / key exchange groups)
                if "SupportedGroups" in ext.__class__.__name__ or "EllipticCurves" in ext.__class__.__name__:
                    for attr in ["groups", "named_group_list", "elliptic_curves"]:
                        if hasattr(ext, attr):
                            groups = getattr(ext, attr)
                            if groups:
                                supported_groups = [get_named_group(g) for g in groups]
                            break

        return ClientHelloData(
            timestamp=time.time(),
            payload_len=len(payload),
            cipher_suites_offered=cipher_suites,
            extensions=extensions,
            supported_groups=supported_groups,
            sni=sni,
        )

    def _parse_server_hello(self, payload: bytes) -> dict | None:
        """Parse Server Hello and extract relevant fields."""
        try:
            tls_packet = TLS(payload)
        except Exception:
            return None

        msg = self._find_handshake_message(tls_packet, TLSServerHello)
        if not msg:
            return None

        # Extract TLS version (check supported_versions extension for TLS 1.3)
        version = msg.version
        if hasattr(msg, "ext") and msg.ext:
            for ext in msg.ext:
                ext_name = ext.__class__.__name__
                if "SupportedVersion" in ext_name:
                    for attr in ["version", "versions", "selected_version"]:
                        if hasattr(ext, attr):
                            val = getattr(ext, attr)
                            if isinstance(val, int):
                                version = val
                                break
                            if isinstance(val, (list, tuple)) and val:
                                version = val[0]
                                break

        # Extract cipher suite
        cipher_suite = ""
        if hasattr(msg, "cipher") and msg.cipher:
            cipher_suite = get_cipher_suite_name(msg.cipher)

        # Extract compression
        compression = "none"
        if hasattr(msg, "comp") and msg.comp is not None:
            comp_val = msg.comp[0] if isinstance(msg.comp, (list, bytes)) else msg.comp
            if comp_val == 0:
                compression = "none"
            elif comp_val == 1:
                compression = "DEFLATE"
            else:
                compression = f"0x{comp_val:02x}"

        # Extract extensions and key_share group
        extensions = []
        key_share_group = None
        if hasattr(msg, "ext") and msg.ext:
            for ext in msg.ext:
                extensions.append(ext.__class__.__name__.replace("TLS_Ext_", ""))

                # Extract key share group from Server Hello
                if "KeyShare" in ext.__class__.__name__:
                    # Try different attribute names for the selected group
                    for attr in ["server_share", "selected_group", "group"]:
                        if hasattr(ext, attr):
                            share = getattr(ext, attr)
                            if share:
                                # Could be the share object or the group directly
                                if hasattr(share, "group"):
                                    key_share_group = get_named_group(share.group)
                                elif isinstance(share, int):
                                    key_share_group = get_named_group(share)
                            break
                    # Also check if there's a direct 'group' attribute on the extension
                    if not key_share_group and hasattr(ext, "group"):
                        group = ext.group
                        if isinstance(group, int):
                            key_share_group = get_named_group(group)

        return {
            "payload_len": len(payload),
            "tls_version": get_tls_version_str(version),
            "cipher_suite": cipher_suite,
            "compression": compression,
            "extensions": extensions,
            "key_share_group": key_share_group,
        }

    def _find_handshake_message(self, tls_packet, msg_type):
        """Find a specific handshake message type in TLS packet."""
        layer = tls_packet
        while layer:
            if isinstance(layer, msg_type):
                return layer
            if hasattr(layer, "msg") and layer.msg:
                msgs = layer.msg if isinstance(layer.msg, list) else [layer.msg]
                for m in msgs:
                    if isinstance(m, msg_type):
                        return m
            if hasattr(layer, "payload") and layer.payload and layer.payload != layer:
                layer = layer.payload
            else:
                layer = None
        return None

    def _record_transaction(self, transaction: TransactionData) -> None:
        """Record transaction: write to JSON and update metrics."""
        # Record metrics (always, regardless of JSON output)
        record_handshake(
            tls_version=transaction.tls_version,
            cipher_suite=transaction.cipher_suite,
            cipher_suites_offered=transaction.client_hello.cipher_suites_offered,
            client_extensions=transaction.client_hello.extensions,
            server_extensions=transaction.server_extensions,
            supported_groups=transaction.client_hello.supported_groups,
            key_share_group=transaction.key_share_group,
        )

        # Write to JSON file if configured
        if not self._output_file:
            return

        doc = {
            "datetime": datetime.now(timezone.utc).isoformat(),
            "client_ip": transaction.client_ip,
            "client_port": transaction.client_port,
            "server_ip": transaction.server_ip,
            "server_port": transaction.server_port,
            "sni": transaction.client_hello.sni,
            "client_hello_payload_len": transaction.client_hello.payload_len,
            "server_hello_payload_len": transaction.server_hello_payload_len,
            "tls_version": transaction.tls_version,
            "cipher_suite": transaction.cipher_suite,
            "key_share_group": transaction.key_share_group,
            "compression": transaction.compression,
            "cipher_suites_offered": transaction.client_hello.cipher_suites_offered,
            "supported_groups": transaction.client_hello.supported_groups,
            "client_extensions": transaction.client_hello.extensions,
            "server_extensions": transaction.server_extensions,
        }

        self._output_file.write(json.dumps(doc) + "\n")
        self._output_file.flush()

    def _cleanup_stale(self) -> None:
        """Remove stale pending transactions."""
        now = time.time()
        stale_keys = [
            key
            for key, data in self._pending.items()
            if now - data.timestamp > self.TRANSACTION_TIMEOUT
        ]
        for key in stale_keys:
            del self._pending[key]
