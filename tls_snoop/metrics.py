"""Prometheus metrics for TLS Snoop."""

from prometheus_client import Counter, start_http_server

# Counter for completed TLS handshakes (Client Hello + Server Hello paired)
tls_handshakes_total = Counter(
    "tls_handshakes_total",
    "Total number of TLS handshakes completed",
    ["tls_version", "cipher_suite"],
)

# Counter for cipher suites offered by clients
tls_cipher_suites_offered_total = Counter(
    "tls_cipher_suites_offered_total",
    "Total number of times each cipher suite was offered by clients",
    ["cipher_suite"],
)

# Counter for client extensions
tls_client_extensions_total = Counter(
    "tls_client_extensions_total",
    "Total number of times each extension appeared in Client Hello",
    ["extension"],
)

# Counter for server extensions
tls_server_extensions_total = Counter(
    "tls_server_extensions_total",
    "Total number of times each extension appeared in Server Hello",
    ["extension"],
)


def start_metrics_server(host: str, port: int) -> None:
    """Start the Prometheus metrics HTTP server."""
    start_http_server(port, addr=host)


def record_handshake(
    tls_version: str,
    cipher_suite: str,
    cipher_suites_offered: list[str],
    client_extensions: list[str],
    server_extensions: list[str],
) -> None:
    """Record metrics for a completed TLS handshake."""
    # Record the handshake with version and selected cipher
    tls_handshakes_total.labels(
        tls_version=tls_version,
        cipher_suite=cipher_suite,
    ).inc()

    # Record offered cipher suites
    for suite in cipher_suites_offered:
        tls_cipher_suites_offered_total.labels(cipher_suite=suite).inc()

    # Record client extensions
    for ext in client_extensions:
        tls_client_extensions_total.labels(extension=ext).inc()

    # Record server extensions
    for ext in server_extensions:
        tls_server_extensions_total.labels(extension=ext).inc()
