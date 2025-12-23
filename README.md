# TLS Snoop

An eBPF-based daemon that captures TLS handshakes from network traffic and exports metadata for analysis.

## Features

- Captures TLS Client Hello and Server Hello messages using eBPF/TC
- Supports IPv4 and IPv6
- Monitors all network interfaces by default (with dynamic interface detection)
- Outputs transaction data as NDJSON (newline-delimited JSON)
- Exposes Prometheus metrics for monitoring
- Runs as a systemd daemon with log rotation support

## Requirements

- Linux kernel >= 4.15
- BCC (BPF Compiler Collection) with Python bindings
- Root privileges (CAP_BPF, CAP_NET_ADMIN)

## Installation

### Arch Linux (AUR)

```bash
# Build and install from AUR
yay -S tls-snoop
# or
paru -S tls-snoop
```

### Debian/Ubuntu

```bash
# Build the .deb package
make deb

# Install
sudo dpkg -i deb/build/tls-snoop_*.deb
sudo apt-get install -f  # Install dependencies if needed
```

### From Source

```bash
# Install dependencies
uv sync

# Run directly (requires root)
make run
```

## Usage

```bash
# Listen on all interfaces, port 443 (default)
sudo tls-snoop

# Listen on one interface
sudo tls-snoop eth0

# Listen on multiple interfaces
sudo tls-snoop eth0 eth1

# Monitor multiple ports
sudo tls-snoop --port 443 --port 8443

# Write JSON transactions to file
sudo tls-snoop --json /var/log/tls-snoop/output.jsonl

# Enable Prometheus metrics
sudo tls-snoop --metrics --metrics-port 12284

# Quiet mode (no stdout output, for daemon use)
sudo tls-snoop --quiet --json /var/log/tls-snoop/output.jsonl
```

### CLI Options

| Option | Description |
|--------|-------------|
| `INTERFACE...` | One or more network interfaces to monitor (default: all interfaces) |
| `--port, -P` | Port to capture TLS traffic on (repeatable, default: 443) |
| `--json, -j` | Write JSON transactions to file (NDJSON format) |
| `--pidfile, -p` | Write PID to file for daemon management |
| `--quiet, -q` | Suppress stdout output |
| `--metrics, -m` | Enable Prometheus metrics endpoint |
| `--metrics-host` | Host to bind metrics server (default: 127.0.0.1) |
| `--metrics-port` | Port for metrics server (default: 12284) |

## Systemd Service

After installation, enable and start the service:

```bash
sudo systemctl enable --now tls-snoop
```

Configuration is in `/etc/tls-snoop/tls-snoop.conf`:

```bash
TLS_SNOOP_OPTS="--quiet --json /var/log/tls-snoop/tls-snoop.log"
```

### Log Rotation

Send SIGUSR1 to reopen the JSON file and attach to new interfaces:

```bash
sudo systemctl reload tls-snoop
# or
sudo kill -USR1 $(cat /run/tls-snoop.pid)
```

Logrotate is configured to rotate logs daily with the `postrotate` script sending SIGUSR1.

## JSON Output Format

Each line is a JSON document representing a completed TLS handshake:

```json
{
  "datetime": "2025-01-15T10:30:45.123456+00:00",
  "client_ip": "192.168.1.100",
  "client_port": 54321,
  "server_ip": "93.184.216.34",
  "server_port": 443,
  "sni": "example.com",
  "client_hello_payload_len": 512,
  "server_hello_payload_len": 128,
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "compression": "none",
  "cipher_suites_offered": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "..."],
  "client_extensions": ["ServerName", "SupportedVersions", "KeyShare", "..."],
  "server_extensions": ["SupportedVersions", "KeyShare"]
}
```

## Prometheus Metrics

When `--metrics` is enabled, the following metrics are exposed at `http://<host>:<port>/metrics`:

| Metric | Labels | Description |
|--------|--------|-------------|
| `tls_handshakes_total` | `tls_version`, `cipher_suite` | Total completed TLS handshakes |
| `tls_cipher_suites_offered_total` | `cipher_suite` | Times each cipher suite was offered by clients |
| `tls_client_extensions_total` | `extension` | Times each extension appeared in Client Hello |
| `tls_server_extensions_total` | `extension` | Times each extension appeared in Server Hello |

## Development

```bash
# Install dev dependencies
uv sync

# Run linter
make lint

# Run type checker
make typecheck

# Build Arch Linux package
make pkg

# Build Debian package
make deb
```

## How It Works

TLS Snoop uses eBPF with TC (Traffic Control) hooks to capture packets at the kernel level:

1. An eBPF program attaches to the `clsact` qdisc on network interfaces
2. Both ingress and egress traffic is inspected for TLS handshake records
3. Client Hello and Server Hello messages are copied to userspace via perf buffer
4. Userspace (Python) parses the TLS data using Scapy and pairs Client/Server Hello by connection tuple
5. Completed transactions are written to JSON and/or recorded as Prometheus metrics

## License

GPL-2.0
