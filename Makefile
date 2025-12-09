.PHONY: all install sync run lint typecheck clean help pkg pkg-clean pkg-srcinfo deb deb-clean

# Package version - extracted from pyproject.toml
VERSION := $(shell python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])")
PKG_NAME := tls-snoop

# Optional network interface (if not set, listens on all interfaces)
INTERFACE ?=

# Python paths - use system Python with venv packages added
PYTHON_VERSION := $(shell python3 -c "import sys; print(f'python{sys.version_info.major}.{sys.version_info.minor}')")
VENV_SITE_PACKAGES := $(shell pwd)/.venv/lib/$(PYTHON_VERSION)/site-packages
PYTHONPATH := $(VENV_SITE_PACKAGES):$(PYTHONPATH)

all: help

# Install dependencies and create virtual environment
install:
	uv sync

# Sync dependencies (faster, assumes lock file exists)
sync:
	uv sync

# Optional JSON output file
JSON_FILE ?=
# Optional PID file
PID_FILE ?=
# Optional ports (space-separated, e.g., "443 8443")
PORTS ?=

# Build args if set
JSON_ARGS := $(if $(JSON_FILE),--json $(JSON_FILE),)
PID_ARGS := $(if $(PID_FILE),--pidfile $(PID_FILE),)
PORT_ARGS := $(foreach p,$(PORTS),--port $(p))

# Run the TLS snooper (requires root)
# Uses system Python (for bcc) with PYTHONPATH including venv packages (for scapy)
run:
	sudo bash -c 'export PYTHONPATH=$(PYTHONPATH); python3 -m tls_snoop $(INTERFACE) --metrics $(PORT_ARGS) $(JSON_ARGS) $(PID_ARGS)'

# Run linter
lint:
	uv run ruff check tls_snoop/

# Run type checker
typecheck:
	uv run mypy tls_snoop/

# Clean generated files
clean:
	rm -rf __pycache__ .mypy_cache .ruff_cache dist/ *.egg-info/
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

# Show help
help:
	@echo "TLS Snoop - eBPF TLS handshake capture tool"
	@echo ""
	@echo "Usage:"
	@echo "  make install           Install dependencies with uv"
	@echo "  make sync              Sync dependencies (fast)"
	@echo "  make run               Run TLS snooper (requires sudo)"
	@echo "  make lint              Run ruff linter"
	@echo "  make typecheck         Run mypy type checker"
	@echo "  make clean             Remove generated files"
	@echo ""
	@echo "Variables:"
	@echo "  INTERFACE        Network interface (default: all interfaces)"
	@echo "  PORTS            Space-separated ports to monitor (default: 443)"
	@echo "  JSON_FILE        Output file for JSON transactions (optional)"
	@echo "  PID_FILE         PID file for daemon management (optional)"
	@echo ""
	@echo "Examples:"
	@echo "  make run                              # Listen on all interfaces, port 443"
	@echo "  make run INTERFACE=wlan0              # Listen on specific interface"
	@echo "  make run PORTS='443 8443'             # Monitor multiple ports"
	@echo "  make run JSON_FILE=output.jsonl       # Write JSON to file"
	@echo ""
	@echo "Packaging:"
	@echo "  make pkg               Build Arch Linux package"
	@echo "  make pkg-srcinfo       Generate .SRCINFO for AUR"
	@echo "  make pkg-clean         Clean Arch package build files"
	@echo "  make deb               Build Debian package"
	@echo "  make deb-clean         Clean Debian package build files"

# =============================================================================
# Arch Linux Package Building
# =============================================================================

# Build Arch Linux package (PKGBUILD is at project root)
pkg:
	@echo "Building Arch Linux package..."
	makepkg -sf
	@echo ""
	@echo "Package built: $(PKG_NAME)-$(VERSION)-*.pkg.tar.zst"
	@echo "Install with: sudo pacman -U $(PKG_NAME)-$(VERSION)-*.pkg.tar.zst"

# Generate .SRCINFO for AUR submission
pkg-srcinfo:
	makepkg --printsrcinfo > .SRCINFO
	@echo "Generated: .SRCINFO"

# Clean Arch package build files
pkg-clean:
	rm -rf pkg/ src/ *.pkg.tar.zst .SRCINFO dist/

# =============================================================================
# Debian Package Building
# =============================================================================

DEB_BUILD_DIR := deb/build
DEB_PKG_DIR := $(DEB_BUILD_DIR)/$(PKG_NAME)-$(VERSION)

# Build Debian package
deb:
	@echo "Building Debian package..."
	@mkdir -p $(DEB_PKG_DIR)/DEBIAN
	@mkdir -p $(DEB_PKG_DIR)/usr/lib/python3/dist-packages
	@mkdir -p $(DEB_PKG_DIR)/usr/bin
	@mkdir -p $(DEB_PKG_DIR)/usr/share/tls-snoop
	@mkdir -p $(DEB_PKG_DIR)/lib/systemd/system
	@mkdir -p $(DEB_PKG_DIR)/etc/tls-snoop
	@mkdir -p $(DEB_PKG_DIR)/etc/logrotate.d
	# Copy Python package
	@cp -r tls_snoop $(DEB_PKG_DIR)/usr/lib/python3/dist-packages/
	# Copy BPF source
	@cp tls_snoop.c $(DEB_PKG_DIR)/usr/share/tls-snoop/
	# Create wrapper script
	@echo '#!/bin/sh' > $(DEB_PKG_DIR)/usr/bin/tls-snoop
	@echo 'exec python3 -m tls_snoop "$$@"' >> $(DEB_PKG_DIR)/usr/bin/tls-snoop
	@chmod 755 $(DEB_PKG_DIR)/usr/bin/tls-snoop
	# Copy systemd service
	@cp tls-snoop.service $(DEB_PKG_DIR)/lib/systemd/system/
	# Copy config files
	@cp tls-snoop.conf $(DEB_PKG_DIR)/etc/tls-snoop/
	@cp tls-snoop.logrotate $(DEB_PKG_DIR)/etc/logrotate.d/tls-snoop
	# Generate control file with version
	@sed 's/VERSION_PLACEHOLDER/$(VERSION)/' deb/control > $(DEB_PKG_DIR)/DEBIAN/control
	# Copy maintainer scripts
	@cp deb/postinst deb/prerm deb/postrm $(DEB_PKG_DIR)/DEBIAN/
	@chmod 755 $(DEB_PKG_DIR)/DEBIAN/postinst $(DEB_PKG_DIR)/DEBIAN/prerm $(DEB_PKG_DIR)/DEBIAN/postrm
	# Build the package
	@dpkg-deb --build $(DEB_PKG_DIR)
	@mv $(DEB_BUILD_DIR)/$(PKG_NAME)-$(VERSION).deb $(DEB_BUILD_DIR)/$(PKG_NAME)_$(VERSION)_amd64.deb
	@echo ""
	@echo "Package built: $(DEB_BUILD_DIR)/$(PKG_NAME)_$(VERSION)_amd64.deb"
	@echo "Install with: sudo dpkg -i $(DEB_BUILD_DIR)/$(PKG_NAME)_$(VERSION)_amd64.deb"

# Clean Debian package build files
deb-clean:
	rm -rf $(DEB_BUILD_DIR)
