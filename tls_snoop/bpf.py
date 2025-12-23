"""BPF program loading and management."""

from pathlib import Path
from pyroute2 import IPRoute

from bcc import BPF

# Interfaces to skip when attaching to all
SKIP_INTERFACES = {"lo"}


def load_bpf_program(ports: list[int]) -> str:
    """Load BPF program source from .c file with dynamic port filtering.

    Args:
        ports: List of destination ports to filter for TLS traffic.
    """
    # Search for the .c file in multiple locations
    module_dir = Path(__file__).parent
    search_paths = [
        module_dir / "tls_snoop.c",  # Symlink in module dir (installed package)
        module_dir.parent / "tls_snoop.c",  # Development: repo root
        Path("/usr/share/tls-snoop/tls_snoop.c"),  # System-wide installation
    ]

    bpf_file = None
    for path in search_paths:
        if path.exists():
            bpf_file = path
            break

    if bpf_file is None:
        searched = ", ".join(str(p) for p in search_paths)
        raise FileNotFoundError(f"BPF program not found. Searched: {searched}")

    source = bpf_file.read_text()

    # Generate port filter condition for both directions:
    # (dst_port == 443 || src_port == 443 || dst_port == 8443 || src_port == 8443 || ...)
    port_conditions = " || ".join(
        f"dst_port == {p} || src_port == {p}" for p in ports
    )
    source = source.replace("PORT_FILTER_CONDITION", port_conditions)

    return source


def create_bpf_filter(bpf_source: str) -> BPF:
    """Create and compile BPF program."""
    return BPF(text=bpf_source)


def get_all_interfaces() -> list[str]:
    """Get all network interfaces except loopback."""
    with IPRoute() as ipr:
        links = ipr.get_links()
        interfaces = []
        for link in links:
            name = link.get_attr("IFLA_IFNAME")
            if name and name not in SKIP_INTERFACES:
                interfaces.append(name)
        return interfaces


class TCAttachment:
    """Manage TC BPF attachment for both ingress and egress."""

    def __init__(self, bpf: BPF, interface: str):
        self.bpf = bpf
        self.interface = interface
        self.ipr = IPRoute()
        self.ifindex = self.ipr.link_lookup(ifname=interface)[0]
        self._qdisc_created = False
        self._ingress_parent = "ffff:fff2"
        self._egress_parent = "ffff:fff3"
        self._ingress_handle = ":1"
        self._egress_handle = ":2"

    def attach(self) -> None:
        """Attach BPF to TC ingress and egress."""
        fn = self.bpf.load_func("tls_filter", BPF.SCHED_CLS)

        # Add clsact qdisc (supports both ingress and egress)
        try:
            self.ipr.tc("add", "clsact", self.ifindex)
            self._qdisc_created = True
        except Exception:
            # Might already exist; we'll skip deleting it on detach
            self._qdisc_created = False

        try:
            # Attach to ingress
            self.ipr.tc(
                "add-filter",
                "bpf",
                self.ifindex,
                self._ingress_handle,
                fd=fn.fd,
                name=fn.name,
                parent=self._ingress_parent,
                classid=1,
                direct_action=True,
            )

            # Attach to egress
            self.ipr.tc(
                "add-filter",
                "bpf",
                self.ifindex,
                self._egress_handle,
                fd=fn.fd,
                name=fn.name,
                parent=self._egress_parent,
                classid=1,
                direct_action=True,
            )

        except Exception:
            # Clean up any partial attachment before bubbling up
            self.detach()
            raise

    def detach(self) -> None:
        """Remove TC attachment."""
        # Remove filters first (safe to call even if not attached)
        for parent, handle in (
            (self._ingress_parent, self._ingress_handle),
            (self._egress_parent, self._egress_handle),
        ):
            try:
                self.ipr.tc("del-filter", "bpf", self.ifindex, handle, parent=parent)
            except Exception:
                pass

        # Only remove the qdisc if we created it to avoid tearing down a pre-existing clsact
        if self._qdisc_created:
            try:
                self.ipr.tc("del", "clsact", self.ifindex)
            except Exception:
                pass

        self._qdisc_created = False

    def close(self) -> None:
        """Clean up resources."""
        self.detach()
        self.ipr.close()


class MultiTCAttachment:
    """Manage TC BPF attachment across multiple interfaces."""

    def __init__(self, bpf: BPF, interfaces: list[str] | None = None):
        """Initialize with BPF and optional interface list.

        If interfaces is None, will auto-detect all interfaces.
        """
        self.bpf = bpf
        self.auto_detect = interfaces is None
        self._attached_interfaces: set[str] = set()
        self._attachments: dict[str, TCAttachment] = {}

        if interfaces is None:
            interfaces = get_all_interfaces()
        self._initial_interfaces = interfaces

    def attach(self) -> None:
        """Attach BPF to TC on all interfaces."""
        for iface in self._initial_interfaces:
            self._attach_interface(iface)

    def _attach_interface(self, iface: str) -> bool:
        """Attach to a single interface. Returns True if newly attached."""
        if iface in self._attached_interfaces:
            return False

        tc: TCAttachment | None = None
        try:
            tc = TCAttachment(self.bpf, iface)
            tc.attach()
            self._attachments[iface] = tc
            self._attached_interfaces.add(iface)
            return True
        except Exception:
            if tc:
                try:
                    tc.close()
                except Exception:
                    pass
            return False

    def refresh(self) -> list[str]:
        """Rescan for new interfaces and attach to them.

        Returns list of newly attached interface names.
        Only works in auto-detect mode.
        """
        if not self.auto_detect:
            return []

        current_interfaces = set(get_all_interfaces())
        new_interfaces = current_interfaces - self._attached_interfaces

        newly_attached = []
        for iface in new_interfaces:
            if self._attach_interface(iface):
                newly_attached.append(iface)

        return newly_attached

    def close(self) -> None:
        """Clean up all attachments."""
        for tc in self._attachments.values():
            tc.close()
        self._attachments.clear()
        self._attached_interfaces.clear()
