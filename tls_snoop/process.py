"""Process lookup utilities via /proc."""

import os
from functools import lru_cache
from pathlib import Path

from .network import ipv4_to_hex, ipv6_to_hex


@lru_cache(maxsize=256)
def find_process_by_inode(inode: str) -> tuple[int, str] | None:
    """Find process by socket inode (cached)."""
    socket_link = f"socket:[{inode}]"

    try:
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue

            fd_dir = pid_dir / "fd"
            if not fd_dir.exists():
                continue

            try:
                for fd in fd_dir.iterdir():
                    try:
                        if fd.is_symlink() and os.readlink(fd) == socket_link:
                            pid = int(pid_dir.name)
                            comm_file = pid_dir / "comm"
                            proc_name = (
                                comm_file.read_text().strip()
                                if comm_file.exists()
                                else "unknown"
                            )
                            return (pid, proc_name)
                    except (PermissionError, FileNotFoundError):
                        continue
            except PermissionError:
                continue
    except Exception:
        pass

    return None


def _lookup_connection(
    proc_file: str,
    local_addr: str,
    remote_addr: str,
) -> tuple[int, str] | None:
    """Look up connection in /proc/net/tcp or tcp6."""
    try:
        with open(proc_file, "r") as f:
            lines = f.readlines()[1:]  # Skip header

        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue

            proc_local = parts[1].upper()
            proc_remote = parts[2].upper()
            inode = parts[9]

            if proc_local == local_addr and proc_remote == remote_addr:
                return find_process_by_inode(inode)

    except Exception:
        pass

    return None


def get_process_by_connection(
    local_ip: int,
    local_port: int,
    remote_ip: int,
    remote_port: int,
) -> tuple[int, str] | None:
    """Look up PID and process name for a TCP connection via /proc/net/tcp."""
    local_addr = f"{ipv4_to_hex(local_ip)}:{local_port:04X}"
    remote_addr = f"{ipv4_to_hex(remote_ip)}:{remote_port:04X}"
    return _lookup_connection("/proc/net/tcp", local_addr, remote_addr)


def get_process_by_connection6(
    local_ip6,
    local_port: int,
    remote_ip6,
    remote_port: int,
) -> tuple[int, str] | None:
    """Look up PID and process name for a TCP6 connection via /proc/net/tcp6."""
    local_addr = f"{ipv6_to_hex(local_ip6)}:{local_port:04X}"
    remote_addr = f"{ipv6_to_hex(remote_ip6)}:{remote_port:04X}"
    return _lookup_connection("/proc/net/tcp6", local_addr, remote_addr)
