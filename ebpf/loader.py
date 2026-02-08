"""eBPF probe loader — loads and attaches BPF programs to kernel tracepoints.

Uses BCC (BPF Compiler Collection) Python bindings to compile and load
the eBPF probes at runtime. Handles PID filtering configuration and
provides a clean attach/detach lifecycle.

Requires:
- Root access (eBPF programs need CAP_SYS_ADMIN or CAP_BPF)
- Kernel >= 5.8 (for ring buffer support)
- /sys/kernel/btf/vmlinux (for CO-RE type information)
- BCC Python bindings (pip install bcc)
"""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Any

# BCC is an optional dependency — import with fallback
try:
    from bcc import BPF

    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False


# Path to the eBPF probe source files
PROBES_DIR = Path(__file__).parent / "probes"

# Minimum kernel version for ring buffer support
MIN_KERNEL_VERSION = (5, 8)


class EbpfError(Exception):
    """Raised when eBPF operations fail."""


def check_compatibility() -> tuple[bool, str]:
    """Verify that the system supports eBPF with ring buffers.

    Returns:
        Tuple of (compatible, reason). If not compatible, reason explains why.
    """
    # Check root
    if os.geteuid() != 0:
        return False, "eBPF probes require root. Run with sudo or as root."

    # Check kernel version
    try:
        release = platform.release()
        parts = release.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        if (major, minor) < MIN_KERNEL_VERSION:
            return False, (
                f"Kernel {release} is too old. Ring buffer requires >= 5.8. "
                f"Current: {major}.{minor}"
            )
    except (ValueError, IndexError):
        return False, f"Could not parse kernel version: {platform.release()}"

    # Check BTF availability (needed for CO-RE)
    btf_path = Path("/sys/kernel/btf/vmlinux")
    if not btf_path.exists():
        return False, (
            "BTF type information not found at /sys/kernel/btf/vmlinux. "
            "Ensure CONFIG_DEBUG_INFO_BTF=y in your kernel config."
        )

    # Check BCC availability
    if not BCC_AVAILABLE:
        return False, (
            "BCC Python bindings not installed. "
            "Install with: pip install bcc (or apt install python3-bcc)"
        )

    return True, "Compatible"


class ProbeSet:
    """Manages a set of eBPF probes attached to a target process.

    Args:
        target_pid: PID of the process to monitor.
    """

    def __init__(self, target_pid: int) -> None:
        self.target_pid: int = target_pid
        self._probes: dict[str, Any] = {}  # name → BPF object
        self._attached: bool = False

    def attach(self) -> None:
        """Compile and attach all eBPF probes.

        Raises:
            EbpfError: If probes fail to load or attach.
        """
        compatible, reason = check_compatibility()
        if not compatible:
            raise EbpfError(reason)

        probe_files = {
            "file_monitor": PROBES_DIR / "file_monitor.bpf.c",
            "lib_load": PROBES_DIR / "lib_load.bpf.c",
            "process_monitor": PROBES_DIR / "process_monitor.bpf.c",
        }

        for name, source_path in probe_files.items():
            if not source_path.exists():
                raise EbpfError(f"Probe source not found: {source_path}")

            try:
                source = source_path.read_text(encoding="utf-8")
                bpf = BPF(text=source)

                # Set the target PID in the configuration map
                pid_map = bpf["target_pid"]
                pid_map[pid_map.Key(0)] = pid_map.Leaf(self.target_pid)

                self._probes[name] = bpf

            except Exception as exc:
                # Clean up any already-loaded probes
                self.detach()
                raise EbpfError(
                    f"Failed to load probe '{name}': {exc}"
                ) from exc

        self._attached = True

    def detach(self) -> None:
        """Detach and clean up all eBPF probes."""
        for name, bpf in self._probes.items():
            try:
                bpf.cleanup()
            except Exception:
                pass  # Best-effort cleanup
        self._probes.clear()
        self._attached = False

    @property
    def is_attached(self) -> bool:
        return self._attached

    def get_ring_buffers(self) -> dict[str, Any]:
        """Get ring buffer references for each probe.

        Returns:
            Dict mapping probe name to its 'events' ring buffer.
        """
        buffers: dict[str, Any] = {}
        for name, bpf in self._probes.items():
            try:
                buffers[name] = bpf["events"]
            except KeyError:
                pass
        return buffers

    def get_probe(self, name: str) -> Any:
        """Get a specific BPF probe object by name."""
        return self._probes.get(name)
