"""Event correlator — cross-references eBPF and Frida events.

Maintains sliding windows of events from both sources and identifies
discrepancies:
- eBPF sees a library load that Frida missed → "stealth_lib_load" (critical)
- Frida sees a load that eBPF missed → should not happen (warning)

This correlation is the key value of the eBPF extension: it validates
Frida's coverage and identifies blind spots in userspace instrumentation.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable

from host.models import Severity, TelemetryEvent

# Sliding window size in seconds
CORRELATION_WINDOW = 5.0

# Minimum time to wait before declaring a missed event (seconds)
MISS_THRESHOLD = 2.0


class EventCorrelator:
    """Cross-references eBPF kernel events with Frida agent events.

    Maintains two sliding windows and periodically checks for events
    that appear in one source but not the other.

    Args:
        on_event: Callback for correlation findings (TelemetryEvent).
    """

    def __init__(self, on_event: Callable[[TelemetryEvent], None]) -> None:
        self._on_event: Callable[[TelemetryEvent], None] = on_event
        self._ebpf_loads: deque[tuple[float, str]] = deque()
        self._frida_loads: deque[tuple[float, str]] = deque()
        self._lock: threading.Lock = threading.Lock()
        self._running: bool = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the correlation check thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._check_loop,
            name="correlator",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the correlation thread."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def on_ebpf_event(self, event: TelemetryEvent) -> None:
        """Process an eBPF event for correlation.

        Extracts library load events from eBPF data and adds them
        to the eBPF sliding window.
        """
        data = event.data

        # Track exec_mmap events (potential library loads)
        if data.get("event") == "exec_mmap":
            fd_path = data.get("fd_path", "")
            if fd_path and fd_path.endswith(".so"):
                with self._lock:
                    self._ebpf_loads.append((time.time(), fd_path))

        # Track file access to .so files
        if data.get("event") == "file_access":
            filename = data.get("filename", "")
            if filename.endswith(".so"):
                with self._lock:
                    self._ebpf_loads.append((time.time(), filename))

    def on_frida_event(self, event: TelemetryEvent) -> None:
        """Process a Frida agent event for correlation.

        Extracts library load events from Frida NativeLoaderMonitor data.
        """
        if event.module_id != "native-loader":
            return

        data = event.data
        if data.get("event") == "library_load_attempt":
            path = data.get("path", "")
            if path:
                with self._lock:
                    self._frida_loads.append((time.time(), path))

    def _check_loop(self) -> None:
        """Periodically check for uncorrelated events."""
        while self._running:
            time.sleep(MISS_THRESHOLD)
            self._correlate()

    def _correlate(self) -> None:
        """Run one correlation pass.

        Compare events in the eBPF window against the Frida window.
        Events older than CORRELATION_WINDOW are expired from both deques.
        """
        now = time.time()
        cutoff = now - CORRELATION_WINDOW
        check_cutoff = now - MISS_THRESHOLD

        with self._lock:
            # Expire old events
            while self._ebpf_loads and self._ebpf_loads[0][0] < cutoff:
                self._ebpf_loads.popleft()
            while self._frida_loads and self._frida_loads[0][0] < cutoff:
                self._frida_loads.popleft()

            # Build sets of library paths for comparison
            # Only check events old enough to have had time for correlation
            ebpf_paths: set[str] = set()
            for ts, path in self._ebpf_loads:
                if ts < check_cutoff:
                    ebpf_paths.add(self._normalize_path(path))

            frida_paths: set[str] = set()
            for ts, path in self._frida_loads:
                if ts < check_cutoff:
                    frida_paths.add(self._normalize_path(path))

        # Find eBPF-only loads (stealth loads that Frida missed)
        stealth_loads = ebpf_paths - frida_paths
        for path in stealth_loads:
            if self._is_interesting_load(path):
                self._on_event(TelemetryEvent(
                    type="telemetry",
                    module_id="ebpf-correlator",
                    timestamp=int(time.time() * 1000),
                    severity=Severity.CRITICAL,
                    data={
                        "event": "stealth_lib_load",
                        "path": path,
                        "detail": (
                            "Library load detected by eBPF but NOT by Frida agent. "
                            "The app may be loading code through a path that bypasses "
                            "dlopen/android_dlopen_ext, evading userspace hooks."
                        ),
                        "source": "correlator",
                    },
                ))

        # Find Frida-only loads (should not normally happen — kernel sees all)
        frida_only = frida_paths - ebpf_paths
        for path in frida_only:
            if self._is_interesting_load(path):
                self._on_event(TelemetryEvent(
                    type="telemetry",
                    module_id="ebpf-correlator",
                    timestamp=int(time.time() * 1000),
                    severity=Severity.WARNING,
                    data={
                        "event": "frida_only_load",
                        "path": path,
                        "detail": (
                            "Library load seen by Frida but not by eBPF. "
                            "This is unexpected and may indicate a timing issue "
                            "or eBPF probe misconfiguration."
                        ),
                        "source": "correlator",
                    },
                ))

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize a library path for comparison.

        eBPF and Frida may report slightly different path formats
        (e.g., with/without trailing null bytes, symlink resolution).
        """
        return path.strip().rstrip("\x00").lower()

    @staticmethod
    def _is_interesting_load(path: str) -> bool:
        """Filter out uninteresting system library loads.

        We only care about discrepancies in non-system libraries.
        System libs load predictably and differences are noise.
        """
        if not path:
            return False

        # Skip common system libraries that generate false positives
        boring_prefixes = [
            "/system/lib",
            "/apex/",
            "/vendor/lib",
        ]
        for prefix in boring_prefixes:
            if path.startswith(prefix):
                return False

        return True
