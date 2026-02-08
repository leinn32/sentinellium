"""Ring buffer consumer — reads eBPF events and converts to TelemetryEvent.

Polls ring buffers from attached eBPF probes and transforms kernel-level
events into the same TelemetryEvent schema used by the Frida agent. This
allows the host's Rich renderer and report pipeline to process eBPF events
identically to agent events.
"""

from __future__ import annotations

import ctypes
import threading
import time
from typing import Any, Callable

from host.models import Severity, TelemetryEvent

# Match the C struct layouts from the BPF probes

TASK_COMM_LEN = 16
MAX_PATH_LEN = 256
MAX_ARG_LEN = 128

# Process event types (must match process_monitor.bpf.c)
EVT_EXECVE = 1
EVT_PTRACE = 2

# ptrace request constants
PTRACE_TRACEME = 0
PTRACE_ATTACH = 16


class FileEvent(ctypes.Structure):
    """Mirrors struct file_event from file_monitor.bpf.c."""

    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("flags", ctypes.c_int32),
        ("filename", ctypes.c_char * MAX_PATH_LEN),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


class LibLoadEvent(ctypes.Structure):
    """Mirrors struct lib_load_event from lib_load.bpf.c."""

    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("addr", ctypes.c_uint64),
        ("length", ctypes.c_uint64),
        ("prot", ctypes.c_int32),
        ("flags", ctypes.c_int32),
        ("fd", ctypes.c_int32),
        ("offset", ctypes.c_uint64),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


class ProcessEvent(ctypes.Structure):
    """Mirrors struct process_event from process_monitor.bpf.c."""

    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * MAX_ARG_LEN),
        ("ptrace_request", ctypes.c_int64),
        ("ptrace_target_pid", ctypes.c_int32),
    ]


class RingBufferConsumer:
    """Consumes eBPF ring buffer events and converts them to TelemetryEvents.

    Runs a polling loop in a background thread, invoking the callback for
    each event. Events are translated from their C struct representation
    into the standard TelemetryEvent schema.

    Args:
        probes: Dict of probe name → BPF object from ProbeSet.
        on_event: Callback for each converted TelemetryEvent.
    """

    def __init__(
        self,
        probes: dict[str, Any],
        on_event: Callable[[TelemetryEvent], None],
    ) -> None:
        self._probes: dict[str, Any] = probes
        self._on_event: Callable[[TelemetryEvent], None] = on_event
        self._running: bool = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the ring buffer polling thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="ebpf-ringbuf",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the polling thread."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def _poll_loop(self) -> None:
        """Main polling loop — reads events from all ring buffers."""
        # Register callbacks for each probe's ring buffer
        for name, bpf in self._probes.items():
            try:
                if name == "file_monitor":
                    bpf["events"].open_ring_buffer(self._handle_file_event)
                elif name == "lib_load":
                    bpf["events"].open_ring_buffer(self._handle_lib_load_event)
                elif name == "process_monitor":
                    bpf["events"].open_ring_buffer(self._handle_process_event)
            except Exception:
                pass

        while self._running:
            try:
                for bpf in self._probes.values():
                    bpf.ring_buffer_poll(timeout=100)
            except Exception:
                pass
            time.sleep(0.01)

    def _handle_file_event(self, cpu: int, data: Any, size: int) -> None:
        """Convert a file_monitor eBPF event to TelemetryEvent."""
        try:
            evt = ctypes.cast(data, ctypes.POINTER(FileEvent)).contents
            filename = evt.filename.decode("utf-8", errors="replace").rstrip("\x00")
            comm = evt.comm.decode("utf-8", errors="replace").rstrip("\x00")

            self._on_event(TelemetryEvent(
                type="telemetry",
                module_id="ebpf-file-monitor",
                timestamp=int(time.time() * 1000),
                severity=Severity.INFO,
                data={
                    "event": "file_access",
                    "filename": filename,
                    "flags": evt.flags,
                    "pid": evt.pid,
                    "tid": evt.tid,
                    "comm": comm,
                    "source": "ebpf",
                },
            ))
        except Exception:
            pass

    def _handle_lib_load_event(self, cpu: int, data: Any, size: int) -> None:
        """Convert a lib_load eBPF event to TelemetryEvent."""
        try:
            evt = ctypes.cast(data, ctypes.POINTER(LibLoadEvent)).contents
            comm = evt.comm.decode("utf-8", errors="replace").rstrip("\x00")

            # Try to resolve fd to a file path
            fd_path = ""
            if evt.fd >= 0:
                try:
                    link = f"/proc/{evt.pid}/fd/{evt.fd}"
                    fd_path = str(os.readlink(link))
                except Exception:
                    fd_path = f"fd:{evt.fd}"

            self._on_event(TelemetryEvent(
                type="telemetry",
                module_id="ebpf-lib-load",
                timestamp=int(time.time() * 1000),
                severity=Severity.INFO,
                data={
                    "event": "exec_mmap",
                    "address": hex(evt.addr),
                    "length": evt.length,
                    "prot": evt.prot,
                    "flags": evt.flags,
                    "fd_path": fd_path,
                    "offset": evt.offset,
                    "pid": evt.pid,
                    "tid": evt.tid,
                    "comm": comm,
                    "source": "ebpf",
                },
            ))
        except Exception:
            pass

    def _handle_process_event(self, cpu: int, data: Any, size: int) -> None:
        """Convert a process_monitor eBPF event to TelemetryEvent."""
        try:
            evt = ctypes.cast(data, ctypes.POINTER(ProcessEvent)).contents
            comm = evt.comm.decode("utf-8", errors="replace").rstrip("\x00")

            if evt.event_type == EVT_EXECVE:
                filename = evt.filename.decode("utf-8", errors="replace").rstrip("\x00")
                self._on_event(TelemetryEvent(
                    type="telemetry",
                    module_id="ebpf-process",
                    timestamp=int(time.time() * 1000),
                    severity=Severity.WARNING,
                    data={
                        "event": "execve",
                        "filename": filename,
                        "pid": evt.pid,
                        "tid": evt.tid,
                        "comm": comm,
                        "source": "ebpf",
                    },
                ))
            elif evt.event_type == EVT_PTRACE:
                severity = Severity.INFO
                detail = ""

                if evt.ptrace_request == PTRACE_TRACEME:
                    severity = Severity.WARNING
                    detail = "Anti-debug: ptrace(PTRACE_TRACEME) — process is self-tracing"
                elif evt.ptrace_request == PTRACE_ATTACH:
                    severity = Severity.WARNING
                    detail = f"ptrace(PTRACE_ATTACH) targeting PID {evt.ptrace_target_pid}"

                self._on_event(TelemetryEvent(
                    type="telemetry",
                    module_id="ebpf-process",
                    timestamp=int(time.time() * 1000),
                    severity=severity,
                    data={
                        "event": "ptrace",
                        "request": evt.ptrace_request,
                        "target_pid": evt.ptrace_target_pid,
                        "pid": evt.pid,
                        "tid": evt.tid,
                        "comm": comm,
                        "detail": detail,
                        "source": "ebpf",
                    },
                ))
        except Exception:
            pass


# Needed for fd resolution in lib_load handler
import os
