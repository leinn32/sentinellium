"""Differential analysis — compare RASP behavior across Android versions.

Runs parallel scans on multiple devices/emulators and produces a diff matrix
showing where detection capabilities vary. Directly answers: "Did our latest
ART hook break on the new Android release?"
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import frida
from rich.console import Console
from rich.table import Table
from rich.text import Text

from host.device import Session
from host.models import Config, ScanReport, Severity, TelemetryEvent

# Known version-specific notes explaining why capabilities may differ.
VERSION_NOTES: dict[tuple[int, str], str] = {
    (33, "jni-tracer"): (
        "Android 13 introduced changes to ART JNI symbol visibility. "
        "Some Call*MethodV symbols may be hidden from dynamic lookup."
    ),
    (34, "jni-tracer"): (
        "Android 14 further restricted ART internal symbol exports. "
        "JNI tracing may require alternative symbol resolution."
    ),
    (34, "integrity"): (
        "Android 14 added MTE (Memory Tagging Extension) on supported "
        "hardware, which may affect direct memory reads."
    ),
    (35, "jni-tracer"): (
        "Android 15 may have changed ART symbol mangling again. "
        "Verify symbol patterns are up to date."
    ),
    (30, "frida-detection"): (
        "Android 11 restricted /proc access for non-debuggable apps. "
        "Maps scanning may return incomplete results."
    ),
    (31, "native-loader"): (
        "Android 12 tightened linker namespace restrictions. "
        "Some library loads may be invisible to the hook."
    ),
}

# Detection capability names per module.
MODULE_CAPABILITIES: dict[str, list[str]] = {
    "native-loader": ["dlopen_ext_hook"],
    "frida-detection": ["maps_scan", "port_scan", "trampoline_scan", "thread_scan"],
    "jni-tracer": ["art_jni_call_hook"],
    "integrity": ["text_hash_baseline"],
    "network-probe": ["connect_hook"],
    "rasp-fingerprint": ["fingerprint_scan"],
}


class DeviceInfo:
    """Metadata about a device used in differential analysis."""

    def __init__(self, device_id: str, name: str, android_version: str, api_level: int) -> None:
        self.device_id: str = device_id
        self.name: str = name
        self.android_version: str = android_version
        self.api_level: int = api_level

    def to_dict(self) -> dict[str, str | int]:
        return {
            "id": self.device_id,
            "name": self.name,
            "android_version": self.android_version,
            "api_level": self.api_level,
        }


class DiffResult:
    """Result of a differential analysis across multiple devices."""

    def __init__(
        self,
        target: str,
        devices: list[DeviceInfo],
        reports: dict[str, ScanReport],
    ) -> None:
        self.target: str = target
        self.devices: list[DeviceInfo] = devices
        self.reports: dict[str, ScanReport] = reports
        self.diff_matrix: dict[str, dict[str, dict[str, str]]] = {}
        self.findings: list[str] = []

        self._compute_diff()
        self._generate_findings()

    def _compute_diff(self) -> None:
        """Build the diff matrix from collected reports.

        For each module capability, classify the result per device:
        - "detected": The module found expected behavior / emitted events
        - "not_detected": Module ran but found nothing
        - "module_unavailable": Module couldn't initialize (e.g., symbol not found)
        """
        for module_id, capabilities in MODULE_CAPABILITIES.items():
            self.diff_matrix[module_id] = {}

            for capability in capabilities:
                cap_results: dict[str, str] = {}

                for device in self.devices:
                    report = self.reports.get(device.device_id)
                    if report is None:
                        cap_results[device.device_id] = "scan_failed"
                        continue

                    cap_results[device.device_id] = self._classify_capability(
                        report, module_id, capability
                    )

                self.diff_matrix[module_id][capability] = cap_results

    def _classify_capability(
        self, report: ScanReport, module_id: str, capability: str
    ) -> str:
        """Classify a detection capability for a single device report."""
        module_events = [
            e for e in report.events if e.module_id == module_id
        ]

        if not module_events:
            return "not_detected"

        # Check for enable_failed events (module couldn't initialize)
        for event in module_events:
            status = event.data.get("status")
            if status == "enable_failed":
                return "module_unavailable"
            error_event = event.data.get("event", "")
            if error_event in ("no_symbols_resolved", "symbol_not_found", "no_baseline"):
                return "module_unavailable"

        # For fingerprint module, check if scan completed
        if capability == "fingerprint_scan":
            for event in module_events:
                if event.data.get("event") in (
                    "rasp_identified",
                    "rasp_unknown",
                    "no_rasp_detected",
                ):
                    return "detected"
            return "not_detected"

        # For hook-based modules, check if the hook was established
        # and produced at least one meaningful event beyond "enabled"
        meaningful_events = [
            e for e in module_events
            if e.data.get("status") != "enabled"
            and e.data.get("event") not in ("symbol_resolved",)
        ]

        if meaningful_events:
            return "detected"

        # Module enabled but no meaningful events — hooks are active but
        # nothing triggered during the scan
        for event in module_events:
            if event.data.get("status") == "enabled":
                return "detected"

        return "not_detected"

    def _generate_findings(self) -> None:
        """Auto-generate findings for inconsistencies across versions."""
        for module_id, capabilities in self.diff_matrix.items():
            for capability, device_results in capabilities.items():
                statuses = set(device_results.values())

                # If all devices agree, no finding needed
                if len(statuses) == 1:
                    continue

                # Find which devices diverge
                for device in self.devices:
                    status = device_results.get(device.device_id, "unknown")
                    if status in ("module_unavailable", "not_detected"):
                        # Check if we have a version-specific note
                        note_key = (device.api_level, module_id)
                        version_note = VERSION_NOTES.get(note_key, "")

                        finding = (
                            f"{module_id}.{capability}: {status} on "
                            f"{device.name} (API {device.api_level})"
                        )
                        if version_note:
                            finding += f". {version_note}"

                        self.findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        return {
            "target": self.target,
            "devices": [d.to_dict() for d in self.devices],
            "diff_matrix": self.diff_matrix,
            "findings": self.findings,
            "reports": {
                dev_id: report.model_dump()
                for dev_id, report in self.reports.items()
            },
        }

    def save(self, output_path: Path) -> None:
        """Save diff report to JSON."""
        output_path.write_text(
            json.dumps(self.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )


def get_device_info(device: frida.core.Device) -> DeviceInfo:
    """Extract device metadata including Android version and API level.

    Runs shell commands via Frida to read system properties.
    """
    android_version = "unknown"
    api_level = 0

    try:
        # Use adb-like property access through Frida
        session = device.attach("system_server")
        script = session.create_script(
            """
            rpc.exports = {
                getprop(name) {
                    const Runtime = Java.use('java.lang.Runtime');
                    const rt = Runtime.getRuntime();
                    const proc = rt.exec(['getprop', name]);
                    const is = proc.getInputStream();
                    const reader = Java.use('java.io.BufferedReader');
                    const isr = Java.use('java.io.InputStreamReader');
                    const br = reader.$new(isr.$new(is));
                    const line = br.readLine();
                    br.close();
                    return line ? line.toString() : '';
                }
            };
            """
        )
        script.load()
        android_version = script.exports_sync.getprop("ro.build.version.release")
        api_str = script.exports_sync.getprop("ro.build.version.sdk")
        api_level = int(api_str) if api_str else 0
        script.unload()
        session.detach()
    except Exception:
        # Fallback: use device name as indicator
        pass

    return DeviceInfo(
        device_id=device.id,
        name=device.name,
        android_version=str(android_version),
        api_level=api_level,
    )


def run_scan_on_device(
    device_id: str,
    package_name: str,
    config: Config,
    duration: int,
) -> tuple[str, ScanReport | None]:
    """Run a scan on a specific device. Returns (device_id, report).

    Designed to run in a ThreadPoolExecutor for parallel scanning.
    """
    import threading

    collected_events: list[TelemetryEvent] = []
    lock = threading.Lock()

    def collect_event(event: TelemetryEvent) -> None:
        with lock:
            collected_events.append(event)

    try:
        device = frida.get_device(device_id, timeout=5)
        session = Session(
            package_name=package_name,
            config=config,
            on_event=collect_event,
            spawn=False,
        )
        session._device = device
        session._session = device.attach(package_name)

        from host.device import AGENT_BUNDLE_PATH

        if not AGENT_BUNDLE_PATH.exists():
            return device_id, None

        agent_source = AGENT_BUNDLE_PATH.read_text(encoding="utf-8")
        session._script = session._session.create_script(agent_source)
        session._script.on("message", session._on_message)
        session._script.load()
        session._script.exports_sync.init(config.modules_json())

        time.sleep(duration)
        session.detach()

        with lock:
            events_copy = list(collected_events)

        report = ScanReport.from_events(
            target=package_name,
            duration=duration,
            events=events_copy,
        )
        return device_id, report

    except Exception:
        return device_id, None


def run_differential_analysis(
    package_name: str,
    device_ids: list[str],
    config: Config,
    duration: int = 30,
    console: Console | None = None,
) -> DiffResult:
    """Run parallel scans across multiple devices and produce a diff.

    Args:
        package_name: Target app package name.
        device_ids: List of Frida device IDs to scan.
        config: Sentinellium configuration.
        duration: Scan duration in seconds per device.
        console: Optional Rich console for progress output.
    """
    con = console or Console()

    # Gather device info
    devices: list[DeviceInfo] = []
    for dev_id in device_ids:
        try:
            device = frida.get_device(dev_id, timeout=5)
            info = get_device_info(device)
            devices.append(info)
            con.print(
                f"  [cyan]{info.device_id}[/cyan]: {info.name} "
                f"(Android {info.android_version}, API {info.api_level})"
            )
        except Exception as exc:
            con.print(f"  [red]{dev_id}[/red]: Failed to connect — {exc}")

    if not devices:
        con.print("[red]No devices available for scanning.[/red]")
        return DiffResult(target=package_name, devices=[], reports={})

    # Run scans in parallel
    con.print(f"\n[cyan]Scanning {package_name} on {len(devices)} devices for {duration}s...[/cyan]")
    reports: dict[str, ScanReport] = {}

    with ThreadPoolExecutor(max_workers=len(devices)) as executor:
        futures = {
            executor.submit(
                run_scan_on_device, dev.device_id, package_name, config, duration
            ): dev
            for dev in devices
        }

        for future in as_completed(futures):
            dev = futures[future]
            try:
                dev_id, report = future.result()
                if report is not None:
                    reports[dev_id] = report
                    con.print(
                        f"  [green]{dev.name}[/green]: {len(report.events)} events, "
                        f"risk={report.risk_score}"
                    )
                else:
                    con.print(f"  [red]{dev.name}[/red]: Scan failed")
            except Exception as exc:
                con.print(f"  [red]{dev.name}[/red]: Error — {exc}")

    return DiffResult(target=package_name, devices=devices, reports=reports)


def print_diff_table(diff: DiffResult, console: Console | None = None) -> None:
    """Print a Rich comparison table for the differential analysis."""
    con = console or Console()

    if not diff.devices:
        con.print("[yellow]No data to compare.[/yellow]")
        return

    table = Table(title=f"Differential Analysis — {diff.target}", expand=True)
    table.add_column("Module", style="cyan", width=20)
    table.add_column("Check", width=20)

    for device in diff.devices:
        table.add_column(
            f"API {device.api_level}",
            justify="center",
            width=10,
        )

    for module_id, capabilities in diff.diff_matrix.items():
        for capability, device_results in capabilities.items():
            row: list[str | Text] = [module_id, capability]

            for device in diff.devices:
                status = device_results.get(device.device_id, "unknown")
                if status == "detected":
                    row.append(Text("✓", style="green bold"))
                elif status == "not_detected":
                    row.append(Text("—", style="dim"))
                elif status == "module_unavailable":
                    row.append(Text("✗", style="red bold"))
                elif status == "scan_failed":
                    row.append(Text("?", style="yellow"))
                else:
                    row.append(Text(status, style="dim"))

            table.add_row(*row)

    con.print(table)

    # Print findings
    if diff.findings:
        con.print("\n[bold]Findings:[/bold]")
        for finding in diff.findings:
            con.print(f"  [yellow]•[/yellow] {finding}")
