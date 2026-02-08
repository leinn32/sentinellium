"""Sentinellium CLI — Click-based command interface.

Provides commands for RASP auditing workflows:
- attach: Interactive live monitoring with Rich TUI
- scan: Timed scan with JSON report output
- devices: List available Frida devices
- simulate: RASP policy simulation mode
- fingerprint: Identify which RASP SDK protects the target app
- diff: Compare RASP behavior across Android versions
- gadget: APK repackaging with Frida Gadget
"""

from __future__ import annotations

import signal
import sys
import threading
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from host.device import Session
from host.models import Config, PolicyAction, ScanReport, Severity, TelemetryEvent
from host.renderer import LiveRenderer, print_scan_report, save_report

console = Console()


@click.group()
@click.version_option(version="0.2.0", prog_name="sentinellium")
def cli() -> None:
    """Sentinellium — Frida-based Android/iOS RASP auditing framework.

    Instruments mobile applications to audit Runtime Application
    Self-Protection (RASP) implementations. Monitors native library
    loading, Frida/jailbreak detection surfaces, JNI/ObjC transitions,
    code integrity, and network behavior.
    """


@cli.command()
@click.argument("package_name")
@click.option("--spawn", is_flag=True, help="Spawn the app instead of attaching to a running process.")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), help="Path to YAML config file.")
@click.option("--ebpf", is_flag=True, help="Enable eBPF kernel probes (requires root).")
def attach(package_name: str, spawn: bool, config_path: Path | None, ebpf: bool) -> None:
    """Attach to a running app and display live telemetry.

    PACKAGE_NAME is the Android package name (e.g., com.example.app).

    Events are displayed in a live-updating Rich table color-coded by
    severity. Press Ctrl+C to detach and see a summary.
    """
    config = _load_config(config_path)
    renderer = LiveRenderer(console=console)

    # eBPF setup (optional)
    ebpf_probe_set = None
    ebpf_consumer = None
    ebpf_correlator = None

    if ebpf:
        ebpf_probe_set, ebpf_consumer, ebpf_correlator = _setup_ebpf(renderer)

    def event_handler(event: TelemetryEvent) -> None:
        renderer.add_event(event)
        if ebpf_correlator is not None:
            ebpf_correlator.on_frida_event(event)

    session = Session(
        package_name=package_name,
        config=config,
        on_event=event_handler,
        spawn=spawn,
    )

    console.print(f"[cyan]Attaching to {package_name}...[/cyan]")

    try:
        session.attach()

        if ebpf_probe_set is not None:
            try:
                import frida
                pid = session._pid or 0
                ebpf_probe_set.target_pid = pid
                ebpf_probe_set.attach()
                if ebpf_consumer is not None:
                    ebpf_consumer.start()
                if ebpf_correlator is not None:
                    ebpf_correlator.start()
                console.print("[green]eBPF probes attached.[/green]")
            except Exception as exc:
                console.print(f"[yellow]eBPF setup failed: {exc}[/yellow]")

        console.print("[green]Attached. Monitoring telemetry. Press Ctrl+C to detach.[/green]")

        with renderer.start():
            stop_event = threading.Event()

            def handle_sigint(signum: int, frame: object) -> None:
                stop_event.set()

            signal.signal(signal.SIGINT, handle_sigint)
            stop_event.wait()

    except KeyboardInterrupt:
        pass
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)
    finally:
        console.print("[cyan]Detaching...[/cyan]")
        if ebpf_consumer is not None:
            ebpf_consumer.stop()
        if ebpf_correlator is not None:
            ebpf_correlator.stop()
        if ebpf_probe_set is not None:
            ebpf_probe_set.detach()
        session.detach()
        renderer.print_summary()


@cli.command()
@click.argument("package_name")
@click.option("--duration", default=30, type=int, help="Scan duration in seconds.")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), help="Path to YAML config file.")
@click.option("--output", "output_path", type=click.Path(path_type=Path), help="Output path for JSON report.")
@click.option("--spawn", is_flag=True, help="Spawn the app instead of attaching to a running process.")
def scan(
    package_name: str,
    duration: int,
    config_path: Path | None,
    output_path: Path | None,
    spawn: bool,
) -> None:
    """Run a timed scan and generate a risk report.

    Attaches to PACKAGE_NAME, collects telemetry for --duration seconds,
    computes a risk score, and outputs a JSON report.
    """
    config = _load_config(config_path)
    collected_events: list[TelemetryEvent] = []
    lock = threading.Lock()

    def collect_event(event: TelemetryEvent) -> None:
        with lock:
            collected_events.append(event)

    session = Session(
        package_name=package_name,
        config=config,
        on_event=collect_event,
        spawn=spawn,
    )

    console.print(f"[cyan]Scanning {package_name} for {duration}s...[/cyan]")

    try:
        session.attach()
        console.print("[green]Attached. Collecting telemetry...[/green]")
        time.sleep(duration)

    except KeyboardInterrupt:
        console.print("[yellow]Scan interrupted early.[/yellow]")
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)
    finally:
        session.detach()

    with lock:
        events_copy = list(collected_events)

    report = ScanReport.from_events(
        target=package_name,
        duration=duration,
        events=events_copy,
    )

    # Print RASP fingerprint prominently if detected
    _print_fingerprint_result(events_copy)

    print_scan_report(report, console=console)

    if output_path is not None:
        save_report(report, output_path)
        console.print(f"[green]Report saved to {output_path}[/green]")


@cli.command()
def devices() -> None:
    """List available Frida devices."""
    from host.device import DeviceManager

    device_list = DeviceManager.enumerate_devices()

    table = Table(title="Frida Devices")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Type", style="green")

    for device in device_list:
        table.add_row(device.id, device.name, device.type)

    console.print(table)


@cli.command()
@click.argument("package_name")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True, help="Path to RASP policy YAML config.")
@click.option("--spawn", is_flag=True, help="Spawn the app instead of attaching to a running process.")
def simulate(package_name: str, config_path: Path, spawn: bool) -> None:
    """Simulate RASP policy responses to detected threats.

    Attaches to PACKAGE_NAME and applies the policy from the config file.
    When a telemetry event matches a severity with action "detach", the
    session is terminated — simulating how a RASP SDK would kill the app.
    """
    config = _load_config(config_path)
    renderer = LiveRenderer(console=console)
    detach_requested = threading.Event()
    detach_reason: list[str] = []

    def policy_handler(event: TelemetryEvent) -> None:
        renderer.add_event(event)
        action = _get_policy_action(config.policy, event.severity)
        if action == PolicyAction.DETACH:
            detach_reason.append(
                f"RASP RESPONSE: Session terminated due to "
                f"[{event.module_id}] detection "
                f"(severity={event.severity.value})"
            )
            detach_requested.set()

    session = Session(
        package_name=package_name,
        config=config,
        on_event=policy_handler,
        spawn=spawn,
    )

    console.print(f"[cyan]Simulate mode: attaching to {package_name}...[/cyan]")
    console.print(f"[dim]Policy: critical={config.policy.critical.value}, "
                  f"warning={config.policy.warning.value}, "
                  f"info={config.policy.info.value}[/dim]")

    try:
        session.attach()
        console.print("[green]Attached. RASP simulation active.[/green]")

        with renderer.start():
            stop = threading.Event()

            def handle_sigint(signum: int, frame: object) -> None:
                stop.set()

            signal.signal(signal.SIGINT, handle_sigint)

            while not stop.is_set() and not detach_requested.is_set():
                stop.wait(timeout=0.5)

    except KeyboardInterrupt:
        pass
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)
    finally:
        session.detach()
        if detach_reason:
            console.print()
            for reason in detach_reason:
                console.print(f"[red bold]{reason}[/red bold]")
        renderer.print_summary()


@cli.command()
@click.argument("package_name")
@click.option("--duration", default=10, type=int, help="Fingerprint scan duration in seconds.")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), help="Path to YAML config file.")
@click.option("--spawn", is_flag=True, help="Spawn the app.")
def fingerprint(package_name: str, duration: int, config_path: Path | None, spawn: bool) -> None:
    """Identify which RASP SDK protects the target app.

    Attaches briefly to PACKAGE_NAME, runs the RASP fingerprinting module,
    and reports which SDK is detected with a confidence score.
    """
    config = _load_config(config_path)

    # Load RASP signatures and inject into the fingerprint module config
    _inject_rasp_signatures(config)

    collected_events: list[TelemetryEvent] = []
    lock = threading.Lock()

    def collect_event(event: TelemetryEvent) -> None:
        with lock:
            collected_events.append(event)

    session = Session(
        package_name=package_name,
        config=config,
        on_event=collect_event,
        spawn=spawn,
    )

    console.print(f"[cyan]Fingerprinting {package_name}...[/cyan]")

    try:
        session.attach()
        time.sleep(duration)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)
    finally:
        session.detach()

    with lock:
        _print_fingerprint_result(collected_events)


@cli.command("diff")
@click.argument("package_name")
@click.option("--devices", "device_ids", required=True, help="Comma-separated Frida device IDs.")
@click.option("--duration", default=30, type=int, help="Scan duration per device.")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), help="Path to YAML config file.")
@click.option("--output", "output_path", type=click.Path(path_type=Path), help="Output path for diff report JSON.")
def diff(
    package_name: str,
    device_ids: str,
    duration: int,
    config_path: Path | None,
    output_path: Path | None,
) -> None:
    """Compare RASP behavior across multiple Android versions.

    Runs parallel scans on the specified devices and produces a comparison
    matrix showing where detection capabilities vary.
    """
    from host.differential import print_diff_table, run_differential_analysis

    config = _load_config(config_path)
    ids = [d.strip() for d in device_ids.split(",") if d.strip()]

    if len(ids) < 2:
        console.print("[red]At least 2 device IDs required for differential analysis.[/red]")
        sys.exit(1)

    console.print(f"[cyan]Differential analysis: {package_name}[/cyan]")
    console.print(f"[dim]Devices: {', '.join(ids)} | Duration: {duration}s each[/dim]")

    result = run_differential_analysis(
        package_name=package_name,
        device_ids=ids,
        config=config,
        duration=duration,
        console=console,
    )

    print_diff_table(result, console=console)

    if output_path is not None:
        result.save(output_path)
        console.print(f"[green]Diff report saved to {output_path}[/green]")


# ── Gadget subgroup ──────────────────────────────────────────

@cli.group()
def gadget() -> None:
    """APK repackaging with Frida Gadget for RASP-protected apps."""


@gadget.command("patch")
@click.argument("input_apk", type=click.Path(exists=True, path_type=Path))
@click.option("--arch", type=click.Choice(["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]), help="Target ABI.")
@click.option("--gadget-lib", type=click.Path(exists=True, path_type=Path), required=True, help="Path to Frida Gadget .so file.")
@click.option("--gadget-mode", type=click.Choice(["script", "listen"]), default="script", help="Gadget interaction mode.")
@click.option("--output", "output_apk", type=click.Path(path_type=Path), help="Output path for patched APK.")
def gadget_patch(
    input_apk: Path,
    arch: str | None,
    gadget_lib: Path,
    gadget_mode: str,
    output_apk: Path | None,
) -> None:
    """Repackage an APK with Frida Gadget embedded.

    INPUT_APK is the path to the original APK file.
    """
    from gadget.patcher import ApkPatcher

    patcher = ApkPatcher(
        input_apk=input_apk,
        gadget_lib=gadget_lib,
        arch=arch,
        gadget_mode=gadget_mode,  # type: ignore[arg-type]
        output_apk=output_apk,
    )

    console.print(f"[cyan]Patching {input_apk.name}...[/cyan]")

    try:
        result = patcher.patch()
        console.print(f"[green]Patched APK: {result}[/green]")
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Patching failed: {exc}[/red]")
        sys.exit(1)


@gadget.command("run")
@click.argument("patched_apk", type=click.Path(exists=True, path_type=Path))
@click.argument("package_name")
@click.option("--gadget-mode", type=click.Choice(["script", "listen"]), default="script")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), help="Path to YAML config file.")
def gadget_run(
    patched_apk: Path,
    package_name: str,
    gadget_mode: str,
    config_path: Path | None,
) -> None:
    """Install patched APK, push agent script, and launch.

    Installs the PATCHED_APK, pushes the agent script (in script mode),
    launches the app, and connects the host renderer.
    """
    import subprocess

    config = _load_config(config_path)

    console.print(f"[cyan]Installing {patched_apk.name}...[/cyan]")
    subprocess.run(["adb", "install", "-r", str(patched_apk)], check=True)

    if gadget_mode == "script":
        agent_path = Path(__file__).parent.parent / "agent" / "_agent.js"
        if agent_path.exists():
            console.print("[cyan]Pushing agent script...[/cyan]")
            subprocess.run(
                ["adb", "push", str(agent_path), "/data/local/tmp/sentinellium-agent.js"],
                check=True,
            )
        else:
            console.print("[yellow]Agent script not found. Build with 'cd agent && npm run build'[/yellow]")

    console.print(f"[cyan]Launching {package_name}...[/cyan]")
    subprocess.run(
        ["adb", "shell", "monkey", "-p", package_name, "-c",
         "android.intent.category.LAUNCHER", "1"],
        check=True, capture_output=True,
    )

    if gadget_mode == "listen":
        console.print("[green]App launched. Connect with: frida -H 127.0.0.1:27043[/green]")
    else:
        console.print("[green]App launched with embedded agent.[/green]")

    # In listen mode, attach the host renderer
    if gadget_mode == "listen":
        time.sleep(3)
        renderer = LiveRenderer(console=console)
        session = Session(
            package_name=package_name,
            config=config,
            on_event=renderer.add_event,
            spawn=False,
        )
        try:
            session.attach()
            with renderer.start():
                stop = threading.Event()
                signal.signal(signal.SIGINT, lambda s, f: stop.set())
                stop.wait()
        except KeyboardInterrupt:
            pass
        finally:
            session.detach()
            renderer.print_summary()


# ── Helper functions ─────────────────────────────────────────

def _load_config(config_path: Path | None) -> Config:
    """Load configuration from a file or use defaults."""
    if config_path is not None:
        return Config.from_yaml(config_path)
    return Config.default()


def _get_policy_action(policy: object, severity: Severity) -> PolicyAction:
    """Get the policy action for a given severity level."""
    from host.models import RaspPolicy

    if not isinstance(policy, RaspPolicy):
        return PolicyAction.LOG

    if severity == Severity.CRITICAL:
        return policy.critical
    elif severity == Severity.WARNING:
        return policy.warning
    else:
        return policy.info


def _inject_rasp_signatures(config: Config) -> None:
    """Load RASP signatures YAML and inject into the fingerprint module config."""
    import yaml

    sig_path = Path(__file__).parent.parent / "config" / "rasp-signatures.yaml"
    if sig_path.exists():
        raw = yaml.safe_load(sig_path.read_text(encoding="utf-8"))
        sigs = raw.get("signatures", {})

        if "rasp-fingerprint" not in config.modules:
            config.modules["rasp-fingerprint"] = {"enabled": True}
        config.modules["rasp-fingerprint"]["signatures"] = sigs


def _print_fingerprint_result(events: list[TelemetryEvent]) -> None:
    """Print RASP fingerprint result prominently if found in events."""
    for event in events:
        if event.module_id != "rasp-fingerprint":
            continue

        evt_type = event.data.get("event", "")
        if evt_type == "rasp_identified":
            sdk_name = event.data.get("detected_sdk_name", "Unknown")
            confidence = event.data.get("confidence", 0)
            console.print()
            console.print(
                f"[bold blue]RASP SDK Detected:[/bold blue] "
                f"[bold]{sdk_name}[/bold] "
                f"[dim](confidence: {confidence}%)[/dim]"
            )
            indicators = event.data.get("matched_indicators", [])
            if indicators:
                for ind in indicators[:5]:
                    console.print(f"  [dim]- {ind}[/dim]")
            console.print()
            return

        elif evt_type == "rasp_unknown":
            console.print()
            console.print(
                "[bold yellow]RASP SDK Detected:[/bold yellow] "
                "[bold]Unknown/Custom[/bold]"
            )
            console.print(f"  [dim]{event.data.get('detail', '')}[/dim]")
            console.print()
            return

        elif evt_type == "no_rasp_detected":
            console.print()
            console.print("[dim]No RASP SDK detected.[/dim]")
            console.print()
            return


def _setup_ebpf(
    renderer: LiveRenderer,
) -> tuple:
    """Set up eBPF probes, consumer, and correlator.

    Returns (probe_set, consumer, correlator) or (None, None, None) on failure.
    """
    try:
        from ebpf.correlator import EventCorrelator
        from ebpf.loader import ProbeSet, check_compatibility
        from ebpf.ring_buffer import RingBufferConsumer
    except ImportError:
        console.print(
            "[yellow]eBPF support not available. Install with: "
            "pip install 'sentinellium[ebpf]'[/yellow]"
        )
        return None, None, None

    compatible, reason = check_compatibility()
    if not compatible:
        console.print(f"[red]eBPF: {reason}[/red]")
        return None, None, None

    # Create correlator that feeds into the renderer
    correlator = EventCorrelator(on_event=renderer.add_event)

    # Create probe set (PID will be set after attach)
    probe_set = ProbeSet(target_pid=0)

    # Consumer converts eBPF events to TelemetryEvents
    def ebpf_event_handler(event: TelemetryEvent) -> None:
        renderer.add_event(event)
        correlator.on_ebpf_event(event)

    consumer = RingBufferConsumer(
        probes={},  # Will be populated after probe_set.attach()
        on_event=ebpf_event_handler,
    )

    return probe_set, consumer, correlator


if __name__ == "__main__":
    cli()
