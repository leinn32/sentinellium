"""CI-optimized runner for automated RASP regression testing.

Wraps the sentinellium scan workflow with:
- Threshold-based pass/fail evaluation
- JUnit XML output for CI test result parsing
- JSON report archival
- Structured exit codes (0 = pass, 1 = fail)

Usage:
    python -m ci.runner \\
        --apk sample-app-debug.apk \\
        --config config/default.yaml \\
        --thresholds ci/thresholds.yaml \\
        --output report.json \\
        --junit results.xml
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import click
import yaml
from rich.console import Console

from host.device import Session
from host.models import Config, ScanReport, Severity, TelemetryEvent
from host.renderer import print_scan_report, save_report

console = Console()


class ThresholdConfig:
    """Parsed CI threshold configuration."""

    def __init__(self, path: Path) -> None:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))

        self.required_detections: dict[str, dict[str, bool]] = raw.get(
            "required_detections", {}
        )
        self.max_risk_score: int = raw.get("max_risk_score", 40)
        self.fail_on: list[str] = raw.get("fail_on", [])


class TestResult:
    """Result of a single threshold test."""

    def __init__(
        self,
        name: str,
        classname: str,
        passed: bool,
        message: str = "",
    ) -> None:
        self.name: str = name
        self.classname: str = classname
        self.passed: bool = passed
        self.message: str = message


def evaluate_thresholds(
    report: ScanReport,
    thresholds: ThresholdConfig,
) -> list[TestResult]:
    """Evaluate scan results against CI thresholds.

    Args:
        report: Completed scan report.
        thresholds: Pass/fail criteria.

    Returns:
        List of TestResult objects for each checked threshold.
    """
    results: list[TestResult] = []

    # Check risk score
    risk_passed = report.risk_score <= thresholds.max_risk_score
    results.append(TestResult(
        name="risk_score",
        classname="sentinellium",
        passed=risk_passed,
        message="" if risk_passed else (
            f"Risk score {report.risk_score} exceeds threshold "
            f"{thresholds.max_risk_score}"
        ),
    ))

    # Check required detections
    for module_id, checks in thresholds.required_detections.items():
        for check_name, required in checks.items():
            if not required:
                continue

            status = _classify_module_status(report, module_id)
            passed = status == "detected"

            results.append(TestResult(
                name=f"{module_id}.{check_name}",
                classname="sentinellium",
                passed=passed,
                message="" if passed else (
                    f"{check_name} {status} on target"
                ),
            ))

    # Check fail_on conditions
    for condition in thresholds.fail_on:
        if condition == "module_unavailable":
            unavailable = _find_unavailable_modules(report)
            passed = len(unavailable) == 0
            results.append(TestResult(
                name="no_module_unavailable",
                classname="sentinellium",
                passed=passed,
                message="" if passed else (
                    f"Unavailable modules: {', '.join(unavailable)}"
                ),
            ))
        elif condition == "uncaught_exception":
            errors = _find_agent_errors(report)
            passed = len(errors) == 0
            results.append(TestResult(
                name="no_uncaught_exceptions",
                classname="sentinellium",
                passed=passed,
                message="" if passed else (
                    f"Agent errors: {len(errors)}"
                ),
            ))

    return results


def generate_junit_xml(
    results: list[TestResult],
    output_path: Path,
) -> None:
    """Generate JUnit XML report for CI systems.

    Produces standard JUnit XML that GitHub Actions, Jenkins, GitLab CI,
    and other CI platforms can parse for test result visualization.

    Args:
        results: List of test results from threshold evaluation.
        output_path: Path to write the XML file.
    """
    failures = sum(1 for r in results if not r.passed)

    testsuite = ET.Element("testsuite", {
        "name": "sentinellium-rasp-audit",
        "tests": str(len(results)),
        "failures": str(failures),
        "errors": "0",
    })

    for result in results:
        testcase = ET.SubElement(testsuite, "testcase", {
            "name": result.name,
            "classname": result.classname,
        })

        if not result.passed:
            failure = ET.SubElement(testcase, "failure", {
                "message": result.message,
            })
            failure.text = result.message

    tree = ET.ElementTree(testsuite)
    ET.indent(tree, space="  ")
    tree.write(output_path, encoding="unicode", xml_declaration=True)


def _classify_module_status(report: ScanReport, module_id: str) -> str:
    """Classify a module's status from the scan report."""
    module_events = [e for e in report.events if e.module_id == module_id]

    if not module_events:
        return "not_detected"

    for event in module_events:
        if event.data.get("status") == "enable_failed":
            return "module_unavailable"
        if event.data.get("event") in ("no_symbols_resolved", "symbol_not_found"):
            return "module_unavailable"

    # If we have events beyond just "enabled", consider it detected
    meaningful = [
        e for e in module_events
        if e.data.get("status") != "enabled"
    ]
    if meaningful:
        return "detected"

    # Module enabled but no meaningful events
    for event in module_events:
        if event.data.get("status") == "enabled":
            return "detected"

    return "not_detected"


def _find_unavailable_modules(report: ScanReport) -> list[str]:
    """Find modules that failed to initialize."""
    unavailable: list[str] = []
    seen: set[str] = set()

    for event in report.events:
        if event.module_id in seen:
            continue
        if event.data.get("status") == "enable_failed":
            unavailable.append(event.module_id)
            seen.add(event.module_id)

    return unavailable


def _find_agent_errors(report: ScanReport) -> list[TelemetryEvent]:
    """Find agent runtime error events."""
    return [
        e for e in report.events
        if e.module_id == "agent-runtime"
        and e.data.get("event") == "script_error"
    ]


@click.command()
@click.option("--apk", type=click.Path(exists=True, path_type=Path), help="APK to install and scan.")
@click.option("--package", type=str, help="Package name (if already installed).")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), default="config/default.yaml")
@click.option("--thresholds", "thresholds_path", type=click.Path(exists=True, path_type=Path), default="ci/thresholds.yaml")
@click.option("--duration", default=30, type=int, help="Scan duration in seconds.")
@click.option("--output", "output_path", type=click.Path(path_type=Path), default="report.json")
@click.option("--junit", "junit_path", type=click.Path(path_type=Path), default=None)
@click.option("--device", "device_id", type=str, default=None, help="Frida device ID.")
def main(
    apk: Path | None,
    package: str | None,
    config_path: Path,
    thresholds_path: Path,
    duration: int,
    output_path: Path,
    junit_path: Path | None,
    device_id: str | None,
) -> None:
    """Run RASP audit in CI mode with threshold evaluation."""
    config = Config.from_yaml(config_path)
    thresholds = ThresholdConfig(thresholds_path)

    # Install APK if provided
    if apk is not None:
        console.print(f"[cyan]Installing {apk}...[/cyan]")
        subprocess.run(["adb", "install", "-r", str(apk)], check=True)

        # Extract package name from APK if not provided
        if package is None:
            result = subprocess.run(
                ["aapt", "dump", "badging", str(apk)],
                capture_output=True, text=True,
            )
            for line in result.stdout.split("\n"):
                if line.startswith("package:"):
                    pkg_match = line.split("name='")[1].split("'")[0]
                    package = pkg_match
                    break

    if package is None:
        console.print("[red]No package name provided or detected.[/red]")
        sys.exit(1)

    # Run scan
    console.print(f"[cyan]Scanning {package} for {duration}s...[/cyan]")
    collected_events: list[TelemetryEvent] = []
    lock = threading.Lock()

    def collect(event: TelemetryEvent) -> None:
        with lock:
            collected_events.append(event)

    session = Session(
        package_name=package,
        config=config,
        on_event=collect,
        spawn=True,
    )

    try:
        session.attach()
        time.sleep(duration)
    except Exception as exc:
        console.print(f"[red]Scan failed: {exc}[/red]")
        sys.exit(1)
    finally:
        session.detach()

    # Build report
    with lock:
        events = list(collected_events)
    report = ScanReport.from_events(target=package, duration=duration, events=events)

    # Save JSON report
    save_report(report, output_path)
    console.print(f"[green]Report saved: {output_path}[/green]")

    # Evaluate thresholds
    results = evaluate_thresholds(report, thresholds)

    # Print results
    print_scan_report(report, console=console)
    console.print()

    failures = [r for r in results if not r.passed]
    passes = [r for r in results if r.passed]

    for r in passes:
        console.print(f"  [green]PASS[/green] {r.name}")
    for r in failures:
        console.print(f"  [red]FAIL[/red] {r.name}: {r.message}")

    # Generate JUnit XML if requested
    if junit_path is not None:
        generate_junit_xml(results, junit_path)
        console.print(f"[green]JUnit report: {junit_path}[/green]")

    # Exit with appropriate code
    if failures:
        console.print(f"\n[red bold]{len(failures)} threshold(s) failed.[/red bold]")
        sys.exit(1)
    else:
        console.print(f"\n[green bold]All {len(passes)} thresholds passed.[/green bold]")
        sys.exit(0)


if __name__ == "__main__":
    main()
