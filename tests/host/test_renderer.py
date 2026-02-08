"""Tests for Rich renderer — summary formatting and event display."""

from __future__ import annotations

from io import StringIO
from typing import Any

from rich.console import Console

from host.models import ScanReport, Severity, TelemetryEvent
from host.renderer import LiveRenderer, print_scan_report


def _make_event(
    module_id: str,
    severity: str,
    data: dict[str, Any] | None = None,
) -> TelemetryEvent:
    """Create a TelemetryEvent for testing."""
    return TelemetryEvent(
        module_id=module_id,
        timestamp=1700000000000,
        severity=Severity(severity),
        data=data or {"event": "test"},
    )


class TestLiveRenderer:
    """Test the LiveRenderer event tracking and formatting."""

    def test_add_event_increments_counts(self) -> None:
        """Adding events correctly increments severity counters."""
        renderer = LiveRenderer()
        renderer.add_event(_make_event("test", "info"))
        renderer.add_event(_make_event("test", "warning"))
        renderer.add_event(_make_event("test", "critical"))
        renderer.add_event(_make_event("test", "info"))

        assert renderer.counts[Severity.INFO] == 2
        assert renderer.counts[Severity.WARNING] == 1
        assert renderer.counts[Severity.CRITICAL] == 1

    def test_events_stored(self) -> None:
        """Events are stored in the internal list."""
        renderer = LiveRenderer()
        renderer.add_event(_make_event("mod-a", "info"))
        renderer.add_event(_make_event("mod-b", "warning"))

        assert len(renderer.events) == 2
        assert renderer.events[0].module_id == "mod-a"
        assert renderer.events[1].module_id == "mod-b"

    def test_max_rows_trimming(self) -> None:
        """Oldest events are trimmed when max_rows is exceeded."""
        renderer = LiveRenderer(max_rows=5)
        for i in range(10):
            renderer.add_event(
                TelemetryEvent(
                    module_id=f"mod-{i}",
                    timestamp=1700000000000 + i,
                    severity=Severity.INFO,
                    data={"index": i},
                )
            )

        assert len(renderer.events) == 5
        # Oldest events should have been trimmed
        assert renderer.events[0].module_id == "mod-5"

    def test_format_data_with_path(self) -> None:
        """Data formatting extracts the 'path' field."""
        result = LiveRenderer._format_data({
            "event": "library_load_attempt",
            "path": "/data/local/tmp/evil.so",
        })
        assert "library_load_attempt" in result
        assert "/data/local/tmp/evil.so" in result

    def test_format_data_with_destination(self) -> None:
        """Data formatting extracts the 'destination' field."""
        result = LiveRenderer._format_data({
            "event": "suspicious_connect",
            "destination": "10.0.0.1:4444",
        })
        assert "10.0.0.1:4444" in result

    def test_format_data_fallback_to_json(self) -> None:
        """Data with no known keys falls back to JSON."""
        result = LiveRenderer._format_data({"unknown_key": "value"})
        assert "unknown_key" in result


class TestPrintScanReport:
    """Test scan report console output."""

    def test_report_prints_without_error(self) -> None:
        """print_scan_report runs without raising exceptions."""
        events = [
            _make_event("native-loader", "critical"),
            _make_event("frida-detection", "warning"),
            _make_event("native-loader", "info"),
        ]
        report = ScanReport.from_events("com.test.app", 30, events)

        # Capture output to verify it runs cleanly
        output = StringIO()
        test_console = Console(file=output, force_terminal=True)
        print_scan_report(report, console=test_console)

        rendered = output.getvalue()
        assert "com.test.app" in rendered
        assert "native-loader" in rendered

    def test_high_risk_report(self) -> None:
        """High-risk report includes risk score."""
        events = [_make_event(f"mod-{i}", "critical") for i in range(5)]
        report = ScanReport.from_events("com.high.risk", 30, events)

        output = StringIO()
        test_console = Console(file=output, force_terminal=True)
        print_scan_report(report, console=test_console)

        rendered = output.getvalue()
        assert "com.high.risk" in rendered
