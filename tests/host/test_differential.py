"""Tests for differential analysis — DiffResult computation and finding generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from host.differential import (
    DeviceInfo,
    DiffResult,
    MODULE_CAPABILITIES,
    VERSION_NOTES,
)
from host.models import ScanReport, Severity, TelemetryEvent


def _make_event(
    module_id: str,
    severity: str = "info",
    data: dict[str, Any] | None = None,
) -> TelemetryEvent:
    """Create a minimal TelemetryEvent for testing."""
    return TelemetryEvent(
        module_id=module_id,
        timestamp=1700000000000,
        severity=Severity(severity),
        data=data or {"event": "test"},
    )


def _make_device(device_id: str, api_level: int, name: str = "") -> DeviceInfo:
    """Create a DeviceInfo for testing."""
    return DeviceInfo(
        device_id=device_id,
        name=name or f"device-{api_level}",
        android_version=str(api_level - 20),  # rough mapping
        api_level=api_level,
    )


class TestDeviceInfo:
    """Test DeviceInfo data class."""

    def test_to_dict(self) -> None:
        dev = DeviceInfo("emu-1", "Pixel 7", "14", 34)
        d = dev.to_dict()
        assert d["id"] == "emu-1"
        assert d["name"] == "Pixel 7"
        assert d["android_version"] == "14"
        assert d["api_level"] == 34


class TestDiffResultComputation:
    """Test DiffResult._compute_diff classification logic."""

    def test_empty_reports_all_scan_failed(self) -> None:
        """Devices with no report get scan_failed status."""
        devices = [_make_device("d1", 33), _make_device("d2", 34)]
        diff = DiffResult(target="com.test", devices=devices, reports={})

        for module_id, caps in diff.diff_matrix.items():
            for cap, results in caps.items():
                assert results["d1"] == "scan_failed"
                assert results["d2"] == "scan_failed"

    def test_module_with_events_classified_detected(self) -> None:
        """Module that emits meaningful events is classified as detected."""
        devices = [_make_device("d1", 33)]
        events = [
            _make_event("native-loader", "info", {"status": "enabled"}),
            _make_event("native-loader", "warning", {"event": "suspicious_library_load"}),
        ]
        report = ScanReport.from_events("com.test", 30, events)

        diff = DiffResult(target="com.test", devices=devices, reports={"d1": report})
        assert diff.diff_matrix["native-loader"]["dlopen_ext_hook"]["d1"] == "detected"

    def test_module_enable_failed_classified_unavailable(self) -> None:
        """Module with enable_failed status is classified as module_unavailable."""
        devices = [_make_device("d1", 33)]
        events = [
            _make_event("jni-tracer", "warning", {"status": "enable_failed"}),
        ]
        report = ScanReport.from_events("com.test", 30, events)

        diff = DiffResult(target="com.test", devices=devices, reports={"d1": report})
        assert diff.diff_matrix["jni-tracer"]["art_jni_call_hook"]["d1"] == "module_unavailable"

    def test_module_no_symbols_classified_unavailable(self) -> None:
        """Module with no_symbols_resolved is classified as module_unavailable."""
        devices = [_make_device("d1", 34)]
        events = [
            _make_event("jni-tracer", "warning", {"event": "no_symbols_resolved"}),
        ]
        report = ScanReport.from_events("com.test", 30, events)

        diff = DiffResult(target="com.test", devices=devices, reports={"d1": report})
        assert diff.diff_matrix["jni-tracer"]["art_jni_call_hook"]["d1"] == "module_unavailable"

    def test_module_only_enabled_classified_detected(self) -> None:
        """Module that was enabled (but no events triggered) counts as detected."""
        devices = [_make_device("d1", 33)]
        events = [
            _make_event("network-probe", "info", {"status": "enabled"}),
        ]
        report = ScanReport.from_events("com.test", 30, events)

        diff = DiffResult(target="com.test", devices=devices, reports={"d1": report})
        assert diff.diff_matrix["network-probe"]["connect_hook"]["d1"] == "detected"

    def test_module_no_events_classified_not_detected(self) -> None:
        """Module with zero events is classified as not_detected."""
        devices = [_make_device("d1", 33)]
        # Report with events only from a different module
        events = [
            _make_event("native-loader", "info", {"status": "enabled"}),
        ]
        report = ScanReport.from_events("com.test", 30, events)

        diff = DiffResult(target="com.test", devices=devices, reports={"d1": report})
        assert diff.diff_matrix["frida-detection"]["maps_scan"]["d1"] == "not_detected"

    def test_fingerprint_rasp_identified_classified_detected(self) -> None:
        """RaspFingerprinter with rasp_identified event is detected."""
        devices = [_make_device("d1", 33)]
        events = [
            _make_event("rasp-fingerprint", "info", {"event": "rasp_identified", "sdk": "wultra"}),
        ]
        report = ScanReport.from_events("com.test", 30, events)

        diff = DiffResult(target="com.test", devices=devices, reports={"d1": report})
        assert diff.diff_matrix["rasp-fingerprint"]["fingerprint_scan"]["d1"] == "detected"

    def test_fingerprint_no_rasp_classified_detected(self) -> None:
        """RaspFingerprinter with no_rasp_detected is still detected (scan completed)."""
        devices = [_make_device("d1", 33)]
        events = [
            _make_event("rasp-fingerprint", "info", {"event": "no_rasp_detected"}),
        ]
        report = ScanReport.from_events("com.test", 30, events)

        diff = DiffResult(target="com.test", devices=devices, reports={"d1": report})
        assert diff.diff_matrix["rasp-fingerprint"]["fingerprint_scan"]["d1"] == "detected"


class TestDiffResultFindings:
    """Test DiffResult._generate_findings for cross-version inconsistencies."""

    def test_no_findings_when_all_agree(self) -> None:
        """No findings generated when all devices report the same status."""
        devices = [_make_device("d1", 33), _make_device("d2", 34)]
        events1 = [_make_event("native-loader", "info", {"status": "enabled"})]
        events2 = [_make_event("native-loader", "info", {"status": "enabled"})]

        diff = DiffResult(
            target="com.test",
            devices=devices,
            reports={
                "d1": ScanReport.from_events("com.test", 30, events1),
                "d2": ScanReport.from_events("com.test", 30, events2),
            },
        )

        # Filter findings to only native-loader
        nl_findings = [f for f in diff.findings if "native-loader" in f]
        assert nl_findings == []

    def test_finding_generated_for_divergence(self) -> None:
        """Finding generated when devices disagree on a capability."""
        devices = [_make_device("d1", 33), _make_device("d2", 34)]

        # d1 has JNI events, d2 has enable_failed
        events1 = [
            _make_event("jni-tracer", "info", {"status": "enabled"}),
            _make_event("jni-tracer", "info", {"event": "symbol_resolved"}),
            _make_event("jni-tracer", "warning", {"event": "jni_call"}),
        ]
        events2 = [
            _make_event("jni-tracer", "warning", {"status": "enable_failed"}),
        ]

        diff = DiffResult(
            target="com.test",
            devices=devices,
            reports={
                "d1": ScanReport.from_events("com.test", 30, events1),
                "d2": ScanReport.from_events("com.test", 30, events2),
            },
        )

        jni_findings = [f for f in diff.findings if "jni-tracer" in f]
        assert len(jni_findings) > 0
        assert "module_unavailable" in jni_findings[0]
        assert "API 34" in jni_findings[0]

    def test_version_note_appended_to_finding(self) -> None:
        """Known version-specific notes are appended to findings."""
        devices = [_make_device("d1", 33), _make_device("d2", 34)]

        events1 = [
            _make_event("jni-tracer", "info", {"status": "enabled"}),
            _make_event("jni-tracer", "warning", {"event": "jni_call"}),
        ]
        events2 = [
            _make_event("jni-tracer", "warning", {"event": "no_symbols_resolved"}),
        ]

        diff = DiffResult(
            target="com.test",
            devices=devices,
            reports={
                "d1": ScanReport.from_events("com.test", 30, events1),
                "d2": ScanReport.from_events("com.test", 30, events2),
            },
        )

        jni_findings = [f for f in diff.findings if "jni-tracer" in f and "API 34" in f]
        assert len(jni_findings) > 0
        # Should include the version note for (34, "jni-tracer")
        assert "restricted" in jni_findings[0].lower() or "ART" in jni_findings[0]


class TestDiffResultSerialization:
    """Test DiffResult serialization to dict/JSON."""

    def test_to_dict_structure(self) -> None:
        """to_dict produces the expected structure."""
        devices = [_make_device("d1", 33)]
        events = [_make_event("native-loader", "info", {"status": "enabled"})]
        report = ScanReport.from_events("com.test", 30, events)

        diff = DiffResult(target="com.test", devices=devices, reports={"d1": report})
        d = diff.to_dict()

        assert d["target"] == "com.test"
        assert len(d["devices"]) == 1
        assert "diff_matrix" in d
        assert "findings" in d
        assert "reports" in d
        assert "d1" in d["reports"]

    def test_to_dict_is_json_serializable(self) -> None:
        """to_dict output can be serialized to JSON without errors."""
        devices = [_make_device("d1", 33)]
        diff = DiffResult(target="com.test", devices=devices, reports={})
        json_str = json.dumps(diff.to_dict(), default=str)
        parsed = json.loads(json_str)
        assert parsed["target"] == "com.test"

    def test_save_writes_json_file(self, tmp_path: Path) -> None:
        """save() writes a valid JSON file."""
        devices = [_make_device("d1", 33)]
        diff = DiffResult(target="com.test", devices=devices, reports={})

        output = tmp_path / "diff-report.json"
        diff.save(output)

        assert output.exists()
        parsed = json.loads(output.read_text(encoding="utf-8"))
        assert parsed["target"] == "com.test"
