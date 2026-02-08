"""Tests for Pydantic models — TelemetryEvent deserialization and ScanReport scoring."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from host.models import (
    Config,
    ModuleSummary,
    PolicyAction,
    RaspPolicy,
    ScanReport,
    Severity,
    TelemetryEvent,
)


class TestTelemetryEvent:
    """Test TelemetryEvent deserialization from agent payloads."""

    def test_valid_info_event(self) -> None:
        """Info-level event with minimal fields deserializes correctly."""
        raw: dict[str, Any] = {
            "type": "telemetry",
            "module_id": "native-loader",
            "timestamp": 1700000000000,
            "severity": "info",
            "data": {"event": "library_load_attempt", "path": "/system/lib64/libc.so"},
        }
        event = TelemetryEvent.model_validate(raw)
        assert event.module_id == "native-loader"
        assert event.severity == Severity.INFO
        assert event.data["path"] == "/system/lib64/libc.so"
        assert event.stacktrace is None

    def test_valid_critical_event_with_stacktrace(self) -> None:
        """Critical event with stacktrace deserializes correctly."""
        raw: dict[str, Any] = {
            "type": "telemetry",
            "module_id": "native-loader",
            "timestamp": 1700000000000,
            "severity": "critical",
            "data": {
                "event": "suspicious_library_load",
                "path": "/data/local/tmp/frida-agent.so",
                "matched_rule": "pattern:frida",
            },
            "stacktrace": "0x7f000000 libdl.so!dlopen\n0x7f100000 libart.so!Runtime",
        }
        event = TelemetryEvent.model_validate(raw)
        assert event.severity == Severity.CRITICAL
        assert event.stacktrace is not None
        assert "libdl.so" in event.stacktrace

    def test_valid_warning_event(self) -> None:
        """Warning event deserializes correctly."""
        raw: dict[str, Any] = {
            "type": "telemetry",
            "module_id": "frida-detection",
            "timestamp": 1700000000000,
            "severity": "warning",
            "data": {
                "check": "memory_maps",
                "finding": "frida_artifact_in_maps",
                "marker": "frida-agent",
            },
        }
        event = TelemetryEvent.model_validate(raw)
        assert event.severity == Severity.WARNING
        assert event.data["check"] == "memory_maps"

    def test_invalid_severity_rejected(self) -> None:
        """Invalid severity value raises a validation error."""
        raw: dict[str, Any] = {
            "type": "telemetry",
            "module_id": "test",
            "timestamp": 1700000000000,
            "severity": "debug",
            "data": {},
        }
        with pytest.raises(Exception):
            TelemetryEvent.model_validate(raw)

    def test_missing_required_field_rejected(self) -> None:
        """Missing module_id raises a validation error."""
        raw: dict[str, Any] = {
            "type": "telemetry",
            "timestamp": 1700000000000,
            "severity": "info",
            "data": {},
        }
        with pytest.raises(Exception):
            TelemetryEvent.model_validate(raw)

    def test_timestamp_str_formatting(self) -> None:
        """Timestamp string is formatted as HH:MM:SS.mmm."""
        event = TelemetryEvent(
            module_id="test",
            timestamp=1700000000123,
            severity=Severity.INFO,
            data={},
        )
        ts = event.timestamp_str
        # Should be in format HH:MM:SS.mmm
        assert len(ts) == 12
        assert ts.count(":") == 2
        assert "." in ts

    def test_extra_fields_in_data_preserved(self) -> None:
        """Arbitrary keys in the data dict are preserved."""
        raw: dict[str, Any] = {
            "type": "telemetry",
            "module_id": "integrity",
            "timestamp": 1700000000000,
            "severity": "critical",
            "data": {
                "event": "integrity_violation",
                "library": "libart.so",
                "expected_hash": "abc123",
                "actual_hash": "def456",
                "custom_field": [1, 2, 3],
            },
        }
        event = TelemetryEvent.model_validate(raw)
        assert event.data["custom_field"] == [1, 2, 3]


class TestScanReport:
    """Test ScanReport risk scoring and aggregation."""

    def _make_event(self, module_id: str, severity: str) -> TelemetryEvent:
        """Create a minimal TelemetryEvent for testing."""
        return TelemetryEvent(
            module_id=module_id,
            timestamp=1700000000000,
            severity=Severity(severity),
            data={"event": "test"},
        )

    def test_empty_scan_zero_risk(self) -> None:
        """Scan with no events has risk score 0."""
        report = ScanReport.from_events("com.test", 30, [])
        assert report.risk_score == 0
        assert report.summary_by_module == {}

    def test_info_only_zero_risk(self) -> None:
        """Scan with only info events has risk score 0."""
        events = [self._make_event("native-loader", "info") for _ in range(10)]
        report = ScanReport.from_events("com.test", 30, events)
        assert report.risk_score == 0

    def test_single_critical_scores_25(self) -> None:
        """One critical event: 15 (event) + 10 (module bonus) = 25."""
        events = [self._make_event("native-loader", "critical")]
        report = ScanReport.from_events("com.test", 30, events)
        assert report.risk_score == 25

    def test_single_warning_scores_5(self) -> None:
        """One warning event scores 5."""
        events = [self._make_event("frida-detection", "warning")]
        report = ScanReport.from_events("com.test", 30, events)
        assert report.risk_score == 5

    def test_mixed_severity_scoring(self) -> None:
        """Mixed events accumulate correctly."""
        events = [
            self._make_event("native-loader", "critical"),  # +15
            self._make_event("native-loader", "warning"),   # +5
            self._make_event("frida-detection", "warning"), # +5
            self._make_event("native-loader", "info"),      # +0
        ]
        # 15 + 5 + 5 + 0 = 25 from events
        # +10 for native-loader having criticals = 35
        report = ScanReport.from_events("com.test", 30, events)
        assert report.risk_score == 35

    def test_risk_capped_at_100(self) -> None:
        """Risk score never exceeds 100."""
        events = [self._make_event(f"mod-{i}", "critical") for i in range(20)]
        report = ScanReport.from_events("com.test", 30, events)
        assert report.risk_score == 100

    def test_module_summary_counts(self) -> None:
        """Per-module summary correctly counts events by severity."""
        events = [
            self._make_event("native-loader", "critical"),
            self._make_event("native-loader", "warning"),
            self._make_event("native-loader", "info"),
            self._make_event("native-loader", "info"),
            self._make_event("frida-detection", "warning"),
        ]
        report = ScanReport.from_events("com.test", 30, events)

        nl_summary = report.summary_by_module["native-loader"]
        assert nl_summary.total_events == 4
        assert nl_summary.critical_count == 1
        assert nl_summary.warning_count == 1
        assert nl_summary.info_count == 2

        fd_summary = report.summary_by_module["frida-detection"]
        assert fd_summary.total_events == 1
        assert fd_summary.warning_count == 1

    def test_report_serializes_to_json(self) -> None:
        """ScanReport serializes to valid JSON."""
        events = [self._make_event("native-loader", "critical")]
        report = ScanReport.from_events("com.test", 30, events)
        json_str = report.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["target"] == "com.test"
        assert parsed["risk_score"] == 25
        assert len(parsed["events"]) == 1


class TestConfig:
    """Test YAML configuration loading."""

    def test_default_config_has_empty_modules(self) -> None:
        """Default Config has no modules if no default.yaml exists."""
        config = Config()
        assert config.modules == {}

    def test_config_from_dict(self) -> None:
        """Config validates from a raw dictionary."""
        raw: dict[str, Any] = {
            "modules": {
                "native-loader": {
                    "enabled": True,
                    "suspicious_paths": ["/data/local/tmp"],
                },
                "network-probe": {
                    "enabled": False,
                },
            },
            "policy": {
                "critical": "detach",
                "warning": "log",
                "info": "log",
            },
        }
        config = Config.model_validate(raw)
        assert config.modules["native-loader"]["enabled"] is True
        assert config.modules["network-probe"]["enabled"] is False
        assert config.policy.critical == PolicyAction.DETACH

    def test_modules_json_output(self) -> None:
        """modules_json() produces valid JSON for the agent."""
        config = Config.model_validate({
            "modules": {
                "native-loader": {"enabled": True, "suspicious_paths": ["/tmp"]},
            },
        })
        result = json.loads(config.modules_json())
        assert result["native-loader"]["enabled"] is True

    def test_policy_defaults(self) -> None:
        """Default policy: critical=detach, warning=log, info=log."""
        policy = RaspPolicy()
        assert policy.critical == PolicyAction.DETACH
        assert policy.warning == PolicyAction.LOG
        assert policy.info == PolicyAction.LOG
