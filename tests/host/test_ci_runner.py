"""Tests for CI runner — threshold evaluation and JUnit XML generation."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest
import yaml

from ci.runner import (
    TestResult,
    ThresholdConfig,
    evaluate_thresholds,
    generate_junit_xml,
    _classify_module_status,
    _find_unavailable_modules,
    _find_agent_errors,
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


def _write_thresholds(path: Path, config: dict[str, Any]) -> Path:
    """Write a threshold config YAML file and return the path."""
    path.write_text(yaml.dump(config), encoding="utf-8")
    return path


class TestThresholdConfig:
    """Test ThresholdConfig parsing from YAML."""

    def test_parses_required_detections(self, tmp_path: Path) -> None:
        cfg_path = _write_thresholds(tmp_path / "t.yaml", {
            "required_detections": {
                "native-loader": {"dlopen_ext_hook": True},
                "frida-detection": {"maps_scan": True, "port_scan": False},
            },
            "max_risk_score": 50,
        })
        tc = ThresholdConfig(cfg_path)
        assert tc.required_detections["native-loader"]["dlopen_ext_hook"] is True
        assert tc.required_detections["frida-detection"]["port_scan"] is False
        assert tc.max_risk_score == 50

    def test_defaults_for_missing_keys(self, tmp_path: Path) -> None:
        cfg_path = _write_thresholds(tmp_path / "t.yaml", {})
        tc = ThresholdConfig(cfg_path)
        assert tc.required_detections == {}
        assert tc.max_risk_score == 40
        assert tc.fail_on == []

    def test_fail_on_conditions(self, tmp_path: Path) -> None:
        cfg_path = _write_thresholds(tmp_path / "t.yaml", {
            "fail_on": ["module_unavailable", "uncaught_exception"],
        })
        tc = ThresholdConfig(cfg_path)
        assert "module_unavailable" in tc.fail_on
        assert "uncaught_exception" in tc.fail_on


class TestClassifyModuleStatus:
    """Test _classify_module_status helper."""

    def test_no_events_returns_not_detected(self) -> None:
        report = ScanReport.from_events("com.test", 30, [])
        assert _classify_module_status(report, "native-loader") == "not_detected"

    def test_enable_failed_returns_unavailable(self) -> None:
        events = [_make_event("native-loader", "warning", {"status": "enable_failed"})]
        report = ScanReport.from_events("com.test", 30, events)
        assert _classify_module_status(report, "native-loader") == "module_unavailable"

    def test_meaningful_events_returns_detected(self) -> None:
        events = [
            _make_event("native-loader", "info", {"status": "enabled"}),
            _make_event("native-loader", "warning", {"event": "suspicious_library_load"}),
        ]
        report = ScanReport.from_events("com.test", 30, events)
        assert _classify_module_status(report, "native-loader") == "detected"

    def test_only_enabled_returns_detected(self) -> None:
        events = [_make_event("native-loader", "info", {"status": "enabled"})]
        report = ScanReport.from_events("com.test", 30, events)
        assert _classify_module_status(report, "native-loader") == "detected"

    def test_no_symbols_resolved_returns_unavailable(self) -> None:
        events = [_make_event("jni-tracer", "warning", {"event": "no_symbols_resolved"})]
        report = ScanReport.from_events("com.test", 30, events)
        assert _classify_module_status(report, "jni-tracer") == "module_unavailable"


class TestFindUnavailableModules:
    """Test _find_unavailable_modules helper."""

    def test_empty_report(self) -> None:
        report = ScanReport.from_events("com.test", 30, [])
        assert _find_unavailable_modules(report) == []

    def test_finds_failed_modules(self) -> None:
        events = [
            _make_event("native-loader", "info", {"status": "enabled"}),
            _make_event("jni-tracer", "warning", {"status": "enable_failed"}),
            _make_event("integrity", "warning", {"status": "enable_failed"}),
        ]
        report = ScanReport.from_events("com.test", 30, events)
        unavailable = _find_unavailable_modules(report)
        assert "jni-tracer" in unavailable
        assert "integrity" in unavailable
        assert "native-loader" not in unavailable

    def test_deduplicates_modules(self) -> None:
        events = [
            _make_event("jni-tracer", "warning", {"status": "enable_failed"}),
            _make_event("jni-tracer", "warning", {"status": "enable_failed"}),
        ]
        report = ScanReport.from_events("com.test", 30, events)
        assert len(_find_unavailable_modules(report)) == 1


class TestFindAgentErrors:
    """Test _find_agent_errors helper."""

    def test_no_errors(self) -> None:
        events = [_make_event("native-loader", "info")]
        report = ScanReport.from_events("com.test", 30, events)
        assert _find_agent_errors(report) == []

    def test_finds_script_errors(self) -> None:
        events = [
            _make_event("agent-runtime", "critical", {"event": "script_error", "message": "crash"}),
            _make_event("native-loader", "info"),
        ]
        report = ScanReport.from_events("com.test", 30, events)
        errors = _find_agent_errors(report)
        assert len(errors) == 1
        assert errors[0].data["message"] == "crash"


class TestEvaluateThresholds:
    """Test evaluate_thresholds — full threshold evaluation logic."""

    def _make_thresholds(self, tmp_path: Path, config: dict[str, Any]) -> ThresholdConfig:
        return ThresholdConfig(_write_thresholds(tmp_path / "t.yaml", config))

    def test_risk_score_pass(self, tmp_path: Path) -> None:
        """Risk score within threshold passes."""
        thresholds = self._make_thresholds(tmp_path, {"max_risk_score": 50})
        events = [_make_event("native-loader", "warning")]  # risk=5
        report = ScanReport.from_events("com.test", 30, events)

        results = evaluate_thresholds(report, thresholds)
        risk_result = next(r for r in results if r.name == "risk_score")
        assert risk_result.passed is True

    def test_risk_score_fail(self, tmp_path: Path) -> None:
        """Risk score exceeding threshold fails."""
        thresholds = self._make_thresholds(tmp_path, {"max_risk_score": 10})
        # 3 criticals = 3*15 + module bonuses, well over 10
        events = [
            _make_event("mod-1", "critical"),
            _make_event("mod-2", "critical"),
            _make_event("mod-3", "critical"),
        ]
        report = ScanReport.from_events("com.test", 30, events)

        results = evaluate_thresholds(report, thresholds)
        risk_result = next(r for r in results if r.name == "risk_score")
        assert risk_result.passed is False
        assert "exceeds" in risk_result.message

    def test_required_detection_pass(self, tmp_path: Path) -> None:
        """Required detection that is present passes."""
        thresholds = self._make_thresholds(tmp_path, {
            "required_detections": {
                "native-loader": {"dlopen_ext_hook": True},
            },
        })
        events = [
            _make_event("native-loader", "info", {"status": "enabled"}),
            _make_event("native-loader", "warning", {"event": "suspicious_library_load"}),
        ]
        report = ScanReport.from_events("com.test", 30, events)

        results = evaluate_thresholds(report, thresholds)
        det_result = next(r for r in results if r.name == "native-loader.dlopen_ext_hook")
        assert det_result.passed is True

    def test_required_detection_fail(self, tmp_path: Path) -> None:
        """Required detection that is missing fails."""
        thresholds = self._make_thresholds(tmp_path, {
            "required_detections": {
                "jni-tracer": {"art_jni_call_hook": True},
            },
        })
        report = ScanReport.from_events("com.test", 30, [])

        results = evaluate_thresholds(report, thresholds)
        det_result = next(r for r in results if r.name == "jni-tracer.art_jni_call_hook")
        assert det_result.passed is False

    def test_fail_on_module_unavailable_pass(self, tmp_path: Path) -> None:
        """No unavailable modules passes the fail_on check."""
        thresholds = self._make_thresholds(tmp_path, {
            "fail_on": ["module_unavailable"],
        })
        events = [_make_event("native-loader", "info", {"status": "enabled"})]
        report = ScanReport.from_events("com.test", 30, events)

        results = evaluate_thresholds(report, thresholds)
        mod_result = next(r for r in results if r.name == "no_module_unavailable")
        assert mod_result.passed is True

    def test_fail_on_module_unavailable_fail(self, tmp_path: Path) -> None:
        """Unavailable module triggers the fail_on check."""
        thresholds = self._make_thresholds(tmp_path, {
            "fail_on": ["module_unavailable"],
        })
        events = [_make_event("jni-tracer", "warning", {"status": "enable_failed"})]
        report = ScanReport.from_events("com.test", 30, events)

        results = evaluate_thresholds(report, thresholds)
        mod_result = next(r for r in results if r.name == "no_module_unavailable")
        assert mod_result.passed is False
        assert "jni-tracer" in mod_result.message

    def test_fail_on_uncaught_exception_pass(self, tmp_path: Path) -> None:
        """No agent errors passes the uncaught_exception check."""
        thresholds = self._make_thresholds(tmp_path, {
            "fail_on": ["uncaught_exception"],
        })
        report = ScanReport.from_events("com.test", 30, [])

        results = evaluate_thresholds(report, thresholds)
        err_result = next(r for r in results if r.name == "no_uncaught_exceptions")
        assert err_result.passed is True

    def test_disabled_required_detection_skipped(self, tmp_path: Path) -> None:
        """Required detection set to false is skipped."""
        thresholds = self._make_thresholds(tmp_path, {
            "required_detections": {
                "native-loader": {"dlopen_ext_hook": False},
            },
        })
        report = ScanReport.from_events("com.test", 30, [])

        results = evaluate_thresholds(report, thresholds)
        # Should only have risk_score, not the disabled detection
        names = [r.name for r in results]
        assert "native-loader.dlopen_ext_hook" not in names


class TestGenerateJunitXml:
    """Test JUnit XML generation."""

    def test_generates_valid_xml(self, tmp_path: Path) -> None:
        """Output is valid XML with correct testsuite structure."""
        results = [
            TestResult("test_pass", "sentinellium", True),
            TestResult("test_fail", "sentinellium", False, "Something broke"),
        ]
        output = tmp_path / "results.xml"
        generate_junit_xml(results, output)

        assert output.exists()
        tree = ET.parse(output)
        root = tree.getroot()
        assert root.tag == "testsuite"
        assert root.get("tests") == "2"
        assert root.get("failures") == "1"

    def test_passing_tests_have_no_failure_element(self, tmp_path: Path) -> None:
        results = [TestResult("test_pass", "sentinellium", True)]
        output = tmp_path / "results.xml"
        generate_junit_xml(results, output)

        tree = ET.parse(output)
        testcase = tree.find(".//testcase[@name='test_pass']")
        assert testcase is not None
        assert testcase.find("failure") is None

    def test_failing_tests_have_failure_element(self, tmp_path: Path) -> None:
        results = [TestResult("test_fail", "sentinellium", False, "Threshold exceeded")]
        output = tmp_path / "results.xml"
        generate_junit_xml(results, output)

        tree = ET.parse(output)
        testcase = tree.find(".//testcase[@name='test_fail']")
        assert testcase is not None
        failure = testcase.find("failure")
        assert failure is not None
        assert failure.get("message") == "Threshold exceeded"

    def test_all_passing_zero_failures(self, tmp_path: Path) -> None:
        results = [
            TestResult("t1", "s", True),
            TestResult("t2", "s", True),
            TestResult("t3", "s", True),
        ]
        output = tmp_path / "results.xml"
        generate_junit_xml(results, output)

        tree = ET.parse(output)
        assert tree.getroot().get("failures") == "0"
        assert tree.getroot().get("tests") == "3"

    def test_empty_results(self, tmp_path: Path) -> None:
        """Empty result list generates a valid but empty testsuite."""
        output = tmp_path / "results.xml"
        generate_junit_xml([], output)

        tree = ET.parse(output)
        assert tree.getroot().get("tests") == "0"
        assert tree.getroot().get("failures") == "0"
