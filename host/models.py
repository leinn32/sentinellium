"""Pydantic models for Sentinellium host.

Defines the data contracts between the Frida agent and the Python host:
- TelemetryEvent: deserialized from agent send() messages
- ScanReport: aggregated output of a timed scan
- ModuleConfig / Config: YAML configuration schema
- RaspPolicy: policy actions for simulate mode
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Telemetry severity levels aligned with RASP threat classification."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class TelemetryEvent(BaseModel):
    """Single telemetry event received from the Frida agent.

    Every agent module emits events through the EventBus, which enforces
    this schema. The host deserializes raw Frida messages into this model
    for type-safe processing and rendering.
    """

    type: str = "telemetry"
    module_id: str
    timestamp: int
    severity: Severity
    data: dict[str, Any]
    stacktrace: str | None = None

    @property
    def timestamp_dt(self) -> datetime:
        """Convert millisecond epoch timestamp to datetime."""
        return datetime.fromtimestamp(self.timestamp / 1000, tz=timezone.utc)

    @property
    def timestamp_str(self) -> str:
        """Human-readable timestamp for display."""
        return self.timestamp_dt.strftime("%H:%M:%S.%f")[:-3]


class PolicyAction(str, Enum):
    """Actions the policy engine can take in response to telemetry events."""

    DETACH = "detach"
    LOG = "log"


class RaspPolicy(BaseModel):
    """Policy configuration for simulate mode.

    Maps severity levels to actions. When a telemetry event arrives whose
    severity matches a policy action of "detach", the session is terminated
    to simulate how a RASP SDK would kill the app.
    """

    critical: PolicyAction = PolicyAction.DETACH
    warning: PolicyAction = PolicyAction.LOG
    info: PolicyAction = PolicyAction.LOG


class ModuleConfig(BaseModel, extra="allow"):
    """Configuration for a single hook module.

    Uses extra="allow" so that module-specific options (suspicious_paths,
    frida_port, etc.) pass through without needing to enumerate every
    possible field here. Each module reads its own config keys.
    """

    enabled: bool = True


class Config(BaseModel):
    """Top-level configuration loaded from YAML.

    Sections:
    - modules: per-module configuration blocks
    - policy: RASP simulation policy actions
    """

    modules: dict[str, dict[str, Any]] = Field(default_factory=dict)
    policy: RaspPolicy = Field(default_factory=RaspPolicy)

    @classmethod
    def from_yaml(cls, path: Path) -> Config:
        """Load configuration from a YAML file.

        Args:
            path: Path to the YAML configuration file.

        Returns:
            Parsed Config instance.

        Raises:
            FileNotFoundError: If the config file doesn't exist.
            yaml.YAMLError: If the YAML is malformed.
        """
        content = path.read_text(encoding="utf-8")
        raw = yaml.safe_load(content)
        if raw is None:
            return cls()
        return cls.model_validate(raw)

    @classmethod
    def default(cls) -> Config:
        """Return the default configuration.

        Tries to load from config/default.yaml relative to the project root.
        Falls back to an empty config if the file doesn't exist.
        """
        default_path = Path(__file__).parent.parent / "config" / "default.yaml"
        if default_path.exists():
            return cls.from_yaml(default_path)
        return cls()

    def modules_json(self) -> str:
        """Serialize the modules config to JSON for passing to the agent.

        The agent's rpc.exports.init() expects a JSON string containing
        the modules configuration block.
        """
        return json.dumps(self.modules)


class ModuleSummary(BaseModel):
    """Per-module summary in a scan report."""

    total_events: int = 0
    critical_count: int = 0
    warning_count: int = 0
    info_count: int = 0


class ScanReport(BaseModel):
    """Aggregated output of a timed scan.

    Produced by the `scan` command after collecting events for the
    configured duration. Includes a risk score and per-module breakdown.
    """

    target: str
    duration_seconds: int
    risk_score: int = Field(ge=0, le=100)
    events: list[TelemetryEvent] = Field(default_factory=list)
    summary_by_module: dict[str, ModuleSummary] = Field(default_factory=dict)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_events(
        cls,
        target: str,
        duration: int,
        events: list[TelemetryEvent],
    ) -> ScanReport:
        """Build a scan report from collected telemetry events.

        Computes the risk score as:
        - Each critical event: +15 points
        - Each warning event: +5 points
        - Each unique module with at least one critical: +10 points
        - Capped at 100

        Args:
            target: Package name of the target app.
            duration: Scan duration in seconds.
            events: Collected telemetry events.
        """
        summary: dict[str, ModuleSummary] = {}

        for event in events:
            if event.module_id not in summary:
                summary[event.module_id] = ModuleSummary()

            mod_summary = summary[event.module_id]
            mod_summary.total_events += 1

            if event.severity == Severity.CRITICAL:
                mod_summary.critical_count += 1
            elif event.severity == Severity.WARNING:
                mod_summary.warning_count += 1
            else:
                mod_summary.info_count += 1

        # Compute risk score
        risk = 0
        modules_with_criticals: set[str] = set()

        for event in events:
            if event.severity == Severity.CRITICAL:
                risk += 15
                modules_with_criticals.add(event.module_id)
            elif event.severity == Severity.WARNING:
                risk += 5

        risk += len(modules_with_criticals) * 10
        risk = min(risk, 100)

        return cls(
            target=target,
            duration_seconds=duration,
            risk_score=risk,
            events=events,
            summary_by_module=summary,
        )
