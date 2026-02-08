"""Rich-based TUI rendering for Sentinellium.

Provides a live-updating table that displays telemetry events grouped
by severity, and summary formatters for scan reports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from host.models import ScanReport, Severity, TelemetryEvent

# Severity → Rich color mapping
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "red bold",
    Severity.WARNING: "yellow",
    Severity.INFO: "green",
}

# Severity → display label
SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.WARNING: "WARNING",
    Severity.INFO: "INFO",
}


class LiveRenderer:
    """Real-time telemetry event renderer using Rich Live display.

    Maintains an internal list of events and re-renders the table on each
    update. Events are displayed in chronological order with color-coded
    severity indicators.

    Args:
        console: Rich Console instance for output.
        max_rows: Maximum number of rows to display (oldest are trimmed).
    """

    def __init__(
        self,
        console: Console | None = None,
        max_rows: int = 100,
    ) -> None:
        self.console: Console = console or Console()
        self.max_rows: int = max_rows
        self.events: list[TelemetryEvent] = []
        self.counts: dict[Severity, int] = {
            Severity.CRITICAL: 0,
            Severity.WARNING: 0,
            Severity.INFO: 0,
        }
        self._live: Live | None = None

    def start(self) -> Live:
        """Start the live display. Returns the Live context manager."""
        self._live = Live(
            self._build_table(),
            console=self.console,
            refresh_per_second=4,
        )
        return self._live

    def add_event(self, event: TelemetryEvent) -> None:
        """Add a telemetry event and refresh the display.

        Args:
            event: Deserialized telemetry event from the agent.
        """
        self.events.append(event)
        self.counts[event.severity] = self.counts.get(event.severity, 0) + 1

        # Trim oldest events if we exceed max_rows
        if len(self.events) > self.max_rows:
            self.events = self.events[-self.max_rows :]

        if self._live is not None:
            self._live.update(self._build_table())

    def _build_table(self) -> Table:
        """Build the Rich table from current events."""
        table = Table(
            title="Sentinellium — Live Telemetry",
            caption=self._status_line(),
            expand=True,
        )

        table.add_column("Time", style="dim", width=12, no_wrap=True)
        table.add_column("Module", style="cyan", width=20)
        table.add_column("Severity", width=10, no_wrap=True)
        table.add_column("Details", ratio=1)

        for event in self.events:
            severity_style = SEVERITY_COLORS[event.severity]
            severity_label = SEVERITY_LABELS[event.severity]

            # Format the data dict into a readable string
            details = self._format_data(event.data)
            if event.stacktrace:
                details += f"\n[dim]{event.stacktrace}[/dim]"

            table.add_row(
                event.timestamp_str,
                event.module_id,
                Text(severity_label, style=severity_style),
                details,
            )

        return table

    def _status_line(self) -> str:
        """Build the status line showing event counts."""
        parts = [
            f"[red]{self.counts[Severity.CRITICAL]} critical[/red]",
            f"[yellow]{self.counts[Severity.WARNING]} warning[/yellow]",
            f"[green]{self.counts[Severity.INFO]} info[/green]",
        ]
        total = sum(self.counts.values())
        return f"Total: {total} events | " + " | ".join(parts)

    @staticmethod
    def _format_data(data: dict[str, Any]) -> str:
        """Format a telemetry data dict for table display.

        Extracts key fields and presents them concisely rather than
        dumping raw JSON.
        """
        parts: list[str] = []

        # Prioritize 'event' and 'detail' fields
        event_type = data.get("event", data.get("check", ""))
        if event_type:
            parts.append(str(event_type))

        detail = data.get("detail", data.get("finding", ""))
        if detail:
            parts.append(str(detail))

        # Add other informative fields
        for key in ("path", "destination", "library", "method", "marker", "port"):
            value = data.get(key)
            if value is not None:
                parts.append(f"{key}={value}")

        # Add matched rule if present
        matched = data.get("matched_rule")
        if matched is not None:
            parts.append(f"rule={matched}")

        if not parts:
            # Fallback: compact JSON
            return json.dumps(data, default=str)[:120]

        return " | ".join(parts)

    def print_summary(self) -> None:
        """Print a final summary after detaching."""
        self.console.print()
        self.console.print(
            Panel(
                f"[red]{self.counts[Severity.CRITICAL]}[/red] critical | "
                f"[yellow]{self.counts[Severity.WARNING]}[/yellow] warning | "
                f"[green]{self.counts[Severity.INFO]}[/green] info",
                title="Session Summary",
                border_style="blue",
            )
        )


def print_scan_report(report: ScanReport, console: Console | None = None) -> None:
    """Print a formatted scan report to the console.

    Args:
        report: Completed scan report with events and risk score.
        console: Optional Rich Console instance.
    """
    console = console or Console()

    # Risk score panel
    if report.risk_score >= 70:
        score_style = "red bold"
    elif report.risk_score >= 30:
        score_style = "yellow bold"
    else:
        score_style = "green bold"

    console.print()
    console.print(
        Panel(
            f"[{score_style}]{report.risk_score}/100[/{score_style}]",
            title=f"Risk Score — {report.target}",
            subtitle=f"Duration: {report.duration_seconds}s",
            border_style="blue",
        )
    )

    # Per-module breakdown
    if report.summary_by_module:
        table = Table(title="Module Summary", expand=True)
        table.add_column("Module", style="cyan")
        table.add_column("Total", justify="right")
        table.add_column("Critical", justify="right", style="red")
        table.add_column("Warning", justify="right", style="yellow")
        table.add_column("Info", justify="right", style="green")

        for module_id, summary in sorted(report.summary_by_module.items()):
            table.add_row(
                module_id,
                str(summary.total_events),
                str(summary.critical_count),
                str(summary.warning_count),
                str(summary.info_count),
            )

        console.print(table)


def save_report(report: ScanReport, output_path: Path) -> None:
    """Save a scan report to a JSON file.

    Args:
        report: Completed scan report.
        output_path: Path to write the JSON file.
    """
    output_path.write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )
