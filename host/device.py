"""Frida device enumeration, session management, and lifecycle.

Handles all Frida interactions: device discovery, process attach/spawn,
script loading, and clean teardown. Designed to be used by the CLI
commands without exposing Frida internals to the rest of the host.
"""

from __future__ import annotations

import signal
import sys
from pathlib import Path
from typing import Any, Callable

import frida

from host.models import Config, TelemetryEvent

# Path to the compiled agent bundle, relative to project root
AGENT_BUNDLE_PATH = Path(__file__).parent.parent / "agent" / "_agent.js"


class DeviceManager:
    """Manages Frida device enumeration."""

    @staticmethod
    def enumerate_devices() -> list[frida.core.Device]:
        """List all available Frida devices.

        Returns:
            List of Frida Device objects with id, name, and type attributes.
        """
        return frida.enumerate_devices()

    @staticmethod
    def get_usb_device(timeout: int = 5) -> frida.core.Device:
        """Get the first available USB device.

        Args:
            timeout: Seconds to wait for a USB device.

        Returns:
            Frida Device connected via USB.

        Raises:
            frida.TimedOutError: If no USB device is found within timeout.
        """
        return frida.get_usb_device(timeout=timeout)


class Session:
    """Manages a Frida instrumentation session.

    Handles the lifecycle of attaching to a target process, loading the
    compiled agent script, routing messages to the host, and performing
    clean teardown on detach.

    Args:
        package_name: Android package name to instrument.
        config: Parsed configuration for module setup.
        on_event: Callback invoked for each deserialized TelemetryEvent.
        spawn: If True, spawn the app instead of attaching to a running process.
    """

    def __init__(
        self,
        package_name: str,
        config: Config,
        on_event: Callable[[TelemetryEvent], None],
        spawn: bool = False,
    ) -> None:
        self.package_name: str = package_name
        self.config: Config = config
        self.on_event: Callable[[TelemetryEvent], None] = on_event
        self.spawn: bool = spawn

        self._device: frida.core.Device | None = None
        self._session: frida.core.Session | None = None
        self._script: frida.core.Script | None = None
        self._pid: int | None = None

    def attach(self) -> None:
        """Attach to the target process and load the agent.

        If spawn mode is enabled, the process is started fresh and
        resumed after the agent is loaded — ensuring hooks are in place
        before the app's initialization code runs.

        Raises:
            FileNotFoundError: If the compiled agent bundle doesn't exist.
            frida.ProcessNotFoundError: If the target process isn't running
                (when not using spawn mode).
        """
        if not AGENT_BUNDLE_PATH.exists():
            raise FileNotFoundError(
                f"Agent bundle not found at {AGENT_BUNDLE_PATH}. "
                "Run 'cd agent && npm run build' first."
            )

        agent_source = AGENT_BUNDLE_PATH.read_text(encoding="utf-8")

        self._device = DeviceManager.get_usb_device()

        if self.spawn:
            self._pid = self._device.spawn([self.package_name])
            self._session = self._device.attach(self._pid)
        else:
            self._session = self._device.attach(self.package_name)

        self._session.on("detached", self._on_detached)

        self._script = self._session.create_script(agent_source)
        self._script.on("message", self._on_message)
        self._script.load()

        # Push module configuration to the agent
        self._script.exports_sync.init(self.config.modules_json())

        if self.spawn and self._pid is not None:
            self._device.resume(self._pid)

    def detach(self) -> None:
        """Cleanly detach from the target process.

        Calls the agent's disableAll() RPC method to ensure all hooks
        are removed before the script is unloaded. This prevents the
        target app from crashing due to dangling hooks.
        """
        if self._script is not None:
            try:
                self._script.exports_sync.disable_all()
            except Exception:
                pass  # Best-effort cleanup
            try:
                self._script.unload()
            except Exception:
                pass
            self._script = None

        if self._session is not None:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None

        self._device = None

    def _on_message(self, message: dict[str, Any], data: Any) -> None:
        """Handle incoming messages from the Frida agent.

        Frida messages have two types:
        - "send": data messages from the agent's send() calls
        - "error": runtime errors in the agent script

        We only process "send" messages that match the TelemetryEvent schema.
        """
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("type") == "telemetry":
                try:
                    event = TelemetryEvent.model_validate(payload)
                    self.on_event(event)
                except Exception:
                    pass  # Skip malformed events
        elif message.get("type") == "error":
            # Agent script error — could indicate a bug in a module
            description = message.get("description", "Unknown error")
            stack = message.get("stack", "")
            # Create a synthetic telemetry event for agent errors
            error_event = TelemetryEvent(
                type="telemetry",
                module_id="agent-runtime",
                timestamp=int(
                    __import__("time").time() * 1000
                ),
                severity="warning",
                data={
                    "event": "script_error",
                    "description": description,
                    "stack": stack,
                },
            )
            self.on_event(error_event)

    def _on_detached(self, reason: str, crash: Any) -> None:
        """Handle session detach events.

        This fires when the target process exits, crashes, or is killed.
        """
        self._session = None
        self._script = None
