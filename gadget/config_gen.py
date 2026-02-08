"""Frida Gadget configuration generator.

Produces the JSON configuration file that Frida Gadget reads at load time.
The config file must be placed alongside the gadget library with the naming
convention: lib<name>.config.so (using .so extension so Android's APK
extraction preserves it).

Two modes are supported:
- script: Points to a local agent script for autonomous operation.
- listen: Opens a port for remote Frida attachment.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal


def generate_config(
    mode: Literal["script", "listen"],
    script_path: str = "/data/local/tmp/sentinellium-agent.js",
    listen_address: str = "0.0.0.0",
    listen_port: int = 27043,
) -> str:
    """Generate Frida Gadget configuration JSON.

    Args:
        mode: Gadget interaction mode — "script" for autonomous, "listen"
              for remote attachment.
        script_path: Absolute path to the agent script on the device.
                     Only used in script mode.
        listen_address: Address to bind for listen mode. Default 0.0.0.0
                        to accept connections from any interface.
        listen_port: Port for listen mode. Default 27043 (non-standard to
                     avoid RASP port checks that target 27042).

    Returns:
        JSON string suitable for writing to the gadget config file.
    """
    if mode == "script":
        config = {
            "interaction": {
                "type": "script",
                "path": script_path,
                "on_change": "reload",
            }
        }
    else:
        config = {
            "interaction": {
                "type": "listen",
                "address": listen_address,
                "port": listen_port,
            }
        }

    return json.dumps(config, indent=2)


def write_config(
    output_dir: Path,
    gadget_lib_name: str,
    mode: Literal["script", "listen"],
    **kwargs: str | int,
) -> Path:
    """Write gadget config to the correct location with .so naming convention.

    The config file must be named identically to the gadget library but with
    ".config.so" suffix. For example, if the gadget is "libsentinellium-gadget.so",
    the config must be "libsentinellium-gadget.config.so".

    Args:
        output_dir: Directory containing the gadget library.
        gadget_lib_name: Name of the gadget library (e.g., "libsentinellium-gadget.so").
        mode: Gadget interaction mode.
        **kwargs: Additional arguments passed to generate_config.

    Returns:
        Path to the written config file.
    """
    # Derive config filename: libfoo.so → libfoo.config.so
    base = gadget_lib_name.replace(".so", "")
    config_name = f"{base}.config.so"
    config_path = output_dir / config_name

    config_json = generate_config(mode, **kwargs)  # type: ignore[arg-type]
    config_path.write_text(config_json, encoding="utf-8")

    return config_path
