"""APK signing utilities for the gadget patching pipeline.

Handles debug keystore generation and APK signing via apksigner.
After repackaging an APK, Android requires it to be re-signed before
installation. We use a debug keystore — the signature won't match the
original, which is acceptable for research/testing purposes (and is
itself a RASP-detectable modification).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# Default debug keystore location
DEFAULT_KEYSTORE_DIR = Path.home() / ".sentinellium"
DEFAULT_KEYSTORE_PATH = DEFAULT_KEYSTORE_DIR / "debug.keystore"
DEFAULT_KEY_ALIAS = "sentinellium"
DEFAULT_STORE_PASS = "sentinellium"
DEFAULT_KEY_PASS = "sentinellium"


def ensure_debug_keystore(keystore_path: Path | None = None) -> Path:
    """Ensure a debug keystore exists, creating one if necessary.

    Uses keytool (from JDK) to generate a self-signed debug keystore.
    The keystore is stored in ~/.sentinellium/ by default.

    Args:
        keystore_path: Optional custom keystore path. Defaults to
                       ~/.sentinellium/debug.keystore.

    Returns:
        Path to the debug keystore.

    Raises:
        FileNotFoundError: If keytool is not available.
        subprocess.CalledProcessError: If keystore generation fails.
    """
    path = keystore_path or DEFAULT_KEYSTORE_PATH

    if path.exists():
        return path

    path.parent.mkdir(parents=True, exist_ok=True)

    _check_tool("keytool", "JDK (keytool)")

    subprocess.run(
        [
            "keytool",
            "-genkeypair",
            "-v",
            "-keystore", str(path),
            "-alias", DEFAULT_KEY_ALIAS,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-storepass", DEFAULT_STORE_PASS,
            "-keypass", DEFAULT_KEY_PASS,
            "-dname", "CN=Sentinellium Debug, O=Sentinellium, C=US",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    return path


def sign_apk(
    apk_path: Path,
    output_path: Path,
    keystore_path: Path | None = None,
) -> Path:
    """Sign an APK using apksigner with the debug keystore.

    Args:
        apk_path: Path to the unsigned/aligned APK.
        output_path: Path for the signed APK output.
        keystore_path: Optional custom keystore. Defaults to the
                       auto-generated debug keystore.

    Returns:
        Path to the signed APK.

    Raises:
        FileNotFoundError: If apksigner is not available.
        subprocess.CalledProcessError: If signing fails.
    """
    _check_tool("apksigner", "Android SDK Build Tools (apksigner)")

    ks = ensure_debug_keystore(keystore_path)

    subprocess.run(
        [
            "apksigner", "sign",
            "--ks", str(ks),
            "--ks-key-alias", DEFAULT_KEY_ALIAS,
            "--ks-pass", f"pass:{DEFAULT_STORE_PASS}",
            "--key-pass", f"pass:{DEFAULT_KEY_PASS}",
            "--out", str(output_path),
            str(apk_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    return output_path


def align_apk(apk_path: Path, output_path: Path) -> Path:
    """Align an APK using zipalign for optimal runtime performance.

    zipalign ensures that all uncompressed data starts with a 4-byte
    alignment, which improves memory-mapped access performance. This
    is required before signing with apksigner.

    Args:
        apk_path: Path to the unaligned APK.
        output_path: Path for the aligned APK output.

    Returns:
        Path to the aligned APK.

    Raises:
        FileNotFoundError: If zipalign is not available.
        subprocess.CalledProcessError: If alignment fails.
    """
    _check_tool("zipalign", "Android SDK Build Tools (zipalign)")

    subprocess.run(
        ["zipalign", "-f", "-v", "4", str(apk_path), str(output_path)],
        check=True,
        capture_output=True,
        text=True,
    )

    return output_path


def _check_tool(name: str, description: str) -> None:
    """Verify that a required external tool is available in PATH.

    Args:
        name: Tool binary name.
        description: Human-readable description for the error message.

    Raises:
        FileNotFoundError: If the tool is not found.
    """
    import shutil

    if shutil.which(name) is None:
        raise FileNotFoundError(
            f"Required tool '{name}' not found in PATH. "
            f"Please install {description} and ensure it's on your PATH."
        )
