"""Tests for gadget utilities — config generation, manifest parsing, Smali injection."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from gadget.config_gen import generate_config, write_config
from gadget.patcher import ApkPatcher, GADGET_LIB_NAME, SMALI_LOAD_LIBRARY, SUPPORTED_ABIS


class TestGenerateConfig:
    """Test Frida Gadget config JSON generation."""

    def test_script_mode_config(self) -> None:
        config = json.loads(generate_config("script"))
        assert config["interaction"]["type"] == "script"
        assert config["interaction"]["on_change"] == "reload"
        assert "/data/local/tmp/" in config["interaction"]["path"]

    def test_script_mode_custom_path(self) -> None:
        config = json.loads(generate_config("script", script_path="/custom/agent.js"))
        assert config["interaction"]["path"] == "/custom/agent.js"

    def test_listen_mode_config(self) -> None:
        config = json.loads(generate_config("listen"))
        assert config["interaction"]["type"] == "listen"
        assert config["interaction"]["address"] == "0.0.0.0"
        assert config["interaction"]["port"] == 27043

    def test_listen_mode_custom_port(self) -> None:
        config = json.loads(generate_config("listen", listen_port=9999))
        assert config["interaction"]["port"] == 9999

    def test_listen_mode_custom_address(self) -> None:
        config = json.loads(generate_config("listen", listen_address="127.0.0.1"))
        assert config["interaction"]["address"] == "127.0.0.1"

    def test_output_is_valid_json(self) -> None:
        for mode in ("script", "listen"):
            result = generate_config(mode)
            parsed = json.loads(result)
            assert isinstance(parsed, dict)


class TestWriteConfig:
    """Test write_config file naming and content."""

    def test_config_naming_convention(self, tmp_path: Path) -> None:
        """Config file follows the lib<name>.config.so naming convention."""
        path = write_config(tmp_path, "libsentinellium-gadget.so", "script")
        assert path.name == "libsentinellium-gadget.config.so"
        assert path.exists()

    def test_config_content_matches_mode(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, "libgadget.so", "listen")
        content = json.loads(path.read_text(encoding="utf-8"))
        assert content["interaction"]["type"] == "listen"

    def test_custom_lib_name(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, "libcustom.so", "script")
        assert path.name == "libcustom.config.so"


class TestApkPatcherManifestParsing:
    """Test ApkPatcher._find_main_activity manifest parsing."""

    def _write_manifest(self, path: Path, content: str) -> Path:
        manifest_path = path / "AndroidManifest.xml"
        manifest_path.write_text(content, encoding="utf-8")
        return manifest_path

    def _make_patcher(self) -> ApkPatcher:
        """Create an ApkPatcher with dummy paths for testing parse methods."""
        return ApkPatcher(
            input_apk=Path("dummy.apk"),
            gadget_lib=Path("dummy.so"),
        )

    def test_standard_manifest(self, tmp_path: Path) -> None:
        """Finds main activity in a standard Android manifest."""
        manifest = self._write_manifest(tmp_path, """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <application>
        <activity android:name="com.example.app.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>""")

        patcher = self._make_patcher()
        result = patcher._find_main_activity(manifest)
        assert result == "com.example.app.MainActivity"

    def test_shorthand_activity_name(self, tmp_path: Path) -> None:
        """Resolves .ShortName to full package + class name."""
        manifest = self._write_manifest(tmp_path, """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <application>
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>""")

        patcher = self._make_patcher()
        result = patcher._find_main_activity(manifest)
        assert result == "com.example.app.MainActivity"

    def test_unqualified_activity_name(self, tmp_path: Path) -> None:
        """Resolves unqualified name (no dots) to package.ClassName."""
        manifest = self._write_manifest(tmp_path, """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <application>
        <activity android:name="MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>""")

        patcher = self._make_patcher()
        result = patcher._find_main_activity(manifest)
        assert result == "com.example.app.MainActivity"

    def test_no_launcher_activity(self, tmp_path: Path) -> None:
        """Returns None when no launcher activity is found."""
        manifest = self._write_manifest(tmp_path, """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <application>
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
            </intent-filter>
        </activity>
    </application>
</manifest>""")

        patcher = self._make_patcher()
        result = patcher._find_main_activity(manifest)
        assert result is None


class TestApkPatcherSmaliInjection:
    """Test ApkPatcher._inject_load_library Smali patching."""

    def _make_patcher(self) -> ApkPatcher:
        return ApkPatcher(
            input_apk=Path("dummy.apk"),
            gadget_lib=Path("dummy.so"),
        )

    def test_inject_into_existing_clinit(self, tmp_path: Path) -> None:
        """Injects into an existing <clinit> method."""
        smali = tmp_path / "Activity.smali"
        smali.write_text("""\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Lcom/example/app/BuildConfig;->DEBUG:Z

    return-void
.end method
""", encoding="utf-8")

        patcher = self._make_patcher()
        patcher._inject_load_library(smali)

        content = smali.read_text(encoding="utf-8")
        assert 'const-string v0, "sentinellium-gadget"' in content
        assert "invoke-static" in content
        # The original code should still be there
        assert "BuildConfig" in content

    def test_inject_into_oncreate(self, tmp_path: Path) -> None:
        """Falls back to onCreate when no <clinit> exists."""
        smali = tmp_path / "Activity.smali"
        smali.write_text("""\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    return-void
.end method
""", encoding="utf-8")

        patcher = self._make_patcher()
        patcher._inject_load_library(smali)

        content = smali.read_text(encoding="utf-8")
        assert 'const-string v0, "sentinellium-gadget"' in content

    def test_creates_new_clinit(self, tmp_path: Path) -> None:
        """Creates a new <clinit> when neither <clinit> nor onCreate exist."""
        smali = tmp_path / "Activity.smali"
        smali.write_text("""\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onResume()V
    .locals 0

    return-void
.end method
""", encoding="utf-8")

        patcher = self._make_patcher()
        patcher._inject_load_library(smali)

        content = smali.read_text(encoding="utf-8")
        assert "<clinit>" in content
        assert 'const-string v0, "sentinellium-gadget"' in content
        assert "return-void" in content

    def test_handles_zero_locals_in_clinit(self, tmp_path: Path) -> None:
        """Upgrades .locals 0 to .locals 1 when injecting into <clinit>."""
        smali = tmp_path / "Activity.smali"
        smali.write_text("""\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method static constructor <clinit>()V
    .locals 0

    return-void
.end method
""", encoding="utf-8")

        patcher = self._make_patcher()
        patcher._inject_load_library(smali)

        content = smali.read_text(encoding="utf-8")
        assert ".locals 1" in content
        assert 'const-string v0, "sentinellium-gadget"' in content


class TestApkPatcherArchResolution:
    """Test ApkPatcher._resolve_arch architecture detection."""

    def _make_patcher(self, arch: str | None = None) -> ApkPatcher:
        return ApkPatcher(
            input_apk=Path("dummy.apk"),
            gadget_lib=Path("dummy.so"),
            arch=arch,
        )

    def test_explicit_arch(self, tmp_path: Path) -> None:
        """Explicit --arch is used regardless of APK contents."""
        decoded = tmp_path / "decoded"
        lib_dir = decoded / "lib" / "armeabi-v7a"
        lib_dir.mkdir(parents=True)

        patcher = self._make_patcher(arch="x86_64")
        result = patcher._resolve_arch(decoded)
        assert result == "x86_64"

    def test_auto_detect_prefers_arm64(self, tmp_path: Path) -> None:
        """Auto-detection prefers arm64-v8a when available."""
        decoded = tmp_path / "decoded"
        for abi in ("armeabi-v7a", "arm64-v8a"):
            (decoded / "lib" / abi).mkdir(parents=True)

        patcher = self._make_patcher()
        result = patcher._resolve_arch(decoded)
        assert result == "arm64-v8a"

    def test_auto_detect_fallback_arm32(self, tmp_path: Path) -> None:
        """Falls back to armeabi-v7a when arm64 isn't present."""
        decoded = tmp_path / "decoded"
        (decoded / "lib" / "armeabi-v7a").mkdir(parents=True)

        patcher = self._make_patcher()
        result = patcher._resolve_arch(decoded)
        assert result == "armeabi-v7a"

    def test_no_native_libs_defaults_arm64(self, tmp_path: Path) -> None:
        """Defaults to arm64-v8a when no native libs exist in APK."""
        decoded = tmp_path / "decoded"
        decoded.mkdir(parents=True)

        patcher = self._make_patcher()
        result = patcher._resolve_arch(decoded)
        assert result == "arm64-v8a"

    def test_find_smali_file(self, tmp_path: Path) -> None:
        """Locates Smali file from class name."""
        decoded = tmp_path / "decoded"
        smali_dir = decoded / "smali" / "com" / "example" / "app"
        smali_dir.mkdir(parents=True)
        (smali_dir / "MainActivity.smali").write_text(".class", encoding="utf-8")

        patcher = self._make_patcher()
        result = patcher._find_smali_file(decoded, "com.example.app.MainActivity")
        assert result is not None
        assert result.name == "MainActivity.smali"

    def test_find_smali_multidex(self, tmp_path: Path) -> None:
        """Locates Smali file in secondary DEX directory."""
        decoded = tmp_path / "decoded"
        smali2 = decoded / "smali_classes2" / "com" / "example"
        smali2.mkdir(parents=True)
        (smali2 / "Helper.smali").write_text(".class", encoding="utf-8")

        patcher = self._make_patcher()
        result = patcher._find_smali_file(decoded, "com.example.Helper")
        assert result is not None
        assert "smali_classes2" in str(result)

    def test_find_smali_not_found(self, tmp_path: Path) -> None:
        """Returns None when class is not found in any smali directory."""
        decoded = tmp_path / "decoded"
        (decoded / "smali").mkdir(parents=True)

        patcher = self._make_patcher()
        result = patcher._find_smali_file(decoded, "com.nonexistent.Class")
        assert result is None
