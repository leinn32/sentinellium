"""APK repackaging pipeline for Frida Gadget injection.

Automates the process of embedding Frida Gadget into an Android APK:
1. Decode APK with apktool
2. Inject gadget .so library into the native libs directory
3. Patch Smali to load the gadget in the app's main Activity
4. Write gadget configuration (script or listen mode)
5. Rebuild, align, and sign the APK

This demonstrates the attacker workflow that RASP SDKs defend against:
repackaging + gadget injection. Having this automated shows understanding
of the full attack chain for systematic RASP resilience testing.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Literal

from gadget.config_gen import write_config
from gadget.signer import align_apk, sign_apk

# Gadget library name as embedded in the APK
GADGET_LIB_NAME = "libsentinellium-gadget.so"

# Android ABI directories
SUPPORTED_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

# Smali injection: System.loadLibrary call to load the gadget
SMALI_LOAD_LIBRARY = """\
    const-string v0, "sentinellium-gadget"

    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
"""


class ApkPatcher:
    """Automated APK patching pipeline for Frida Gadget injection.

    Args:
        input_apk: Path to the original APK file.
        gadget_lib: Path to the Frida Gadget shared library for the target arch.
        arch: Target ABI (e.g., "arm64-v8a"). Auto-detected if not provided.
        gadget_mode: "script" for autonomous agent execution, "listen" for
                     remote attachment via Frida.
        output_apk: Path for the patched APK. Defaults to <input>-patched.apk.
        agent_script: Path to the compiled agent JS. Required for script mode.
    """

    def __init__(
        self,
        input_apk: Path,
        gadget_lib: Path,
        arch: str | None = None,
        gadget_mode: Literal["script", "listen"] = "script",
        output_apk: Path | None = None,
        agent_script: Path | None = None,
    ) -> None:
        self.input_apk: Path = input_apk
        self.gadget_lib: Path = gadget_lib
        self.arch: str | None = arch
        self.gadget_mode: Literal["script", "listen"] = gadget_mode
        self.output_apk: Path = output_apk or input_apk.with_name(
            input_apk.stem + "-patched.apk"
        )
        self.agent_script: Path | None = agent_script
        self._work_dir: Path | None = None

    def patch(self) -> Path:
        """Execute the full patching pipeline.

        Returns:
            Path to the final signed, patched APK.

        Raises:
            FileNotFoundError: If required tools (apktool, zipalign, apksigner) are missing.
            ValueError: If the APK structure is unexpected.
            subprocess.CalledProcessError: If any pipeline step fails.
        """
        self._verify_prerequisites()

        with tempfile.TemporaryDirectory(prefix="sentinellium-") as tmpdir:
            work = Path(tmpdir)
            self._work_dir = work

            decoded_dir = work / "decoded"
            rebuilt_apk = work / "rebuilt.apk"
            aligned_apk = work / "aligned.apk"
            signed_apk = work / "signed.apk"

            # Step 1: Decode
            self._decode_apk(decoded_dir)

            # Step 2: Determine target architecture
            target_arch = self._resolve_arch(decoded_dir)

            # Step 3: Inject gadget library
            self._inject_gadget(decoded_dir, target_arch)

            # Step 4: Write gadget config
            self._write_gadget_config(decoded_dir, target_arch)

            # Step 5: Patch Smali to load gadget
            self._patch_smali(decoded_dir)

            # Step 6: Rebuild
            self._rebuild_apk(decoded_dir, rebuilt_apk)

            # Step 7: Align
            align_apk(rebuilt_apk, aligned_apk)

            # Step 8: Sign
            sign_apk(aligned_apk, signed_apk)

            # Step 9: Copy to output
            shutil.copy2(signed_apk, self.output_apk)

        return self.output_apk

    def _verify_prerequisites(self) -> None:
        """Verify all required tools are available."""
        for tool, desc in [
            ("apktool", "apktool (APK decompilation/recompilation)"),
            ("zipalign", "Android SDK Build Tools (zipalign)"),
            ("apksigner", "Android SDK Build Tools (apksigner)"),
        ]:
            if shutil.which(tool) is None:
                raise FileNotFoundError(
                    f"Required tool '{tool}' not found. Install {desc}."
                )

        if not self.input_apk.exists():
            raise FileNotFoundError(f"Input APK not found: {self.input_apk}")

        if self.input_apk.suffix == ".aab":
            raise ValueError(
                "App bundles (.aab) are not supported. Use a base APK (.apk) instead."
            )

        if not self.gadget_lib.exists():
            raise FileNotFoundError(
                f"Frida Gadget library not found: {self.gadget_lib}"
            )

    def _decode_apk(self, output_dir: Path) -> None:
        """Decode APK using apktool."""
        subprocess.run(
            ["apktool", "d", str(self.input_apk), "-o", str(output_dir), "-f"],
            check=True,
            capture_output=True,
            text=True,
        )

    def _resolve_arch(self, decoded_dir: Path) -> str:
        """Determine the target ABI for gadget injection.

        If --arch was specified, validates it. Otherwise, auto-detects
        from existing native libraries in the APK.
        """
        lib_dir = decoded_dir / "lib"
        existing_abis: list[str] = []

        if lib_dir.exists():
            existing_abis = [
                d.name for d in lib_dir.iterdir()
                if d.is_dir() and d.name in SUPPORTED_ABIS
            ]

        if self.arch:
            if existing_abis and self.arch not in existing_abis:
                # Warn but proceed — user may know what they're doing
                pass
            return self.arch

        if existing_abis:
            # Prefer arm64-v8a > armeabi-v7a > x86_64 > x86
            for preferred in SUPPORTED_ABIS:
                if preferred in existing_abis:
                    return preferred

        # No existing native libs — default to arm64-v8a
        return "arm64-v8a"

    def _inject_gadget(self, decoded_dir: Path, arch: str) -> None:
        """Copy the Frida Gadget library into the APK's native lib directory."""
        target_dir = decoded_dir / "lib" / arch
        target_dir.mkdir(parents=True, exist_ok=True)

        target_path = target_dir / GADGET_LIB_NAME
        shutil.copy2(self.gadget_lib, target_path)

    def _write_gadget_config(self, decoded_dir: Path, arch: str) -> None:
        """Write the gadget configuration file alongside the library."""
        lib_dir = decoded_dir / "lib" / arch
        write_config(
            output_dir=lib_dir,
            gadget_lib_name=GADGET_LIB_NAME,
            mode=self.gadget_mode,
        )

    def _patch_smali(self, decoded_dir: Path) -> None:
        """Inject System.loadLibrary call into the main Activity's Smali.

        Finds the launcher Activity from AndroidManifest.xml, locates its
        Smali file, and injects a loadLibrary call in either the static
        initializer (<clinit>) or onCreate method.
        """
        manifest_path = decoded_dir / "AndroidManifest.xml"
        main_activity_class = self._find_main_activity(manifest_path)

        if main_activity_class is None:
            raise ValueError(
                "Could not find launcher Activity in AndroidManifest.xml. "
                "The APK may use an unusual manifest structure."
            )

        smali_path = self._find_smali_file(decoded_dir, main_activity_class)

        if smali_path is None:
            raise ValueError(
                f"Could not find Smali file for {main_activity_class}. "
                "It may be in a secondary DEX or obfuscated."
            )

        self._inject_load_library(smali_path)

    def _find_main_activity(self, manifest_path: Path) -> str | None:
        """Parse AndroidManifest.xml to find the launcher Activity class name.

        Returns the fully-qualified class name (e.g., "com.example.MainActivity"),
        or None if not found.
        """
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        package = root.get("package", "")

        for activity in root.iter("activity"):
            for intent_filter in activity.iter("intent-filter"):
                has_main = False
                has_launcher = False

                for action in intent_filter.iter("action"):
                    if action.get(f"{{{ns['android']}}}name") == "android.intent.action.MAIN":
                        has_main = True
                for category in intent_filter.iter("category"):
                    if category.get(f"{{{ns['android']}}}name") == "android.intent.category.LAUNCHER":
                        has_launcher = True

                if has_main and has_launcher:
                    name = activity.get(f"{{{ns['android']}}}name", "")
                    if name.startswith("."):
                        name = package + name
                    elif "." not in name:
                        name = f"{package}.{name}"
                    return name

        return None

    def _find_smali_file(
        self, decoded_dir: Path, class_name: str
    ) -> Path | None:
        """Locate the Smali file for a Java class.

        Handles multidex APKs by searching all smali* directories.
        Class name format: "com.example.MainActivity" →
        "smali/com/example/MainActivity.smali"
        """
        relative_path = class_name.replace(".", "/") + ".smali"

        # Search all smali directories (smali, smali_classes2, smali_classes3, ...)
        for entry in sorted(decoded_dir.iterdir()):
            if entry.is_dir() and entry.name.startswith("smali"):
                candidate = entry / relative_path
                if candidate.exists():
                    return candidate

        return None

    def _inject_load_library(self, smali_path: Path) -> None:
        """Inject System.loadLibrary into a Smali file.

        Strategy:
        1. Look for an existing <clinit> method (static initializer).
           If found, inject at the start of the method body.
        2. If no <clinit>, look for onCreate and inject there.
        3. If neither, create a new <clinit> method.
        """
        content = smali_path.read_text(encoding="utf-8")

        # Strategy 1: Inject into existing <clinit>
        clinit_pattern = r"(\.method\s+(?:public\s+|private\s+)?static\s+constructor\s+<clinit>\(\)V\s*\n\s*\.locals\s+\d+)"
        clinit_match = re.search(clinit_pattern, content)

        if clinit_match:
            injection_point = clinit_match.end()
            # Need to ensure .locals is at least 1
            locals_match = re.search(
                r"\.locals\s+(\d+)", clinit_match.group(0)
            )
            if locals_match:
                current_locals = int(locals_match.group(1))
                if current_locals < 1:
                    content = content[:clinit_match.start()] + \
                        clinit_match.group(0).replace(
                            f".locals {current_locals}",
                            ".locals 1"
                        ) + content[clinit_match.end():]
                    # Recalculate injection point
                    clinit_match = re.search(clinit_pattern, content)
                    if clinit_match:
                        injection_point = clinit_match.end()

            content = (
                content[:injection_point]
                + "\n"
                + SMALI_LOAD_LIBRARY
                + content[injection_point:]
            )
            smali_path.write_text(content, encoding="utf-8")
            return

        # Strategy 2: Inject into onCreate
        oncreate_pattern = r"(\.method\s+(?:public|protected)\s+onCreate\(Landroid/os/Bundle;\)V\s*\n\s*\.locals\s+\d+)"
        oncreate_match = re.search(oncreate_pattern, content)

        if oncreate_match:
            injection_point = oncreate_match.end()
            locals_match = re.search(
                r"\.locals\s+(\d+)", oncreate_match.group(0)
            )
            if locals_match:
                current_locals = int(locals_match.group(1))
                if current_locals < 1:
                    content = content[:oncreate_match.start()] + \
                        oncreate_match.group(0).replace(
                            f".locals {current_locals}",
                            ".locals 1"
                        ) + content[oncreate_match.end():]
                    oncreate_match = re.search(oncreate_pattern, content)
                    if oncreate_match:
                        injection_point = oncreate_match.end()

            content = (
                content[:injection_point]
                + "\n"
                + SMALI_LOAD_LIBRARY
                + content[injection_point:]
            )
            smali_path.write_text(content, encoding="utf-8")
            return

        # Strategy 3: Create a new <clinit> method
        # Insert before the first .method or at end of class
        new_clinit = """
.method static constructor <clinit>()V
    .locals 1

""" + SMALI_LOAD_LIBRARY + """
    return-void
.end method
"""
        first_method = re.search(r"^\.method\s", content, re.MULTILINE)
        if first_method:
            content = (
                content[:first_method.start()]
                + new_clinit
                + "\n"
                + content[first_method.start():]
            )
        else:
            content += "\n" + new_clinit

        smali_path.write_text(content, encoding="utf-8")

    def _rebuild_apk(self, decoded_dir: Path, output_apk: Path) -> None:
        """Rebuild the APK from the decoded directory using apktool."""
        subprocess.run(
            ["apktool", "b", str(decoded_dir), "-o", str(output_apk)],
            check=True,
            capture_output=True,
            text=True,
        )
