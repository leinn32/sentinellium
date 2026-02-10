"""
Multi-Layer APK Scanner — Extracts RASP signatures from APK files statically.

Scanning layers (ordered by cost):
  1. ZIP entry names — native .so filenames (essentially free)
  2. String tables — regex scan of DEX/SO raw bytes (fast)
  3. DEX class enumeration — androguard class name extraction (moderate)
  4. AndroidManifest.xml — component and permission scanning (moderate)
  5. APKiD — deep packer/protector identification (slow, optional)

Usage:
    python scanner.py --dir ./tmp/apks --output results/scan_results.json
"""

from __future__ import annotations

import json
import re
import sys
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path


# ── Layer 1: Native library patterns ──────────────────────────────────────────

RASP_NATIVE_LIBS: dict[str, str] = {
    # Wultra
    "libwultraappprotection": "wultra",
    "libpowerauth": "wultra",
    # Promon SHIELD
    "libshield.so": "promon",
    "libpromon": "promon",
    # Guardsquare DexGuard / iXGuard
    "libdexguard": "guardsquare",
    # Appdome
    "libappdome": "appdome",
    # Talsec freeRASP
    "libfreerasp.so": "talsec",
    "libtalsec": "talsec",
    # LIAPP
    "libliapp": "liapp",
    "liblockin": "liapp",
    # Digital.ai / Arxan
    "libaxan": "arxan",
    "libdigitalai": "arxan",
    # DexProtector
    "libdexprotector": "dexprotector",
    "libalice.so": "dexprotector",
    # AppSealing
    "libcovault": "appsealing",
    # Tencent Legu
    "libshell.so": "tencent_legu",
    "libmobisecy.so": "tencent_legu",
    # Qihoo 360 Jiagu
    "libjiagu": "qihoo_360",
    "libprotectclass.so": "qihoo_360",
    # Bangcle / SecNeo
    "libsecexe.so": "bangcle",
    "libsecmain.so": "bangcle",
}

# ── Layer 2: String patterns ─────────────────────────────────────────────────

RASP_STRING_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(rb"WultraAppProtection|PowerAuth|io\.wultra", re.IGNORECASE), "wultra"),
    (re.compile(rb"PromonShield|SHIELD_|promon\.shield", re.IGNORECASE), "promon"),
    (re.compile(rb"DexGuard|guardsquare|iXGuard", re.IGNORECASE), "guardsquare"),
    (re.compile(rb"freeRASP|talsec|aheaditec", re.IGNORECASE), "talsec"),
    (re.compile(rb"appdome", re.IGNORECASE), "appdome"),
    (re.compile(rb"AppSealing|covault", re.IGNORECASE), "appsealing"),
    (re.compile(rb"DexProtector|dexprotector", re.IGNORECASE), "dexprotector"),
    (re.compile(rb"LIAPP|lockincomp", re.IGNORECASE), "liapp"),
    (re.compile(rb"arxan|digital\.ai", re.IGNORECASE), "arxan"),
]

# ── Layer 3: Java class/package prefixes ─────────────────────────────────────

RASP_CLASS_PREFIXES: list[tuple[str, str]] = [
    ("io/wultra/app/protection", "wultra"),
    ("com/wultra/android/powerauth", "wultra"),
    ("no/promon/shield", "promon"),
    ("no/promon/shieldlib", "promon"),
    ("com/guardsquare", "guardsquare"),
    ("com/aheaditec/talsec", "talsec"),
    ("com/appdome", "appdome"),
    ("com/lockincomp", "liapp"),
    ("com/arxan", "arxan"),
    ("com/digitalai", "arxan"),
    ("com/verimatrix/stublib", "verimatrix"),
    ("com/zimperium", "zimperium"),
    ("com/criticalblue/approovsdk", "approov"),
    ("net/pradeo", "pradeo"),
]

# ── Layer 4: Manifest component patterns ─────────────────────────────────────

RASP_MANIFEST_PATTERNS: list[tuple[str, str]] = [
    ("com.appdome.SdkService", "appdome"),
    ("no.promon.shield", "promon"),
    ("com.guardsquare", "guardsquare"),
    ("io.wultra.app.protection", "wultra"),
    ("com.aheaditec.talsec", "talsec"),
]


@dataclass
class ScanHit:
    vendor: str
    layer: str
    indicator: str
    detail: str = ""


@dataclass
class ScanResult:
    sha256: str
    pkg_name: str
    hits: list[ScanHit] = field(default_factory=list)
    vendors: set[str] = field(default_factory=set)
    error: str | None = None

    def add_hit(self, hit: ScanHit) -> None:
        self.hits.append(hit)
        self.vendors.add(hit.vendor)


def scan_layer1_zip_entries(apk_path: Path, result: ScanResult) -> None:
    """Layer 1: Scan ZIP entry names for known RASP native libraries."""
    try:
        with zipfile.ZipFile(apk_path) as z:
            for entry in z.namelist():
                if not (entry.startswith("lib/") and entry.endswith(".so")):
                    continue
                basename = entry.split("/")[-1].lower()
                for pattern, vendor in RASP_NATIVE_LIBS.items():
                    if pattern in basename:
                        result.add_hit(ScanHit(
                            vendor=vendor,
                            layer="native_lib",
                            indicator=pattern,
                            detail=entry,
                        ))
    except (zipfile.BadZipFile, OSError) as e:
        result.error = f"Layer 1 failed: {e}"


def scan_layer2_strings(apk_path: Path, result: ScanResult) -> None:
    """Layer 2: Scan raw bytes of DEX and SO files for RASP string patterns."""
    try:
        with zipfile.ZipFile(apk_path) as z:
            for entry in z.namelist():
                if not (entry.endswith(".dex") or
                        (entry.startswith("lib/") and entry.endswith(".so"))):
                    continue
                try:
                    data = z.read(entry)
                    for pattern, vendor in RASP_STRING_PATTERNS:
                        match = pattern.search(data)
                        if match:
                            result.add_hit(ScanHit(
                                vendor=vendor,
                                layer="string_pattern",
                                indicator=match.group(0).decode("utf-8", errors="replace"),
                                detail=entry,
                            ))
                except Exception:
                    continue
    except (zipfile.BadZipFile, OSError) as e:
        result.error = f"Layer 2 failed: {e}"


def scan_layer3_dex_classes(apk_path: Path, result: ScanResult) -> None:
    """Layer 3: Enumerate DEX class names for known RASP packages."""
    try:
        from androguard.core.apk import APK
        from androguard.core.dex import DEX

        apk = APK(str(apk_path))
        for dex_name in apk.get_dex_names():
            dex_data = apk.get_file(dex_name)
            if not dex_data:
                continue
            try:
                dex = DEX(dex_data)
                for cls in dex.get_classes():
                    cls_name = cls.get_name()
                    if not cls_name:
                        continue
                    # Normalize: "Lio/wultra/app/Foo;" → "io/wultra/app/Foo"
                    normalized = cls_name.lstrip("L").rstrip(";")
                    for prefix, vendor in RASP_CLASS_PREFIXES:
                        if normalized.startswith(prefix):
                            result.add_hit(ScanHit(
                                vendor=vendor,
                                layer="java_class",
                                indicator=prefix,
                                detail=cls_name,
                            ))
                            break  # One match per class is enough
            except Exception:
                continue
    except ImportError:
        pass  # androguard not installed — skip this layer
    except Exception as e:
        result.error = f"Layer 3 failed: {e}"


def scan_layer4_manifest(apk_path: Path, result: ScanResult) -> None:
    """Layer 4: Scan AndroidManifest.xml for RASP service components."""
    try:
        from androguard.core.apk import APK

        apk = APK(str(apk_path))
        components = (
            apk.get_activities() +
            apk.get_services() +
            apk.get_receivers() +
            apk.get_providers()
        )
        for component in components:
            for pattern, vendor in RASP_MANIFEST_PATTERNS:
                if pattern in component:
                    result.add_hit(ScanHit(
                        vendor=vendor,
                        layer="manifest_component",
                        indicator=pattern,
                        detail=component,
                    ))
    except ImportError:
        pass  # androguard not installed
    except Exception as e:
        result.error = f"Layer 4 failed: {e}"


def scan_apk(apk_path: Path, cascade: bool = True) -> ScanResult:
    """Run all scan layers on a single APK."""
    sha256 = apk_path.stem
    result = ScanResult(sha256=sha256, pkg_name="")

    # Layer 1: always run (free)
    scan_layer1_zip_entries(apk_path, result)

    # Layer 2: always run (fast)
    scan_layer2_strings(apk_path, result)

    # Layers 3 & 4: skip if cascade mode and we already found hits
    if cascade and len(result.vendors) > 0:
        return result

    scan_layer3_dex_classes(apk_path, result)
    scan_layer4_manifest(apk_path, result)

    return result


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Multi-layer APK RASP scanner")
    parser.add_argument("--dir", required=True, help="Directory containing APK files")
    parser.add_argument("--output", default="results/scan_results.json", help="Output JSON path")
    parser.add_argument("--no-cascade", action="store_true", help="Run all layers regardless of early hits")
    args = parser.parse_args()

    apk_dir = Path(args.dir)
    if not apk_dir.is_dir():
        print(f"[scanner] ERROR: {apk_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    apks = list(apk_dir.glob("*.apk"))
    print(f"[scanner] Scanning {len(apks)} APKs...")

    results = []
    rasp_count = 0

    for i, apk_path in enumerate(apks):
        result = scan_apk(apk_path, cascade=not args.no_cascade)
        if result.vendors:
            rasp_count += 1
            results.append(result)

        if (i + 1) % 100 == 0:
            print(f"[scanner] Progress: {i + 1}/{len(apks)} ({rasp_count} with RASP)")

    # Write results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    serializable = []
    for r in results:
        d = {
            "sha256": r.sha256,
            "vendors": sorted(r.vendors),
            "hits": [asdict(h) for h in r.hits],
        }
        if r.error:
            d["error"] = r.error
        serializable.append(d)

    with open(output_path, "w") as f:
        json.dump(serializable, f, indent=2)

    print(f"[scanner] Done. {rasp_count}/{len(apks)} APKs contain RASP indicators.")
    print(f"[scanner] Results written to {output_path}")

    # Print vendor distribution
    vendor_counts: dict[str, int] = {}
    for r in results:
        for v in r.vendors:
            vendor_counts[v] = vendor_counts.get(v, 0) + 1

    print("\n[scanner] Vendor distribution:")
    for vendor, count in sorted(vendor_counts.items(), key=lambda x: -x[1]):
        print(f"  {vendor}: {count}")


if __name__ == "__main__":
    main()
