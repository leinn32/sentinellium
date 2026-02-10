"""
AndroZoo Collector — Filters the APK index and downloads candidates.

Selects APKs likely to contain commercial RASP SDKs (Play Store, large size)
and downloads them in rate-limited batches for scanning.

Usage:
    python collector.py --csv latest_with-added-date.csv.gz --batch 2000
"""

from __future__ import annotations

import csv
import gzip
import os
import sys
from pathlib import Path

import requests
import yaml


def load_config(config_path: str = "config.yaml") -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def download_csv_index(url: str, dest: Path) -> Path:
    """Download the AndroZoo CSV index if not already cached."""
    if dest.exists():
        print(f"[collector] Using cached CSV index: {dest}")
        return dest

    print(f"[collector] Downloading CSV index from {url}...")
    resp = requests.get(url, stream=True, timeout=300)
    resp.raise_for_status()

    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as f:
        for chunk in resp.iter_content(8192):
            f.write(chunk)

    print(f"[collector] Downloaded {dest.stat().st_size / 1_000_000:.1f} MB")
    return dest


def filter_candidates(
    csv_path: Path,
    markets_filter: list[str],
    min_apk_size: int,
    max_samples: int,
) -> list[dict]:
    """Select APK candidates from the AndroZoo CSV index."""
    candidates = []
    opener = gzip.open if csv_path.suffix == ".gz" else open

    print(f"[collector] Filtering candidates from {csv_path}...")
    with opener(csv_path, "rt", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            markets = row.get("markets", "")
            apk_size = int(row.get("apk_size", 0))

            # Filter: must be from target markets and above minimum size
            if not any(m in markets for m in markets_filter):
                continue
            if apk_size < min_apk_size:
                continue

            candidates.append({
                "sha256": row["sha256"],
                "pkg_name": row.get("pkg_name", ""),
                "apk_size": apk_size,
                "vt_detection": int(row.get("vt_detection", 0)),
            })

            if len(candidates) >= max_samples:
                break

    print(f"[collector] Selected {len(candidates)} candidates")
    return candidates


def download_apk(sha256: str, api_key: str, output_dir: Path) -> Path | None:
    """Download a single APK from AndroZoo. Returns path or None on failure."""
    dest = output_dir / f"{sha256}.apk"
    if dest.exists():
        return dest

    try:
        resp = requests.get(
            "https://androzoo.uni.lu/api/download",
            params={"apikey": api_key, "sha256": sha256},
            stream=True,
            timeout=120,
        )
        resp.raise_for_status()

        with open(dest, "wb") as f:
            for chunk in resp.iter_content(8192):
                f.write(chunk)

        return dest
    except Exception as e:
        print(f"[collector] Failed to download {sha256[:12]}...: {e}", file=sys.stderr)
        return None


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="AndroZoo RASP intelligence collector")
    parser.add_argument("--config", default="config.yaml", help="Pipeline config path")
    parser.add_argument("--csv", help="Path to AndroZoo CSV (downloads if not provided)")
    parser.add_argument("--batch", type=int, help="Override batch size")
    parser.add_argument("--download", action="store_true", help="Download APKs (default: filter only)")
    args = parser.parse_args()

    config = load_config(args.config)
    api_key = os.environ.get("ANDROZOO_API_KEY", config["androzoo"].get("api_key", ""))

    # Get CSV index
    if args.csv:
        csv_path = Path(args.csv)
    else:
        csv_path = Path(config["collection"]["download_dir"]) / "latest.csv.gz"
        download_csv_index(config["androzoo"]["csv_url"], csv_path)

    # Filter candidates
    batch_size = args.batch or config["collection"]["batch_size"]
    candidates = filter_candidates(
        csv_path,
        config["collection"]["markets_filter"],
        config["collection"]["min_apk_size"],
        batch_size,
    )

    # Save candidate list
    results_dir = Path(config["collection"]["results_dir"])
    results_dir.mkdir(parents=True, exist_ok=True)
    candidates_file = results_dir / "candidates.csv"
    with open(candidates_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["sha256", "pkg_name", "apk_size", "vt_detection"])
        writer.writeheader()
        writer.writerows(candidates)
    print(f"[collector] Wrote {len(candidates)} candidates to {candidates_file}")

    # Optionally download
    if args.download:
        if not api_key:
            print("[collector] ERROR: Set ANDROZOO_API_KEY env var or config.yaml", file=sys.stderr)
            sys.exit(1)

        output_dir = Path(config["collection"]["download_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)

        downloaded = 0
        for i, candidate in enumerate(candidates):
            result = download_apk(candidate["sha256"], api_key, output_dir)
            if result:
                downloaded += 1
            if (i + 1) % 100 == 0:
                print(f"[collector] Progress: {i + 1}/{len(candidates)} ({downloaded} downloaded)")

        print(f"[collector] Downloaded {downloaded}/{len(candidates)} APKs")


if __name__ == "__main__":
    main()
