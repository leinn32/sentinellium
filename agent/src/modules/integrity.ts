/**
 * IntegrityBaseline — Detects runtime code patching via memory hashing.
 *
 * What:  On attach, snapshots SHA-256 hashes of the .text (executable code)
 *        sections of key loaded native libraries. Periodically re-hashes and
 *        alerts if any bytes have changed.
 *
 * Why:   Runtime patching (via Frida's Memory.patchCode, manual mprotect+write,
 *        or other instrumentation frameworks) modifies executable memory in-place.
 *        RASP SDKs use similar integrity checks to detect tampering. This module
 *        provides an independent baseline to audit whether such patches are
 *        detectable and whether the RASP's own integrity checks are functioning.
 *
 * RASP:  Directly mirrors Wultra's code integrity features. Demonstrates
 *        understanding of how RASP products detect hooking frameworks at the
 *        memory level and validates the integrity checking interval sensitivity.
 */

import { BaseHookModule, type ModuleConfig } from "../core/hook-module";

/** Chunk size for processing large .text sections without blocking main thread. */
const CHUNK_SIZE = 65536; // 64KB

interface BaselineEntry {
  moduleName: string;
  baseAddress: string;
  size: number;
  hash: string;
}

export class IntegrityBaseline extends BaseHookModule {
  readonly id = "integrity";

  /** Baseline hashes keyed by "module_name+base_address". */
  private baselines: Map<string, BaselineEntry> = new Map();

  /** Handle for the periodic re-check interval. */
  private intervalHandle: ReturnType<typeof setInterval> | null = null;

  /** Libraries to watch — configurable via YAML. */
  private watchedLibs: string[];

  /** Re-check interval in seconds — configurable. */
  private intervalSeconds: number;

  constructor(config: ModuleConfig = {}) {
    super(config);
    this.watchedLibs = this.configValue<string[]>("watched_libs", [
      "libart.so",
    ]);
    this.intervalSeconds = this.configValue<number>("interval_seconds", 5);
  }

  protected onEnable(): void {
    this.buildBaseline();

    if (this.baselines.size === 0) {
      this.emit("warning", {
        event: "no_baseline",
        detail: "No executable sections found for watched libraries",
        watched_libs: this.watchedLibs,
      });
      return;
    }

    this.emit("info", {
      event: "baseline_established",
      sections: this.baselines.size,
      libraries: [...new Set([...this.baselines.values()].map((b) => b.moduleName))],
    });

    // Start periodic integrity checks
    this.intervalHandle = setInterval(() => {
      this.checkIntegrity();
    }, this.intervalSeconds * 1000);
  }

  protected onDisable(): void {
    if (this.intervalHandle !== null) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }
    this.baselines.clear();
  }

  /**
   * Build initial baseline hashes for all executable sections of watched libraries.
   *
   * Uses Module.enumerateRanges('r-x') to find executable segments, which
   * correspond to .text sections and other code segments. We hash the raw
   * bytes to establish a baseline for later comparison.
   *
   * Also discovers the target app's own .so files via Process.enumerateModules()
   * to automatically include them without requiring explicit configuration.
   */
  private buildBaseline(): void {
    // Build the full list of libraries to watch
    const targetLibs = new Set(this.watchedLibs.map((l) => l.toLowerCase()));

    // Auto-discover app-specific native libraries
    const modules = Process.enumerateModules();
    for (const mod of modules) {
      // Include libs from the app's data directory (not system libs)
      if (
        mod.path.includes("/data/app/") ||
        mod.path.includes("/data/data/")
      ) {
        targetLibs.add(mod.name.toLowerCase());
      }
    }

    for (const mod of modules) {
      if (!targetLibs.has(mod.name.toLowerCase())) {
        continue;
      }

      try {
        const ranges = mod.enumerateRanges("r-x");
        for (const range of ranges) {
          const key = `${mod.name}+${range.base}`;
          const hash = this.hashMemoryRegion(range.base, range.size);

          if (hash !== null) {
            this.baselines.set(key, {
              moduleName: mod.name,
              baseAddress: range.base.toString(),
              size: range.size,
              hash,
            });
          }
        }
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        this.emit("warning", {
          event: "baseline_failed",
          library: mod.name,
          error: msg,
        });
      }
    }
  }

  /**
   * Re-hash all baselined sections and compare against stored hashes.
   * Emits "critical" for any mismatch — indicating runtime code modification.
   */
  private checkIntegrity(): void {
    let violations = 0;

    for (const [key, baseline] of this.baselines.entries()) {
      try {
        const base = ptr(baseline.baseAddress);
        const currentHash = this.hashMemoryRegion(base, baseline.size);

        if (currentHash === null) {
          this.emit("warning", {
            event: "hash_failed",
            library: baseline.moduleName,
            address: baseline.baseAddress,
            detail: "Could not read memory region — module may have been unloaded",
          });
          continue;
        }

        if (currentHash !== baseline.hash) {
          violations++;
          this.emit("critical", {
            event: "integrity_violation",
            library: baseline.moduleName,
            section_base: baseline.baseAddress,
            section_size: baseline.size,
            expected_hash: baseline.hash,
            actual_hash: currentHash,
            detail:
              "Executable code has been modified at runtime. This indicates " +
              "active hooking or memory patching.",
          });
        }
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        this.emit("warning", {
          event: "check_error",
          key,
          error: msg,
        });
      }
    }

    if (violations === 0) {
      this.emit("info", {
        event: "integrity_check_passed",
        sections_verified: this.baselines.size,
      });
    }
  }

  /**
   * Compute SHA-256 hash of a memory region, processing in chunks
   * to avoid blocking the main thread for large sections.
   *
   * Returns hex-encoded hash string, or null if the region is unreadable.
   */
  private hashMemoryRegion(base: NativePointer, size: number): string | null {
    try {
      // For small regions, hash in one shot
      if (size <= CHUNK_SIZE) {
        const bytes = base.readByteArray(size);
        if (bytes === null) {
          return null;
        }
        return this.sha256(bytes);
      }

      // For large regions, hash in chunks and combine
      // We read and hash the full region but in manageable pieces
      // to reduce the risk of blocking the app's main thread
      const chunkHashes: string[] = [];
      let offset = 0;

      while (offset < size) {
        const chunkLen = Math.min(CHUNK_SIZE, size - offset);
        const bytes = base.add(offset).readByteArray(chunkLen);
        if (bytes === null) {
          return null;
        }
        chunkHashes.push(this.sha256(bytes));
        offset += chunkLen;
      }

      // Hash the concatenated chunk hashes for a final digest
      const combined = chunkHashes.join("");
      // Convert string to ArrayBuffer for hashing
      const encoder = new ArrayBuffer(combined.length * 2);
      const view = new Uint8Array(encoder);
      for (let i = 0; i < combined.length; i++) {
        view[i] = combined.charCodeAt(i) & 0xff;
      }
      return this.sha256(encoder);
    } catch {
      return null;
    }
  }

  /**
   * Compute SHA-256 hash using Frida's built-in Checksum API.
   * Returns lowercase hex string.
   */
  private sha256(data: ArrayBuffer): string {
    const checksum = new Checksum("sha256");
    checksum.update(data);
    return checksum.getString();
  }
}
