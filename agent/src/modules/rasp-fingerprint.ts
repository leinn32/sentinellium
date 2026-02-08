/**
 * RaspFingerprinter — Identifies which RASP SDK protects the target app.
 *
 * What:  Scans loaded native libraries, Java classes, and runtime behaviors
 *        to match against a signature database of known RASP/protection SDKs.
 *
 * Why:   Before auditing a RASP implementation, you need to know *which* SDK
 *        the app uses. Different vendors (Wultra, Promon, Guardsquare, Appdome,
 *        Talsec) have different detection methods, native libraries, and bypass
 *        strategies. Auto-detecting the SDK makes Sentinellium immediately
 *        useful for comparative research and targeted auditing.
 *
 * RASP:  Directly useful for competitive analysis at a RASP vendor. Identifies
 *        which SDK a competitor uses and provides a starting point for evaluating
 *        their detection coverage. Also useful for penetration testers who need
 *        to quickly determine what protections they're facing.
 */

import { BaseHookModule, type ModuleConfig } from "../core/hook-module";

/** Confidence thresholds and scoring weights. */
const SCORE_NATIVE_LIB = 40;
const SCORE_JAVA_CLASS = 30;
const SCORE_STRING_PATTERN = 15;
const SCORE_BEHAVIORAL = 15;
const CONFIDENCE_THRESHOLD = 60;

/** Signature definition for a single RASP SDK. */
interface RaspSignature {
  display_name: string;
  indicators: {
    native_libs?: string[];
    java_classes?: string[];
    asset_files?: string[];
    string_patterns?: string[];
    manifest_components?: string[];
    dex_patterns?: string[];
    heuristic_native_behaviors?: string[];
  };
}

/** Parsed signatures config from YAML. */
interface SignaturesConfig {
  [sdkId: string]: RaspSignature;
}

/** Result of fingerprinting a single SDK candidate. */
interface CandidateResult {
  sdkId: string;
  displayName: string;
  confidence: number;
  matchedIndicators: string[];
}

export class RaspFingerprinter extends BaseHookModule {
  readonly id = "rasp-fingerprint";

  /** Signature database loaded from config. */
  private signatures: SignaturesConfig = {};

  constructor(config: ModuleConfig = {}) {
    super(config);

    // Signatures are passed from the host via the config block.
    // The host reads rasp-signatures.yaml and merges it into the
    // module config under the "signatures" key.
    const rawSigs = config["signatures"];
    if (rawSigs !== undefined && typeof rawSigs === "object" && rawSigs !== null) {
      this.signatures = rawSigs as SignaturesConfig;
    }
  }

  protected onEnable(): void {
    // Run fingerprinting as a one-shot scan.
    // Static analysis first, then behavioral if needed.
    const candidates = this.runStaticScan();
    const behavioral = this.runBehavioralScan();

    // Merge behavioral scores into candidates
    for (const result of behavioral) {
      const existing = candidates.find((c) => c.sdkId === result.sdkId);
      if (existing) {
        existing.confidence += result.confidence;
        existing.matchedIndicators.push(...result.matchedIndicators);
      } else {
        candidates.push(result);
      }
    }

    // Sort by confidence descending
    candidates.sort((a, b) => b.confidence - a.confidence);

    // Build the all_candidates map
    const allCandidates: Record<string, number> = {};
    for (const c of candidates) {
      if (c.confidence > 0 && c.sdkId !== "unknown") {
        allCandidates[c.sdkId] = c.confidence;
      }
    }

    // Determine the winner
    const top = candidates[0];
    if (top && top.confidence >= CONFIDENCE_THRESHOLD && top.sdkId !== "unknown") {
      this.emit("info", {
        event: "rasp_identified",
        detected_sdk: top.sdkId,
        detected_sdk_name: top.displayName,
        confidence: top.confidence,
        matched_indicators: top.matchedIndicators,
        all_candidates: allCandidates,
      });
    } else {
      // Check if we have any behavioral indicators suggesting custom RASP
      const unknownCandidate = candidates.find((c) => c.sdkId === "unknown");
      if (unknownCandidate && unknownCandidate.confidence > 0) {
        this.emit("info", {
          event: "rasp_unknown",
          detected_sdk: "unknown",
          detected_sdk_name: "Unknown/Custom RASP",
          confidence: unknownCandidate.confidence,
          matched_indicators: unknownCandidate.matchedIndicators,
          all_candidates: allCandidates,
          detail: "RASP-like behavior detected but no known SDK signature matched.",
        });
      } else {
        this.emit("info", {
          event: "no_rasp_detected",
          detected_sdk: "none",
          confidence: 0,
          all_candidates: allCandidates,
          detail: "No RASP SDK indicators found. App may be unprotected or using an unknown SDK.",
        });
      }
    }
  }

  protected onDisable(): void {
    // Scan-based module — nothing to detach.
  }

  /**
   * Static scan: enumerate loaded modules and Java classes against signatures.
   *
   * This runs immediately on attach and checks:
   * 1. Native libraries loaded in the process
   * 2. Java classes currently loaded in the VM
   * 3. String patterns in /proc/self/maps
   */
  private runStaticScan(): CandidateResult[] {
    const results: CandidateResult[] = [];

    // Collect loaded native module names
    const loadedModules = this.getLoadedModules();
    const loadedModuleNames = loadedModules.map((m) => m.name.toLowerCase());

    // Collect loaded Java classes
    const loadedClasses = this.getLoadedJavaClasses();

    // Read /proc/self/maps for string patterns
    const mapsContent = this.readProcMaps();

    for (const [sdkId, signature] of Object.entries(this.signatures)) {
      if (sdkId === "unknown") {
        continue; // Handle separately in behavioral scan
      }

      const result: CandidateResult = {
        sdkId,
        displayName: signature.display_name,
        confidence: 0,
        matchedIndicators: [],
      };

      // Check native libraries
      if (signature.indicators.native_libs) {
        for (const libPattern of signature.indicators.native_libs) {
          const matched = this.matchModulePattern(
            loadedModuleNames,
            libPattern.toLowerCase()
          );
          if (matched !== null) {
            result.confidence += SCORE_NATIVE_LIB;
            result.matchedIndicators.push(`native_lib:${matched}`);
          }
        }
      }

      // Check Java classes
      if (signature.indicators.java_classes) {
        for (const classPattern of signature.indicators.java_classes) {
          const matched = this.matchClassPattern(loadedClasses, classPattern);
          if (matched !== null) {
            result.confidence += SCORE_JAVA_CLASS;
            result.matchedIndicators.push(`java_class:${matched}`);
          }
        }
      }

      // Check string patterns in maps/modules
      if (signature.indicators.string_patterns) {
        for (const pattern of signature.indicators.string_patterns) {
          if (mapsContent.toLowerCase().includes(pattern.toLowerCase())) {
            result.confidence += SCORE_STRING_PATTERN;
            result.matchedIndicators.push(`string:${pattern}`);
          }
        }
      }

      if (result.confidence > 0) {
        results.push(result);
      }
    }

    return results;
  }

  /**
   * Behavioral scan: detect RASP-like behaviors that suggest protection
   * even when no known SDK signature matches.
   *
   * Checks for:
   * 1. ptrace self-attach (anti-debug)
   * 2. Thread scanning /proc/self/maps periodically
   * 3. JNI_OnLoad with integrity checks
   */
  private runBehavioralScan(): CandidateResult[] {
    const results: CandidateResult[] = [];
    const unknownResult: CandidateResult = {
      sdkId: "unknown",
      displayName: "Unknown/Custom RASP",
      confidence: 0,
      matchedIndicators: [],
    };

    // Check for anti-debug ptrace self-attach by looking for
    // TracerPid != 0 in /proc/self/status
    try {
      const status = this.readProcFile("/proc/self/status");
      const tracerMatch = status.match(/TracerPid:\s*(\d+)/);
      if (tracerMatch) {
        const tracerPid = parseInt(tracerMatch[1] ?? "0", 10);
        if (tracerPid !== 0) {
          unknownResult.confidence += SCORE_BEHAVIORAL;
          unknownResult.matchedIndicators.push(
            `behavior:ptrace_self_attach(tracer_pid=${tracerPid})`
          );
        }
      }
    } catch {
      // Can't read status — skip
    }

    // Check for suspicious thread names that indicate RASP monitoring threads
    try {
      const threads = Process.enumerateThreads();
      const suspiciousThreadPatterns = [
        "rasp", "shield", "protect", "guard", "integrity",
        "tamper", "security", "monitor", "watchdog",
      ];

      for (const thread of threads) {
        try {
          const commPath = `/proc/self/task/${thread.id}/comm`;
          const file = new File(commPath, "r");
          const name = file.readAllText().trim().toLowerCase();
          file.close();

          for (const pattern of suspiciousThreadPatterns) {
            if (name.includes(pattern)) {
              unknownResult.confidence += SCORE_BEHAVIORAL;
              unknownResult.matchedIndicators.push(
                `behavior:rasp_thread(${name})`
              );
              break;
            }
          }
        } catch {
          continue;
        }
      }
    } catch {
      // Thread enumeration failed — skip
    }

    // Check for anti-Frida measures (if the app has already tried to detect us)
    // by looking for common RASP signal handlers
    try {
      const modules = Process.enumerateModules();
      for (const mod of modules) {
        if (mod.path.includes("/data/app/") || mod.path.includes("/data/data/")) {
          // App's own native libs — check for RASP-like exports
          try {
            const exports = mod.enumerateExports();
            for (const exp of exports) {
              const lowerName = exp.name.toLowerCase();
              if (
                lowerName.includes("checkintegrity") ||
                lowerName.includes("antidebug") ||
                lowerName.includes("detecthook") ||
                lowerName.includes("checkroot") ||
                lowerName.includes("isfrida") ||
                lowerName.includes("antitamper")
              ) {
                unknownResult.confidence += SCORE_BEHAVIORAL;
                unknownResult.matchedIndicators.push(
                  `behavior:rasp_export(${mod.name}:${exp.name})`
                );
              }
            }
          } catch {
            continue;
          }
        }
      }
    } catch {
      // Module enumeration failed — skip
    }

    if (unknownResult.confidence > 0) {
      results.push(unknownResult);
    }

    return results;
  }

  /** Enumerate loaded native modules in the process. */
  private getLoadedModules(): { name: string; path: string }[] {
    try {
      return Process.enumerateModules().map((m) => ({
        name: m.name,
        path: m.path,
      }));
    } catch {
      return [];
    }
  }

  /** Enumerate loaded Java classes in the VM. */
  private getLoadedJavaClasses(): string[] {
    const classes: string[] = [];
    try {
      if (Java.available) {
        Java.performNow(() => {
          Java.enumerateLoadedClasses({
            onMatch(name) {
              classes.push(name);
            },
            onComplete() {
              // done
            },
          });
        });
      }
    } catch {
      this.emit("info", {
        event: "java_enum_failed",
        detail: "Could not enumerate Java classes — VM may not be available",
      });
    }
    return classes;
  }

  /** Read /proc/self/maps as a single string. */
  private readProcMaps(): string {
    return this.readProcFile("/proc/self/maps");
  }

  /** Read a proc filesystem file. */
  private readProcFile(path: string): string {
    try {
      const file = new File(path, "r");
      const content = file.readAllText();
      file.close();
      return content;
    } catch {
      return "";
    }
  }

  /**
   * Match a module name against a pattern that supports trailing wildcards.
   * e.g., "libWultra*.so" matches "libWultraAppProtection.so"
   */
  private matchModulePattern(
    moduleNames: string[],
    pattern: string
  ): string | null {
    if (pattern.includes("*")) {
      const regex = new RegExp(
        "^" +
          pattern
            .replace(/[.+^${}()|[\]\\]/g, "\\$&")
            .replace(/\*/g, ".*") +
          "$",
        "i"
      );
      for (const name of moduleNames) {
        if (regex.test(name)) {
          return name;
        }
      }
    } else {
      for (const name of moduleNames) {
        if (name === pattern) {
          return name;
        }
      }
    }
    return null;
  }

  /**
   * Match a Java class name against a pattern with wildcard support.
   * e.g., "io.wultra.app.protection.*" matches "io.wultra.app.protection.RaspManager"
   *
   * Converts Java class dots to slashes for comparison since Frida
   * reports classes in JNI format (e.g., "Lio/wultra/app/protection/RaspManager;").
   */
  private matchClassPattern(
    classNames: string[],
    pattern: string
  ): string | null {
    // Normalize pattern: handle both dot and slash notation
    const dotPattern = pattern.replace(/\//g, ".");
    const slashPattern = pattern.replace(/\./g, "/");

    if (dotPattern.endsWith(".*")) {
      // Package wildcard: match any class in the package
      const packagePrefix = dotPattern.slice(0, -2);
      const slashPrefix = slashPattern.slice(0, -2);

      for (const cls of classNames) {
        // Handle JNI format: "Lio/wultra/app/protection/Foo;"
        const normalized = cls.replace(/^L/, "").replace(/;$/, "");
        if (
          normalized.startsWith(slashPrefix + "/") ||
          cls.startsWith(packagePrefix + ".")
        ) {
          return cls;
        }
      }
    } else {
      // Exact class match
      for (const cls of classNames) {
        const normalized = cls
          .replace(/^L/, "")
          .replace(/;$/, "")
          .replace(/\//g, ".");
        if (normalized === dotPattern || cls === dotPattern) {
          return cls;
        }
      }
    }
    return null;
  }
}
