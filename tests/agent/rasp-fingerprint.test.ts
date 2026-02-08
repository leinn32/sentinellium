/**
 * Tests for RaspFingerprinter — module pattern matching, class pattern
 * matching, confidence scoring, and candidate ranking.
 *
 * Frida APIs are unavailable in vitest, so we replicate the pure logic
 * portions of the module for unit testing.
 */

import { describe, it, expect } from "vitest";

/** Scoring weights — replicated from RaspFingerprinter. */
const SCORE_NATIVE_LIB = 40;
const SCORE_JAVA_CLASS = 30;
const SCORE_STRING_PATTERN = 15;
const SCORE_BEHAVIORAL = 15;
const CONFIDENCE_THRESHOLD = 60;

/** Replicated from RaspFingerprinter.matchModulePattern. */
function matchModulePattern(
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

/** Replicated from RaspFingerprinter.matchClassPattern. */
function matchClassPattern(
  classNames: string[],
  pattern: string
): string | null {
  const dotPattern = pattern.replace(/\//g, ".");
  const slashPattern = pattern.replace(/\./g, "/");

  if (dotPattern.endsWith(".*")) {
    const packagePrefix = dotPattern.slice(0, -2);
    const slashPrefix = slashPattern.slice(0, -2);

    for (const cls of classNames) {
      const normalized = cls.replace(/^L/, "").replace(/;$/, "");
      if (
        normalized.startsWith(slashPrefix + "/") ||
        cls.startsWith(packagePrefix + ".")
      ) {
        return cls;
      }
    }
  } else {
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

describe("RaspFingerprinter module pattern matching", () => {
  const loadedModules = [
    "libc.so",
    "libart.so",
    "libwultraappprotection.so",
    "libpromon.so",
    "libssl.so",
    "libapp-native.so",
  ];

  it("should match exact library name", () => {
    expect(matchModulePattern(loadedModules, "libpromon.so")).toBe(
      "libpromon.so"
    );
  });

  it("should match wildcard pattern: libwultra*.so", () => {
    expect(matchModulePattern(loadedModules, "libwultra*.so")).toBe(
      "libwultraappprotection.so"
    );
  });

  it("should return null for missing library", () => {
    expect(matchModulePattern(loadedModules, "libfoo.so")).toBeNull();
  });

  it("should be case-insensitive for wildcard matching", () => {
    expect(matchModulePattern(loadedModules, "LIBWULTRA*.SO")).toBe(
      "libwultraappprotection.so"
    );
  });

  it("should match wildcard in middle: lib*native.so", () => {
    expect(matchModulePattern(loadedModules, "lib*native.so")).toBe(
      "libapp-native.so"
    );
  });

  it("should not partial-match without wildcard", () => {
    expect(matchModulePattern(loadedModules, "libwultra")).toBeNull();
  });

  it("should handle pattern with only wildcards", () => {
    expect(matchModulePattern(loadedModules, "*.so")).toBe("libc.so");
  });
});

describe("RaspFingerprinter class pattern matching", () => {
  const loadedClasses = [
    "Lio/wultra/app/protection/RaspManager;",
    "Lio/wultra/app/protection/Config;",
    "Lcom/promon/shield/ShieldManager;",
    "Lcom/example/app/MainActivity;",
    "com.guardsquare.dexguard.runtime.Detection",
  ];

  it("should match package wildcard in JNI format", () => {
    const result = matchClassPattern(
      loadedClasses,
      "io.wultra.app.protection.*"
    );
    expect(result).toBe("Lio/wultra/app/protection/RaspManager;");
  });

  it("should match exact class name in dot notation", () => {
    const result = matchClassPattern(
      loadedClasses,
      "com.guardsquare.dexguard.runtime.Detection"
    );
    expect(result).toBe("com.guardsquare.dexguard.runtime.Detection");
  });

  it("should match exact class name from JNI format", () => {
    const result = matchClassPattern(
      loadedClasses,
      "com.promon.shield.ShieldManager"
    );
    expect(result).toBe("Lcom/promon/shield/ShieldManager;");
  });

  it("should return null for unmatched class", () => {
    const result = matchClassPattern(
      loadedClasses,
      "com.nonexistent.SomeClass"
    );
    expect(result).toBeNull();
  });

  it("should return null for unmatched package wildcard", () => {
    const result = matchClassPattern(
      loadedClasses,
      "com.appdome.protection.*"
    );
    expect(result).toBeNull();
  });

  it("should handle slash notation in pattern", () => {
    const result = matchClassPattern(
      loadedClasses,
      "io/wultra/app/protection/*"
    );
    expect(result).toBe("Lio/wultra/app/protection/RaspManager;");
  });
});

describe("RaspFingerprinter confidence scoring", () => {
  interface CandidateResult {
    sdkId: string;
    displayName: string;
    confidence: number;
    matchedIndicators: string[];
  }

  /** Simplified scoring engine that mirrors the real module's logic. */
  function scoreCandidate(
    nativeLibMatches: number,
    javaClassMatches: number,
    stringMatches: number,
    behavioralMatches: number
  ): number {
    return (
      nativeLibMatches * SCORE_NATIVE_LIB +
      javaClassMatches * SCORE_JAVA_CLASS +
      stringMatches * SCORE_STRING_PATTERN +
      behavioralMatches * SCORE_BEHAVIORAL
    );
  }

  it("should reach threshold with native lib + java class", () => {
    const score = scoreCandidate(1, 1, 0, 0);
    expect(score).toBe(70);
    expect(score).toBeGreaterThanOrEqual(CONFIDENCE_THRESHOLD);
  });

  it("should reach threshold with native lib + string + behavioral", () => {
    const score = scoreCandidate(1, 0, 1, 1);
    expect(score).toBe(70);
    expect(score).toBeGreaterThanOrEqual(CONFIDENCE_THRESHOLD);
  });

  it("should NOT reach threshold with only java class + string", () => {
    const score = scoreCandidate(0, 1, 1, 0);
    expect(score).toBe(45);
    expect(score).toBeLessThan(CONFIDENCE_THRESHOLD);
  });

  it("should NOT reach threshold with only a native lib", () => {
    const score = scoreCandidate(1, 0, 0, 0);
    expect(score).toBe(40);
    expect(score).toBeLessThan(CONFIDENCE_THRESHOLD);
  });

  it("should rank candidates by confidence descending", () => {
    const candidates: CandidateResult[] = [
      { sdkId: "wultra", displayName: "Wultra", confidence: 70, matchedIndicators: [] },
      { sdkId: "promon", displayName: "Promon", confidence: 85, matchedIndicators: [] },
      { sdkId: "talsec", displayName: "Talsec", confidence: 40, matchedIndicators: [] },
    ];

    candidates.sort((a, b) => b.confidence - a.confidence);

    expect(candidates[0]!.sdkId).toBe("promon");
    expect(candidates[1]!.sdkId).toBe("wultra");
    expect(candidates[2]!.sdkId).toBe("talsec");
  });

  it("should select top candidate only if above threshold", () => {
    const candidates: CandidateResult[] = [
      { sdkId: "talsec", displayName: "Talsec", confidence: 40, matchedIndicators: [] },
      { sdkId: "unknown", displayName: "Unknown", confidence: 15, matchedIndicators: [] },
    ];

    candidates.sort((a, b) => b.confidence - a.confidence);
    const top = candidates[0]!;

    const detected =
      top.confidence >= CONFIDENCE_THRESHOLD && top.sdkId !== "unknown";
    expect(detected).toBe(false);
  });

  it("should produce high confidence for multiple indicators", () => {
    // 2 native libs + 1 java class + 1 string
    const score = scoreCandidate(2, 1, 1, 0);
    expect(score).toBe(125);
    expect(score).toBeGreaterThanOrEqual(CONFIDENCE_THRESHOLD);
  });
});

describe("RaspFingerprinter string pattern matching", () => {
  /** Replicated maps content string matching. */
  function matchStringPattern(
    mapsContent: string,
    pattern: string
  ): boolean {
    return mapsContent.toLowerCase().includes(pattern.toLowerCase());
  }

  const sampleMaps = [
    "7f000000-7f001000 r-xp 00000000 fd:00 12345 /data/app/com.example/lib/arm64/libWultraAppProtection.so",
    "7f002000-7f003000 r-xp 00000000 fd:00 12346 /system/lib64/libc.so",
    "7f004000-7f005000 r--p 00000000 fd:00 12347 /data/app/com.example/base.apk",
  ].join("\n");

  it("should match Wultra string in maps", () => {
    expect(matchStringPattern(sampleMaps, "wultra")).toBe(true);
  });

  it("should match case-insensitively", () => {
    expect(matchStringPattern(sampleMaps, "WULTRA")).toBe(true);
  });

  it("should not match absent pattern", () => {
    expect(matchStringPattern(sampleMaps, "promon")).toBe(false);
  });

  it("should match partial string in path", () => {
    expect(matchStringPattern(sampleMaps, "AppProtection")).toBe(true);
  });
});
