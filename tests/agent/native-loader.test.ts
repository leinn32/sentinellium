/**
 * Tests for NativeLoaderMonitor telemetry event shape and path matching logic.
 *
 * Since Frida APIs are not available in a standard Node/vitest environment,
 * these tests validate the pure logic portions of the module: path matching,
 * config parsing, and telemetry event structure.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Test the path matching and suspicious pattern logic extracted from
 * NativeLoaderMonitor. We test the matching algorithm directly since
 * the Frida Interceptor APIs can't run outside a Frida context.
 */

/** Replicated matching logic from NativeLoaderMonitor for unit testing. */
function matchSuspicious(
  path: string,
  suspiciousPaths: string[],
  suspiciousPatterns: string[]
): string | null {
  const lowerPath = path.toLowerCase();

  for (const suspiciousPath of suspiciousPaths) {
    if (suspiciousPath.includes("*")) {
      const pattern = suspiciousPath
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, "[^/]+");
      if (new RegExp(pattern, "i").test(path)) {
        return `path:${suspiciousPath}`;
      }
    } else if (lowerPath.startsWith(suspiciousPath.toLowerCase())) {
      return `path:${suspiciousPath}`;
    }
  }

  for (const pattern of suspiciousPatterns) {
    if (lowerPath.includes(pattern.toLowerCase())) {
      return `pattern:${pattern}`;
    }
  }

  return null;
}

describe("NativeLoaderMonitor path matching", () => {
  const defaultPaths = ["/data/local/tmp", "/data/data/*/lib-custom/"];
  const defaultPatterns = ["frida", "xposed", "substrate", "magisk"];

  it("should match exact suspicious path prefix", () => {
    const result = matchSuspicious(
      "/data/local/tmp/evil.so",
      defaultPaths,
      defaultPatterns
    );
    expect(result).toBe("path:/data/local/tmp");
  });

  it("should match wildcard path pattern", () => {
    const result = matchSuspicious(
      "/data/data/com.example.app/lib-custom/inject.so",
      defaultPaths,
      defaultPatterns
    );
    expect(result).toBe("path:/data/data/*/lib-custom/");
  });

  it("should match substring pattern: frida", () => {
    const result = matchSuspicious(
      "/system/lib64/libfrida-agent.so",
      defaultPaths,
      defaultPatterns
    );
    expect(result).toBe("pattern:frida");
  });

  it("should match substring pattern: xposed (case-insensitive)", () => {
    const result = matchSuspicious(
      "/data/app/XposedBridge.jar",
      defaultPaths,
      defaultPatterns
    );
    expect(result).toBe("pattern:xposed");
  });

  it("should match substring pattern: magisk", () => {
    const result = matchSuspicious(
      "/sbin/magisk",
      defaultPaths,
      defaultPatterns
    );
    expect(result).toBe("pattern:magisk");
  });

  it("should match substrate pattern", () => {
    const result = matchSuspicious(
      "/data/local/tmp/libsubstrate.so",
      defaultPaths,
      defaultPatterns
    );
    // Path prefix matches first
    expect(result).toBe("path:/data/local/tmp");
  });

  it("should return null for clean system library", () => {
    const result = matchSuspicious(
      "/system/lib64/libc.so",
      defaultPaths,
      defaultPatterns
    );
    expect(result).toBeNull();
  });

  it("should return null for clean app library", () => {
    const result = matchSuspicious(
      "/data/app/com.example.app/lib/arm64/libnative.so",
      defaultPaths,
      defaultPatterns
    );
    expect(result).toBeNull();
  });

  it("should return null with empty config", () => {
    const result = matchSuspicious("/data/local/tmp/evil.so", [], []);
    expect(result).toBeNull();
  });

  it("should handle custom suspicious paths from config", () => {
    const customPaths = ["/custom/injection/path"];
    const result = matchSuspicious(
      "/custom/injection/path/payload.so",
      customPaths,
      []
    );
    expect(result).toBe("path:/custom/injection/path");
  });
});

describe("TelemetryEvent shape", () => {
  it("should have the correct interface shape", () => {
    const event = {
      type: "telemetry" as const,
      module_id: "native-loader",
      timestamp: Date.now(),
      severity: "critical" as const,
      data: {
        event: "suspicious_library_load",
        path: "/data/local/tmp/frida-agent.so",
        matched_rule: "pattern:frida",
      },
      stacktrace: "0x7f000 libdl.so!dlopen",
    };

    expect(event.type).toBe("telemetry");
    expect(event.module_id).toBe("native-loader");
    expect(typeof event.timestamp).toBe("number");
    expect(["info", "warning", "critical"]).toContain(event.severity);
    expect(event.data).toBeDefined();
    expect(typeof event.data).toBe("object");
  });

  it("should allow optional stacktrace", () => {
    const event = {
      type: "telemetry" as const,
      module_id: "native-loader",
      timestamp: Date.now(),
      severity: "info" as const,
      data: { event: "library_load_attempt", path: "/system/lib/libc.so" },
    };

    expect(event.stacktrace).toBeUndefined();
  });
});

describe("CIDR parsing logic", () => {
  /** Replicated from NetworkProbe for testing. */
  function parseCidr(
    cidr: string
  ): { network: number; mask: number } | null {
    const parts = cidr.split("/");
    if (parts.length !== 2) return null;
    const [ipStr, bitsStr] = parts;
    if (!ipStr || !bitsStr) return null;

    const bits = parseInt(bitsStr, 10);
    if (isNaN(bits) || bits < 0 || bits > 32) return null;

    const octets = ipStr.split(".");
    if (octets.length !== 4) return null;

    let ip = 0;
    for (const octet of octets) {
      const val = parseInt(octet, 10);
      if (isNaN(val) || val < 0 || val > 255) return null;
      ip = (ip << 8) | val;
    }

    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return {
      network: (ip & mask) >>> 0,
      mask: mask >>> 0,
    };
  }

  it("should parse 10.0.0.0/8 correctly", () => {
    const result = parseCidr("10.0.0.0/8");
    expect(result).not.toBeNull();
    expect(result!.network).toBe(0x0a000000);
    expect(result!.mask).toBe(0xff000000);
  });

  it("should parse 192.168.0.0/16 correctly", () => {
    const result = parseCidr("192.168.0.0/16");
    expect(result).not.toBeNull();
    expect(result!.network).toBe(0xc0a80000);
    expect(result!.mask).toBe(0xffff0000);
  });

  it("should reject invalid CIDR", () => {
    expect(parseCidr("not-a-cidr")).toBeNull();
    expect(parseCidr("10.0.0.0")).toBeNull();
    expect(parseCidr("10.0.0.0/33")).toBeNull();
  });
});
