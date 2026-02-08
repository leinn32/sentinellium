/**
 * Tests for FridaDetectionAuditor — trampoline pattern matching and
 * memory map marker detection logic.
 *
 * Frida APIs are unavailable in vitest, so we replicate the pure logic
 * portions of the module for unit testing.
 */

import { describe, it, expect } from "vitest";

/** Frida inline hook trampoline signature for arm64. */
const ARM64_TRAMPOLINE: number[] = [
  0x50, 0x00, 0x00, 0x58, // LDR X16, #8
  0x00, 0x02, 0x1f, 0xd6, // BR X16
];

/** Frida inline hook trampoline signature for arm32. */
const ARM32_TRAMPOLINE: number[] = [
  0x00, 0x00, 0x9f, 0xe5, // LDR PC, [PC, #0]
];

/** Replicated from FridaDetectionAuditor.matchesPattern. */
function matchesPattern(bytes: Uint8Array, pattern: number[]): boolean {
  for (let i = 0; i < pattern.length; i++) {
    const expected = pattern[i];
    if (expected === undefined || bytes[i] !== expected) {
      return false;
    }
  }
  return true;
}

/** Replicated memory maps marker matching logic. */
function findMapMarkers(
  lines: string[],
  markers: string[]
): { marker: string; line: string }[] {
  const hits: { marker: string; line: string }[] = [];
  for (const line of lines) {
    for (const marker of markers) {
      if (line.toLowerCase().includes(marker)) {
        hits.push({ marker, line: line.trim() });
      }
    }
  }
  return hits;
}

describe("FridaDetectionAuditor trampoline matching", () => {
  it("should detect arm64 trampoline signature", () => {
    const bytes = new Uint8Array([
      0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    expect(matchesPattern(bytes, ARM64_TRAMPOLINE)).toBe(true);
  });

  it("should detect arm32 trampoline signature", () => {
    const bytes = new Uint8Array([
      0x00, 0x00, 0x9f, 0xe5, 0x78, 0x56, 0x34, 0x12,
    ]);
    expect(matchesPattern(bytes, ARM32_TRAMPOLINE)).toBe(true);
  });

  it("should reject non-matching bytes for arm64", () => {
    // Normal function prologue (STP X29, X30, [SP, #-16]!)
    const bytes = new Uint8Array([
      0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91,
    ]);
    expect(matchesPattern(bytes, ARM64_TRAMPOLINE)).toBe(false);
  });

  it("should reject non-matching bytes for arm32", () => {
    const bytes = new Uint8Array([0x04, 0xe0, 0x2d, 0xe5]);
    expect(matchesPattern(bytes, ARM32_TRAMPOLINE)).toBe(false);
  });

  it("should reject empty byte array", () => {
    const bytes = new Uint8Array([]);
    expect(matchesPattern(bytes, ARM64_TRAMPOLINE)).toBe(false);
  });

  it("should reject partial match", () => {
    // First two bytes match arm64 but rest diverges
    const bytes = new Uint8Array([
      0x50, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]);
    expect(matchesPattern(bytes, ARM64_TRAMPOLINE)).toBe(false);
  });
});

describe("FridaDetectionAuditor memory map scanning", () => {
  const defaultMarkers = ["frida-agent", "frida-gadget", "gmain"];

  it("should detect frida-agent in maps", () => {
    const lines = [
      "7f000000-7f001000 r-xp 00000000 fd:00 12345 /data/local/tmp/re.frida.server/frida-agent-64.so",
      "7f002000-7f003000 r--p 00000000 fd:00 12346 /system/lib64/libc.so",
    ];
    const hits = findMapMarkers(lines, defaultMarkers);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.marker).toBe("frida-agent");
  });

  it("should detect frida-gadget in maps", () => {
    const lines = [
      "7a000000-7a001000 r-xp 00000000 fd:00 99999 /data/app/com.example/lib/arm64/libfrida-gadget.so",
    ];
    const hits = findMapMarkers(lines, defaultMarkers);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.marker).toBe("frida-gadget");
  });

  it("should detect gmain thread mapping", () => {
    const lines = [
      "7b000000-7b001000 r-xp 00000000 fd:00 11111 /tmp/frida-1234/gmain",
    ];
    const hits = findMapMarkers(lines, defaultMarkers);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.marker).toBe("gmain");
  });

  it("should return empty for clean maps", () => {
    const lines = [
      "7f000000-7f001000 r-xp 00000000 fd:00 12345 /system/lib64/libc.so",
      "7f002000-7f003000 r-xp 00000000 fd:00 12346 /system/lib64/libart.so",
      "7f004000-7f005000 rw-p 00000000 00:00 0      [stack]",
    ];
    const hits = findMapMarkers(lines, defaultMarkers);
    expect(hits).toHaveLength(0);
  });

  it("should detect multiple markers in a single scan", () => {
    const lines = [
      "7f000000-7f001000 r-xp /data/local/tmp/re.frida.server/frida-agent-64.so",
      "7f002000-7f003000 r-xp /tmp/frida-1234/gmain",
    ];
    const hits = findMapMarkers(lines, defaultMarkers);
    expect(hits).toHaveLength(2);
  });

  it("should be case-insensitive", () => {
    const lines = [
      "7f000000-7f001000 r-xp /data/local/tmp/FRIDA-AGENT.so",
    ];
    const hits = findMapMarkers(lines, defaultMarkers);
    expect(hits).toHaveLength(1);
  });
});

describe("Frida suspicious thread detection", () => {
  const suspiciousNames = ["gmain", "gdbus", "gum-js-loop"];

  /** Replicated thread name matching. */
  function matchSuspiciousThread(
    threadName: string,
    patterns: string[]
  ): boolean {
    return patterns.some((p) => threadName === p);
  }

  it("should flag gmain thread", () => {
    expect(matchSuspiciousThread("gmain", suspiciousNames)).toBe(true);
  });

  it("should flag gdbus thread", () => {
    expect(matchSuspiciousThread("gdbus", suspiciousNames)).toBe(true);
  });

  it("should flag gum-js-loop thread", () => {
    expect(matchSuspiciousThread("gum-js-loop", suspiciousNames)).toBe(true);
  });

  it("should not flag normal threads", () => {
    expect(matchSuspiciousThread("main", suspiciousNames)).toBe(false);
    expect(matchSuspiciousThread("Binder:1234_1", suspiciousNames)).toBe(false);
    expect(matchSuspiciousThread("RenderThread", suspiciousNames)).toBe(false);
  });
});
