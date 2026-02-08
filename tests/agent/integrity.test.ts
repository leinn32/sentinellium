/**
 * Tests for IntegrityBaseline — chunked hashing logic, baseline entry
 * structure, and configValue helper.
 *
 * Frida APIs are unavailable in vitest, so we replicate the pure logic
 * portions of the module for unit testing.
 */

import { describe, it, expect } from "vitest";

const CHUNK_SIZE = 65536; // 64KB — matches the module constant

describe("IntegrityBaseline chunk calculation", () => {
  /**
   * Replicated logic: given a total size, compute the chunk boundaries
   * that the module would use for hashing.
   */
  function computeChunks(
    totalSize: number,
    chunkSize: number
  ): { offset: number; length: number }[] {
    const chunks: { offset: number; length: number }[] = [];
    let offset = 0;
    while (offset < totalSize) {
      const length = Math.min(chunkSize, totalSize - offset);
      chunks.push({ offset, length });
      offset += length;
    }
    return chunks;
  }

  it("should produce a single chunk for size <= CHUNK_SIZE", () => {
    const chunks = computeChunks(1024, CHUNK_SIZE);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toEqual({ offset: 0, length: 1024 });
  });

  it("should produce a single chunk for exactly CHUNK_SIZE", () => {
    const chunks = computeChunks(CHUNK_SIZE, CHUNK_SIZE);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toEqual({ offset: 0, length: CHUNK_SIZE });
  });

  it("should produce two chunks for CHUNK_SIZE + 1", () => {
    const chunks = computeChunks(CHUNK_SIZE + 1, CHUNK_SIZE);
    expect(chunks).toHaveLength(2);
    expect(chunks[0]).toEqual({ offset: 0, length: CHUNK_SIZE });
    expect(chunks[1]).toEqual({ offset: CHUNK_SIZE, length: 1 });
  });

  it("should produce correct chunks for a typical .text section (256KB)", () => {
    const size = 256 * 1024;
    const chunks = computeChunks(size, CHUNK_SIZE);
    expect(chunks).toHaveLength(4);
    // All chunks should be full-size
    for (const chunk of chunks) {
      expect(chunk.length).toBe(CHUNK_SIZE);
    }
    // Verify coverage: sum of lengths should equal total
    const totalCovered = chunks.reduce((sum, c) => sum + c.length, 0);
    expect(totalCovered).toBe(size);
  });

  it("should handle non-aligned sizes correctly", () => {
    const size = CHUNK_SIZE * 3 + 12345;
    const chunks = computeChunks(size, CHUNK_SIZE);
    expect(chunks).toHaveLength(4);
    expect(chunks[3]!.length).toBe(12345);
  });

  it("should handle zero size with no chunks", () => {
    const chunks = computeChunks(0, CHUNK_SIZE);
    expect(chunks).toHaveLength(0);
  });
});

describe("IntegrityBaseline entry structure", () => {
  interface BaselineEntry {
    moduleName: string;
    baseAddress: string;
    size: number;
    hash: string;
  }

  it("should have the expected shape", () => {
    const entry: BaselineEntry = {
      moduleName: "libart.so",
      baseAddress: "0x7f00000000",
      size: 262144,
      hash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    };

    expect(entry.moduleName).toBe("libart.so");
    expect(typeof entry.baseAddress).toBe("string");
    expect(typeof entry.size).toBe("number");
    expect(entry.hash).toHaveLength(64); // SHA-256 hex = 64 chars
  });

  it("should use compound key format module+address", () => {
    const key = `libart.so+0x7f00000000`;
    expect(key).toContain("+");
    expect(key.split("+")).toHaveLength(2);
  });
});

describe("IntegrityBaseline watched library matching", () => {
  /**
   * Replicated logic for matching modules against watched libraries.
   * The module builds a Set of watched lib names (lowercased) and checks
   * if a module's name is in that set.
   */
  function shouldWatch(
    moduleName: string,
    modulePath: string,
    watchedLibs: string[]
  ): boolean {
    const targetLibs = new Set(watchedLibs.map((l) => l.toLowerCase()));

    // Always include app-specific native libraries
    if (modulePath.includes("/data/app/") || modulePath.includes("/data/data/")) {
      return true;
    }

    return targetLibs.has(moduleName.toLowerCase());
  }

  it("should watch explicitly configured library", () => {
    expect(
      shouldWatch("libart.so", "/system/lib64/libart.so", ["libart.so"])
    ).toBe(true);
  });

  it("should watch app-specific library regardless of config", () => {
    expect(
      shouldWatch("libnative.so", "/data/app/com.example/lib/arm64/libnative.so", [])
    ).toBe(true);
  });

  it("should watch library from /data/data/", () => {
    expect(
      shouldWatch("libcustom.so", "/data/data/com.example/lib-custom/libcustom.so", [])
    ).toBe(true);
  });

  it("should not watch unconfigured system library", () => {
    expect(
      shouldWatch("libc.so", "/system/lib64/libc.so", ["libart.so"])
    ).toBe(false);
  });

  it("should be case-insensitive for watched libs", () => {
    expect(
      shouldWatch("libART.so", "/system/lib64/libART.so", ["libart.so"])
    ).toBe(true);
  });
});

describe("configValue helper logic", () => {
  /**
   * Replicated from BaseHookModule.configValue.
   */
  function configValue<T>(
    config: Record<string, unknown>,
    key: string,
    defaultValue: T
  ): T {
    const raw = config[key];
    if (raw === undefined || raw === null) {
      return defaultValue;
    }
    if (typeof raw === typeof defaultValue) {
      return raw as T;
    }
    if (Array.isArray(defaultValue) && Array.isArray(raw)) {
      return raw as T;
    }
    return defaultValue;
  }

  it("should return config value when present and type matches", () => {
    expect(configValue({ interval_seconds: 10 }, "interval_seconds", 5)).toBe(10);
  });

  it("should return default when key is missing", () => {
    expect(configValue({}, "interval_seconds", 5)).toBe(5);
  });

  it("should return default when value is null", () => {
    expect(configValue({ interval_seconds: null }, "interval_seconds", 5)).toBe(5);
  });

  it("should return default when type mismatches", () => {
    expect(configValue({ interval_seconds: "ten" }, "interval_seconds", 5)).toBe(5);
  });

  it("should handle array values", () => {
    const result = configValue(
      { watched_libs: ["libart.so", "libssl.so"] },
      "watched_libs",
      ["libart.so"]
    );
    expect(result).toEqual(["libart.so", "libssl.so"]);
  });

  it("should return default array when key is missing", () => {
    const result = configValue({}, "watched_libs", ["libart.so"]);
    expect(result).toEqual(["libart.so"]);
  });

  it("should handle boolean config values", () => {
    expect(configValue({ enabled: true }, "enabled", false)).toBe(true);
    expect(configValue({ enabled: false }, "enabled", true)).toBe(false);
  });

  it("should handle string config values", () => {
    expect(configValue({ name: "custom" }, "name", "default")).toBe("custom");
  });
});
