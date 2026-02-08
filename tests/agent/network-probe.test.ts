/**
 * Tests for NetworkProbe — IP conversion, private IP detection,
 * port classification, and DNS resolution heuristic.
 *
 * Frida APIs are unavailable in vitest, so we replicate the pure logic
 * portions of the module for unit testing.
 */

import { describe, it, expect } from "vitest";

/** Replicated from NetworkProbe.intToIp. */
function intToIp(addr: number): string {
  return [
    addr & 0xff,
    (addr >> 8) & 0xff,
    (addr >> 16) & 0xff,
    (addr >> 24) & 0xff,
  ].join(".");
}

/** Replicated from NetworkProbe.parseCidr. */
function parseCidr(
  cidr: string
): { network: number; mask: number } | null {
  const parts = cidr.split("/");
  if (parts.length !== 2) return null;
  const [ipStr, bitsStr] = parts;
  if (ipStr === undefined || bitsStr === undefined) return null;

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

/** Replicated from NetworkProbe.isPrivateIp. */
function isPrivateIp(
  addrNetworkOrder: number,
  privateRanges: { network: number; mask: number }[]
): boolean {
  const hostOrder =
    ((addrNetworkOrder & 0xff) << 24) |
    (((addrNetworkOrder >> 8) & 0xff) << 16) |
    (((addrNetworkOrder >> 16) & 0xff) << 8) |
    ((addrNetworkOrder >> 24) & 0xff);

  return privateRanges.some(
    (range) => (hostOrder & range.mask) === range.network
  );
}

/** Convert dotted IP to network byte order uint32. */
function ipToNetworkOrder(ip: string): number {
  const parts = ip.split(".").map(Number);
  return (
    (parts[0]! & 0xff) |
    ((parts[1]! & 0xff) << 8) |
    ((parts[2]! & 0xff) << 16) |
    ((parts[3]! & 0xff) << 24)
  );
}

/** Common ports that are expected for normal traffic. */
const EXPECTED_PORTS = new Set([80, 443, 8080, 8443, 53]);

describe("NetworkProbe IP conversion (network byte order)", () => {
  it("should convert 127.0.0.1", () => {
    // 127.0.0.1 in network byte order: 0x0100007f
    const addr = 0x0100007f;
    expect(intToIp(addr)).toBe("127.0.0.1");
  });

  it("should convert 192.168.1.100", () => {
    // Network byte order: 100.1.168.192 = 0xc0a80164
    const addr = ipToNetworkOrder("192.168.1.100");
    expect(intToIp(addr)).toBe("192.168.1.100");
  });

  it("should convert 10.0.0.1", () => {
    const addr = ipToNetworkOrder("10.0.0.1");
    expect(intToIp(addr)).toBe("10.0.0.1");
  });

  it("should convert 0.0.0.0", () => {
    expect(intToIp(0)).toBe("0.0.0.0");
  });

  it("should convert 255.255.255.255", () => {
    const addr = 0xffffffff;
    expect(intToIp(addr)).toBe("255.255.255.255");
  });

  it("should convert 8.8.8.8 (Google DNS)", () => {
    const addr = ipToNetworkOrder("8.8.8.8");
    expect(intToIp(addr)).toBe("8.8.8.8");
  });
});

describe("NetworkProbe private IP detection", () => {
  const defaultRanges = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
  ]
    .map(parseCidr)
    .filter((r): r is { network: number; mask: number } => r !== null);

  it("should detect 10.x.x.x as private", () => {
    const addr = ipToNetworkOrder("10.0.0.1");
    expect(isPrivateIp(addr, defaultRanges)).toBe(true);
  });

  it("should detect 10.255.255.255 as private", () => {
    const addr = ipToNetworkOrder("10.255.255.255");
    expect(isPrivateIp(addr, defaultRanges)).toBe(true);
  });

  it("should detect 192.168.1.1 as private", () => {
    const addr = ipToNetworkOrder("192.168.1.1");
    expect(isPrivateIp(addr, defaultRanges)).toBe(true);
  });

  it("should detect 172.16.0.1 as private", () => {
    const addr = ipToNetworkOrder("172.16.0.1");
    expect(isPrivateIp(addr, defaultRanges)).toBe(true);
  });

  it("should detect 172.31.255.255 as private", () => {
    const addr = ipToNetworkOrder("172.31.255.255");
    expect(isPrivateIp(addr, defaultRanges)).toBe(true);
  });

  it("should detect 127.0.0.1 as private (loopback)", () => {
    const addr = ipToNetworkOrder("127.0.0.1");
    expect(isPrivateIp(addr, defaultRanges)).toBe(true);
  });

  it("should NOT detect 8.8.8.8 as private", () => {
    const addr = ipToNetworkOrder("8.8.8.8");
    expect(isPrivateIp(addr, defaultRanges)).toBe(false);
  });

  it("should NOT detect 172.32.0.1 as private (outside /12 range)", () => {
    const addr = ipToNetworkOrder("172.32.0.1");
    expect(isPrivateIp(addr, defaultRanges)).toBe(false);
  });

  it("should NOT detect 11.0.0.1 as private", () => {
    const addr = ipToNetworkOrder("11.0.0.1");
    expect(isPrivateIp(addr, defaultRanges)).toBe(false);
  });

  it("should NOT detect 1.1.1.1 as private", () => {
    const addr = ipToNetworkOrder("1.1.1.1");
    expect(isPrivateIp(addr, defaultRanges)).toBe(false);
  });
});

describe("NetworkProbe port classification", () => {
  it("should recognize port 80 as expected", () => {
    expect(EXPECTED_PORTS.has(80)).toBe(true);
  });

  it("should recognize port 443 as expected", () => {
    expect(EXPECTED_PORTS.has(443)).toBe(true);
  });

  it("should recognize port 53 as expected (DNS)", () => {
    expect(EXPECTED_PORTS.has(53)).toBe(true);
  });

  it("should recognize port 8080 as expected", () => {
    expect(EXPECTED_PORTS.has(8080)).toBe(true);
  });

  it("should flag port 4444 as unexpected (common reverse shell)", () => {
    expect(EXPECTED_PORTS.has(4444)).toBe(false);
  });

  it("should flag port 27042 as unexpected (Frida default)", () => {
    expect(EXPECTED_PORTS.has(27042)).toBe(false);
  });

  it("should flag port 1337 as unexpected", () => {
    expect(EXPECTED_PORTS.has(1337)).toBe(false);
  });
});

describe("NetworkProbe network byte order port conversion", () => {
  /** Replicated port conversion from connect() hook. */
  function convertPort(portRaw: number): number {
    return ((portRaw & 0xff) << 8) | ((portRaw >> 8) & 0xff);
  }

  it("should convert port 80 (0x0050 → 0x5000)", () => {
    expect(convertPort(0x5000)).toBe(80);
  });

  it("should convert port 443 (0x01BB → 0xBB01)", () => {
    expect(convertPort(0xbb01)).toBe(443);
  });

  it("should convert port 8080", () => {
    // 8080 = 0x1F90, network order = 0x901F
    expect(convertPort(0x901f)).toBe(8080);
  });

  it("should convert port 27042 (Frida default)", () => {
    // 27042 = 0x69A2, network order = 0xA269
    expect(convertPort(0xa269)).toBe(27042);
  });
});
