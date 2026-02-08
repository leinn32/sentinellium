/**
 * NetworkProbe — Monitors native-layer network connections via libc connect().
 *
 * What:  Hooks `connect()` in libc.so via Interceptor.attach to monitor outgoing
 *        TCP connections at the lowest user-space level.
 *
 * Why:   Android's Java-layer network monitoring (e.g., OkHttp interceptors or
 *        NetworkSecurityConfig) can be bypassed by native code that calls
 *        connect() directly. Malware, C2 channels, and some RASP evasion
 *        techniques use raw sockets to avoid Java-layer visibility.
 *        This module extends RASP auditing to the native network layer.
 *
 * RASP:  Extends Wultra's HTTP proxy and VPN detection concepts to the native
 *        layer. Particularly useful for malware research where C2 communication
 *        channels bypass Java-level network stacks entirely.
 *
 * Note:  This module is deliberately minimal and disabled by default. Native
 *        network hooking is extremely noisy on Android (system services, GMS,
 *        DNS, etc. generate hundreds of connections). Production use would
 *        require per-UID or per-module filtering.
 */

import { BaseHookModule, type ModuleConfig } from "../core/hook-module";

/** sockaddr_in layout constants */
const AF_INET = 2;
const SOCKADDR_IN_SIZE = 16;

/** Common ports that are expected for normal traffic. */
const EXPECTED_PORTS = new Set([80, 443, 8080, 8443, 53]);

interface CidrRange {
  network: number;
  mask: number;
}

export class NetworkProbe extends BaseHookModule {
  readonly id = "network-probe";

  /** Interceptor listener handles for clean detach. */
  private listeners: InvocationListener[] = [];

  /** Parsed CIDR ranges for private network detection. */
  private privateRanges: CidrRange[];

  /** Track recent getaddrinfo calls for DNS resolution heuristic. */
  private recentDnsLookups: Map<string, number> = new Map();

  constructor(config: ModuleConfig = {}) {
    super(config);

    const rangeStrings = this.configValue<string[]>("private_ranges", [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "127.0.0.0/8",
    ]);

    this.privateRanges = rangeStrings
      .map((r) => this.parseCidr(r))
      .filter((r): r is CidrRange => r !== null);
  }

  protected onEnable(): void {
    this.hookGetaddrinfo();
    this.hookConnect();
  }

  protected onDisable(): void {
    for (const listener of this.listeners) {
      listener.detach();
    }
    this.listeners = [];
    this.recentDnsLookups.clear();
  }

  /**
   * Hook getaddrinfo to track DNS resolutions.
   *
   * This is used by the hardcoded-IP heuristic: if a connect() call goes to
   * an IP that was recently resolved via DNS, it's normal. If no DNS lookup
   * preceded the connect(), the IP may be hardcoded — a potential C2 indicator.
   */
  private hookGetaddrinfo(): void {
    const resolveAddr = Module.findExportByName("libc.so", "getaddrinfo");
    if (resolveAddr === null) {
      this.emit("info", {
        event: "hook_skipped",
        symbol: "getaddrinfo",
        detail: "Symbol not found in libc.so",
      });
      return;
    }

    const self = this;
    const listener = Interceptor.attach(resolveAddr, {
      onEnter(args) {
        const hostnamePtr = args[0];
        if (hostnamePtr !== undefined && !hostnamePtr.isNull()) {
          const hostname = hostnamePtr.readUtf8String();
          if (hostname !== null) {
            (this as InvocationContext & { _hostname: string })._hostname =
              hostname;
          }
        }
      },
      onLeave(retval) {
        const hostname = (this as InvocationContext & { _hostname?: string })
          ._hostname;
        if (hostname !== undefined && retval.toInt32() === 0) {
          // Mark that this hostname was recently resolved
          self.recentDnsLookups.set(hostname, Date.now());

          // Periodically clean old entries
          if (self.recentDnsLookups.size > 500) {
            const cutoff = Date.now() - 10000;
            for (const [k, v] of self.recentDnsLookups.entries()) {
              if (v < cutoff) {
                self.recentDnsLookups.delete(k);
              }
            }
          }
        }
      },
    });

    this.listeners.push(listener);
  }

  /**
   * Hook connect() to monitor outgoing TCP connections.
   *
   * We parse the sockaddr_in struct from args[1] to extract the destination
   * IP and port. The struct layout (for AF_INET) is:
   *   offset 0: uint16 sin_family
   *   offset 2: uint16 sin_port (network byte order)
   *   offset 4: uint32 sin_addr (network byte order)
   */
  private hookConnect(): void {
    const connectAddr = Module.findExportByName("libc.so", "connect");
    if (connectAddr === null) {
      throw new Error("Could not resolve connect() in libc.so");
    }

    const self = this;
    const listener = Interceptor.attach(connectAddr, {
      onEnter(args) {
        try {
          const sockaddrPtr = args[1];
          if (sockaddrPtr === undefined || sockaddrPtr.isNull()) {
            return;
          }

          // Read address family
          const family = sockaddrPtr.readU16();
          if (family !== AF_INET) {
            return; // Only handle IPv4 for now
          }

          // Parse sockaddr_in
          const portRaw = sockaddrPtr.add(2).readU16();
          // Convert from network byte order (big-endian) to host
          const port = ((portRaw & 0xff) << 8) | ((portRaw >> 8) & 0xff);

          const addrRaw = sockaddrPtr.add(4).readU32();
          const ip = self.intToIp(addrRaw);

          // Check if this is a private/local address
          const isPrivate = self.isPrivateIp(addrRaw);

          if (isPrivate) {
            // Private addresses are expected — log at info only
            self.emit("info", {
              event: "connect_private",
              destination: `${ip}:${port}`,
              private: true,
            });
            return;
          }

          // Non-private connection on unexpected port
          if (!EXPECTED_PORTS.has(port)) {
            // Check DNS resolution heuristic
            const recentlyResolved = self.wasRecentlyResolved(ip);

            if (!recentlyResolved) {
              // Hardcoded IP on unusual port — potential C2
              self.emit(
                "critical",
                {
                  event: "suspicious_connect",
                  destination: `${ip}:${port}`,
                  port,
                  ip,
                  dns_resolved: false,
                  detail:
                    "Connection to non-private IP on unusual port without " +
                    "preceding DNS resolution. Possible hardcoded C2 address.",
                },
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                  .map(DebugSymbol.fromAddress)
                  .join("\n")
              );
            } else {
              // DNS-resolved but unusual port
              self.emit("warning", {
                event: "unusual_port_connect",
                destination: `${ip}:${port}`,
                port,
                ip,
                dns_resolved: true,
              });
            }
          } else {
            // Standard port, non-private — normal traffic
            self.emit("info", {
              event: "connect_external",
              destination: `${ip}:${port}`,
            });
          }
        } catch {
          // Don't crash the app for network monitoring failures
        }
      },
    });

    this.listeners.push(listener);
  }

  /** Convert a 32-bit integer (network byte order) to dotted-decimal IP string. */
  private intToIp(addr: number): string {
    return [
      addr & 0xff,
      (addr >> 8) & 0xff,
      (addr >> 16) & 0xff,
      (addr >> 24) & 0xff,
    ].join(".");
  }

  /** Check if an IP (network byte order uint32) falls within any configured private range. */
  private isPrivateIp(addr: number): boolean {
    // Convert from network byte order to host byte order for CIDR comparison
    const hostOrder =
      ((addr & 0xff) << 24) |
      (((addr >> 8) & 0xff) << 16) |
      (((addr >> 16) & 0xff) << 8) |
      ((addr >> 24) & 0xff);

    return this.privateRanges.some(
      (range) => (hostOrder & range.mask) === range.network
    );
  }

  /** Parse a CIDR notation string into network address and mask. */
  private parseCidr(cidr: string): CidrRange | null {
    const parts = cidr.split("/");
    if (parts.length !== 2) {
      return null;
    }
    const [ipStr, bitsStr] = parts;
    if (ipStr === undefined || bitsStr === undefined) {
      return null;
    }

    const bits = parseInt(bitsStr, 10);
    if (isNaN(bits) || bits < 0 || bits > 32) {
      return null;
    }

    const octets = ipStr.split(".");
    if (octets.length !== 4) {
      return null;
    }

    let ip = 0;
    for (const octet of octets) {
      const val = parseInt(octet, 10);
      if (isNaN(val) || val < 0 || val > 255) {
        return null;
      }
      ip = (ip << 8) | val;
    }

    // Use unsigned right shift to handle the sign bit correctly
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;

    return {
      network: (ip & mask) >>> 0,
      mask: mask >>> 0,
    };
  }

  /**
   * Heuristic: check if any DNS lookup resolved to this IP recently.
   *
   * This is a best-effort check. We compare the IP against the timestamps
   * of recent getaddrinfo calls. A 10-second window is used because DNS
   * resolution and the subsequent connect() typically happen close together.
   *
   * Note: This heuristic has limitations — it doesn't track the actual
   * resolved addresses, only that *some* DNS lookup happened recently.
   * A more accurate implementation would parse the getaddrinfo results.
   */
  private wasRecentlyResolved(_ip: string): boolean {
    const now = Date.now();
    const threshold = 10000; // 10 seconds

    for (const timestamp of this.recentDnsLookups.values()) {
      if (now - timestamp < threshold) {
        return true;
      }
    }
    return false;
  }
}
