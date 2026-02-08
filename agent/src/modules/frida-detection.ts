/**
 * FridaDetectionAuditor — Inverts the RASP perspective to score Frida visibility.
 *
 * What:  Implements the same detection checks that RASP SDKs use to detect Frida,
 *        then reports which ones the current environment *fails* — i.e., where
 *        Frida is detectable.
 *
 * Why:   Instead of just hooking things, this module demonstrates understanding of
 *        the detection surface from the defender's perspective. Each check maps to
 *        a real RASP detection technique used by products like Wultra's SDK.
 *
 * RASP:  Directly maps to anti-debugging and anti-tampering features. The module
 *        essentially produces a "stealth score" showing how visible Frida is to
 *        a standard RASP implementation. Useful for evaluating whether a RASP SDK's
 *        detection coverage is comprehensive.
 */

import { BaseHookModule, type ModuleConfig } from "../core/hook-module";

/** Frida inline hook trampoline signature for arm64. */
const ARM64_TRAMPOLINE: number[] = [
  0x50, 0x00, 0x00, 0x58, // LDR X16, #8
  0x00, 0x02, 0x1f, 0xd6, // BR X16
];

/** Frida inline hook trampoline signature for arm32. */
const ARM32_TRAMPOLINE: number[] = [
  0x00, 0x00, 0x9f, 0xe5, // LDR PC, [PC, #0]  — common Frida arm32 pattern
];

export class FridaDetectionAuditor extends BaseHookModule {
  readonly id = "frida-detection";

  /** Default Frida server port — configurable for non-standard setups. */
  private fridaPort: number;

  constructor(config: ModuleConfig = {}) {
    super(config);
    this.fridaPort = this.configValue<number>("frida_port", 27042);
  }

  protected onEnable(): void {
    // Run all checks sequentially to avoid overwhelming the target.
    // Each check is independent and emits its own telemetry.
    this.checkMemoryMaps();
    this.checkFridaPort();
    this.checkTrampolines();
    this.checkNamedThreads();
  }

  protected onDisable(): void {
    // This module is scan-based, not hook-based — nothing to detach.
  }

  /**
   * Check 1: Memory Maps Scan
   *
   * Reads /proc/self/maps and searches for Frida-related strings.
   * RASP SDKs typically perform this check periodically or on startup.
   *
   * Detectable artifacts:
   *   - "frida-agent": The injected agent shared library
   *   - "frida-gadget": The embedded gadget for non-rooted instrumentation
   *   - "gmain": GLib main loop thread, loaded by Frida's runtime
   */
  private checkMemoryMaps(): void {
    try {
      const markers = ["frida-agent", "frida-gadget", "gmain"];
      const maps = this.readProcMaps();

      let detectionCount = 0;
      for (const line of maps) {
        for (const marker of markers) {
          if (line.toLowerCase().includes(marker)) {
            detectionCount++;
            this.emit("warning", {
              check: "memory_maps",
              finding: "frida_artifact_in_maps",
              marker,
              map_entry: line.trim(),
            });
          }
        }
      }

      if (detectionCount === 0) {
        this.emit("info", {
          check: "memory_maps",
          finding: "clean",
          detail: "No Frida artifacts found in /proc/self/maps",
        });
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("warning", {
        check: "memory_maps",
        finding: "check_failed",
        error: msg,
      });
    }
  }

  /**
   * Check 2: Frida Port Scan
   *
   * Attempts a native connect() to the default Frida server port.
   * A successful connection means frida-server is actively listening,
   * which is a critical finding — any RASP that doesn't check this is
   * missing a trivial detection vector.
   */
  private checkFridaPort(): void {
    try {
      const socket = new Socket(Socket.type("tcp"));
      let connected = false;

      // Use Frida's Socket API for a non-blocking connect attempt
      try {
        socket.connect({
          family: "ipv4",
          host: "127.0.0.1",
          port: this.fridaPort,
        });
        // If we get here without throwing, connection succeeded
        connected = true;
        socket.close();
      } catch {
        // Connection refused = Frida server not listening = good
        connected = false;
      }

      if (connected) {
        this.emit("critical", {
          check: "port_scan",
          finding: "frida_server_listening",
          port: this.fridaPort,
          detail: `Frida server detected on 127.0.0.1:${this.fridaPort}`,
        });
      } else {
        this.emit("info", {
          check: "port_scan",
          finding: "clean",
          port: this.fridaPort,
          detail: "Default Frida port not listening",
        });
      }
    } catch (error: unknown) {
      // Fallback: Use native connect() via NativeFunction if Socket API unavailable
      this.checkFridaPortNative();
    }
  }

  /**
   * Fallback port check using raw native socket APIs.
   * More reliable on some Android versions where Frida's Socket class
   * may not be available.
   */
  private checkFridaPortNative(): void {
    try {
      const AF_INET = 2;
      const SOCK_STREAM = 1;
      const IPPROTO_TCP = 6;

      const socketFn = new NativeFunction(
        Module.findExportByName("libc.so", "socket")!,
        "int",
        ["int", "int", "int"]
      );
      const connectFn = new NativeFunction(
        Module.findExportByName("libc.so", "connect")!,
        "int",
        ["int", "pointer", "int"]
      );
      const closeFn = new NativeFunction(
        Module.findExportByName("libc.so", "close")!,
        "int",
        ["int"]
      );

      const fd = socketFn(AF_INET, SOCK_STREAM, IPPROTO_TCP) as number;
      if (fd < 0) {
        this.emit("warning", {
          check: "port_scan",
          finding: "check_failed",
          error: "Failed to create socket",
        });
        return;
      }

      // Build sockaddr_in struct: family=AF_INET, port=27042, addr=127.0.0.1
      const sockaddr = Memory.alloc(16);
      sockaddr.writeU16(AF_INET); // sin_family
      sockaddr
        .add(2)
        .writeU16(((this.fridaPort >> 8) & 0xff) | ((this.fridaPort & 0xff) << 8)); // sin_port (network byte order)
      sockaddr.add(4).writeU32(0x0100007f); // 127.0.0.1 in network byte order

      const result = connectFn(fd, sockaddr, 16) as number;
      closeFn(fd);

      if (result === 0) {
        this.emit("critical", {
          check: "port_scan_native",
          finding: "frida_server_listening",
          port: this.fridaPort,
        });
      } else {
        this.emit("info", {
          check: "port_scan_native",
          finding: "clean",
          port: this.fridaPort,
        });
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("warning", {
        check: "port_scan_native",
        finding: "check_failed",
        error: msg,
      });
    }
  }

  /**
   * Check 3: Trampoline Scan
   *
   * For each loaded module, scans the first 16 bytes of exported functions
   * for known Frida inline hook patterns.
   *
   * On arm64, Frida's Interceptor replaces the function prologue with:
   *   LDR X16, #8    (0x58000050)
   *   BR  X16        (0xd61f0200)
   *   <8-byte target address>
   *
   * On arm32, the pattern is:
   *   LDR PC, [PC, #0]  (0xe59f0000)
   *   <4-byte target address>
   *
   * RASP SDKs scan their own exports for these patterns to detect hooks.
   */
  private checkTrampolines(): void {
    try {
      const arch = Process.arch;
      const pattern = arch === "arm64" ? ARM64_TRAMPOLINE : ARM32_TRAMPOLINE;
      const patternLen = pattern.length;

      let totalExports = 0;
      let trampolinesFound = 0;

      const modules = Process.enumerateModules();
      for (const mod of modules) {
        // Skip system libraries to reduce noise — focus on app and RASP libs
        if (mod.path.startsWith("/system/") && !mod.name.includes("libart")) {
          continue;
        }

        try {
          const exports = mod.enumerateExports();
          for (const exp of exports) {
            if (exp.type !== "function") {
              continue;
            }
            totalExports++;

            try {
              const bytes = exp.address.readByteArray(patternLen);
              if (bytes === null) {
                continue;
              }

              if (this.matchesPattern(bytes, pattern)) {
                trampolinesFound++;
                this.emit("warning", {
                  check: "trampoline_scan",
                  finding: "hook_detected",
                  library: mod.name,
                  function: exp.name,
                  address: exp.address.toString(),
                  arch,
                });
              }
            } catch {
              // Can't read memory at this address — skip
              continue;
            }
          }
        } catch {
          // Can't enumerate exports for this module — skip
          continue;
        }
      }

      this.emit("info", {
        check: "trampoline_scan",
        finding: "scan_complete",
        total_exports_scanned: totalExports,
        trampolines_found: trampolinesFound,
        arch,
      });
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("warning", {
        check: "trampoline_scan",
        finding: "check_failed",
        error: msg,
      });
    }
  }

  /**
   * Check 4: Named Thread Scan
   *
   * Enumerates threads via /proc/self/task/[tid]/comm and flags
   * Frida-related thread names. Frida spawns several threads with
   * distinctive names from GLib:
   *   - "gmain":      GLib main event loop
   *   - "gdbus":      GLib D-Bus thread
   *   - "gum-js-loop": Frida's JavaScript runtime loop
   *
   * RASP SDKs that enumerate thread names can trivially detect Frida
   * unless the attacker patches these thread names.
   */
  private checkNamedThreads(): void {
    try {
      const suspiciousNames = ["gmain", "gdbus", "gum-js-loop"];
      let detectionCount = 0;

      const threads = Process.enumerateThreads();
      for (const thread of threads) {
        try {
          // Read thread name from /proc/self/task/<tid>/comm
          const commPath = `/proc/self/task/${thread.id}/comm`;
          const file = new File(commPath, "r");
          const name = file.readAllText().trim();
          file.close();

          for (const suspicious of suspiciousNames) {
            if (name === suspicious) {
              detectionCount++;
              this.emit("warning", {
                check: "thread_scan",
                finding: "suspicious_thread",
                thread_id: thread.id,
                thread_name: name,
              });
            }
          }
        } catch {
          // Can't read comm for this thread — skip
          continue;
        }
      }

      if (detectionCount === 0) {
        this.emit("info", {
          check: "thread_scan",
          finding: "clean",
          detail: "No Frida-related thread names found",
          threads_scanned: threads.length,
        });
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("warning", {
        check: "thread_scan",
        finding: "check_failed",
        error: msg,
      });
    }
  }

  /** Read /proc/self/maps into an array of lines. */
  private readProcMaps(): string[] {
    const file = new File("/proc/self/maps", "r");
    const content = file.readAllText();
    file.close();
    return content.split("\n").filter((line) => line.length > 0);
  }

  /** Compare a byte array against a known pattern. */
  private matchesPattern(bytes: ArrayBuffer, pattern: number[]): boolean {
    const view = new Uint8Array(bytes);
    for (let i = 0; i < pattern.length; i++) {
      const expected = pattern[i];
      if (expected === undefined || view[i] !== expected) {
        return false;
      }
    }
    return true;
  }
}
