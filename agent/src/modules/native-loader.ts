/**
 * NativeLoaderMonitor — Monitors native library loading via android_dlopen_ext.
 *
 * What:  Hooks `android_dlopen_ext` in the dynamic linker (linker64/linker/libdl.so).
 *
 * Why:   `android_dlopen_ext` is the real entry point for all native library loading
 *        on Android 7+. Unlike `dlopen`, which is a thin POSIX wrapper that may not
 *        exist on all Android versions, `android_dlopen_ext` is always called by the
 *        runtime when loading .so files — including through System.loadLibrary().
 *        Attackers who inject Frida gadgets, Xposed modules, or custom native payloads
 *        go through this function *before* Java-layer monitoring sees anything.
 *
 * RASP:  Audits whether a RASP SDK's tamper detection catches native-level library
 *        injection. If Sentinellium detects a suspicious load that the RASP missed,
 *        that's a gap in the SDK's defense coverage worth reporting.
 */

import { BaseHookModule, type ModuleConfig } from "../core/hook-module";

export class NativeLoaderMonitor extends BaseHookModule {
  readonly id = "native-loader";

  /** Interceptor listener handles for clean detach. */
  private listeners: InvocationListener[] = [];

  /** Paths considered suspicious — configurable via YAML. */
  private suspiciousPaths: string[] = [];

  /** Substring patterns in library names that indicate injection — configurable. */
  private suspiciousPatterns: string[] = [];

  constructor(config: ModuleConfig = {}) {
    super(config);
    this.suspiciousPaths = this.configValue<string[]>("suspicious_paths", [
      "/data/local/tmp",
      "/data/data/*/lib-custom/",
    ]);
    this.suspiciousPatterns = this.configValue<string[]>(
      "suspicious_patterns",
      ["frida", "xposed", "substrate", "magisk"]
    );
  }

  protected onEnable(): void {
    const target = this.resolveSymbol();
    if (target === null) {
      throw new Error(
        "Could not resolve android_dlopen_ext in linker64, linker, or libdl.so"
      );
    }

    const self = this;
    const listener = Interceptor.attach(target, {
      /**
       * onEnter: Read the library path from the first argument.
       * The signature is: void* android_dlopen_ext(const char* filename, int flag,
       *                                            const android_dlextinfo* extinfo,
       *                                            const void* caller_addr)
       */
      onEnter(args) {
        const pathPtr = args[0];
        if (pathPtr === undefined || pathPtr.isNull()) {
          return;
        }
        const path = pathPtr.readUtf8String();
        if (path === null) {
          return;
        }

        // Store path for onLeave correlation
        (this as InvocationContext & { _libPath: string })._libPath = path;

        // Always log the load at info level
        self.emit("info", {
          event: "library_load_attempt",
          path,
        });

        // Check against suspicious paths and patterns
        const matchedRule = self.matchSuspicious(path);
        if (matchedRule !== null) {
          self.emit(
            "critical",
            {
              event: "suspicious_library_load",
              path,
              matched_rule: matchedRule,
            },
            Thread.backtrace(this.context, Backtracer.ACCURATE)
              .map(DebugSymbol.fromAddress)
              .join("\n")
          );
        }
      },

      /**
       * onLeave: Log whether the load succeeded (non-null handle).
       * A failed load of a suspicious library is still worth noting — it means
       * something attempted injection but the linker rejected it.
       */
      onLeave(retval) {
        const path = (this as InvocationContext & { _libPath?: string })
          ._libPath;
        if (path === undefined) {
          return;
        }
        const success = !retval.isNull();
        self.emit("info", {
          event: "library_load_result",
          path,
          success,
          handle: success ? retval.toString() : null,
        });
      },
    });

    this.listeners.push(listener);
  }

  protected onDisable(): void {
    for (const listener of this.listeners) {
      listener.detach();
    }
    this.listeners = [];
  }

  /**
   * Resolve the address of android_dlopen_ext.
   *
   * We try multiple modules because the symbol lives in different places
   * across Android versions:
   *   - Android 7-9: linker64 (64-bit) or linker (32-bit)
   *   - Android 10+: also exported from libdl.so for compat
   *   - Some ROMs: available via linker_namespace symbols
   */
  private resolveSymbol(): NativePointer | null {
    const candidates = ["linker64", "linker", "libdl.so"];
    for (const mod of candidates) {
      const addr = Module.findExportByName(mod, "android_dlopen_ext");
      if (addr !== null) {
        this.emit("info", {
          event: "symbol_resolved",
          module: mod,
          symbol: "android_dlopen_ext",
          address: addr.toString(),
        });
        return addr;
      }
    }
    // Fallback: try without specifying a module (global search)
    const addr = Module.findExportByName(null, "android_dlopen_ext");
    if (addr !== null) {
      this.emit("info", {
        event: "symbol_resolved",
        module: "global",
        symbol: "android_dlopen_ext",
        address: addr.toString(),
      });
      return addr;
    }
    return null;
  }

  /**
   * Check a library path against suspicious paths and patterns.
   * Returns the matched rule string, or null if clean.
   *
   * Path matching supports simple wildcard (*) for directory patterns.
   * Pattern matching is case-insensitive substring search.
   */
  private matchSuspicious(path: string): string | null {
    const lowerPath = path.toLowerCase();

    // Check exact/prefix path matches
    for (const suspiciousPath of this.suspiciousPaths) {
      if (suspiciousPath.includes("*")) {
        // Convert simple glob to regex: "/data/data/*/lib-custom/"
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

    // Check substring patterns in filename/path
    for (const pattern of this.suspiciousPatterns) {
      if (lowerPath.includes(pattern.toLowerCase())) {
        return `pattern:${pattern}`;
      }
    }

    return null;
  }
}
