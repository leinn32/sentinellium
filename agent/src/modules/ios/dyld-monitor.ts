/**
 * DyldMonitor — Dynamic linker monitoring for iOS.
 *
 * What:  Hooks `dlopen` and registers a `_dyld_register_func_for_add_image`
 *        callback to monitor all dynamic library loading on iOS.
 *
 * Why:   On iOS, dlopen is the primary mechanism for loading dynamic libraries
 *        (dylibs/frameworks), but not the only one. Lazy binding and framework
 *        loading via dyld bypass dlopen entirely. By hooking both the POSIX API
 *        and the dyld notification callback, we capture all image loads including
 *        those from Substrate, Cycript, and Frida injection.
 *
 * RASP:  Mirrors the Android NativeLoaderMonitor but for iOS. RASP SDKs check
 *        for Substrate/Frida dylibs at load time; this module audits whether
 *        those checks catch all injection vectors, including dyld-level loads
 *        that bypass dlopen.
 */

import { BaseHookModule, type ModuleConfig } from "../../core/hook-module";

/** Known suspicious library paths on jailbroken iOS devices. */
const SUSPICIOUS_PATHS_DEFAULT = [
  "/Library/MobileSubstrate/",
  "/usr/lib/TweakInject/",
  "/usr/lib/substrate/",
  "/Library/Frameworks/CydiaSubstrate.framework/",
];

/** Suspicious library name patterns. */
const SUSPICIOUS_PATTERNS_DEFAULT = [
  "substrate",
  "cycript",
  "frida",
  "tweakinject",
  "substitute",
  "libhooker",
  "ellekit",
];

export class DyldMonitor extends BaseHookModule {
  readonly id = "dyld-monitor";

  private listeners: InvocationListener[] = [];
  private suspiciousPaths: string[];
  private suspiciousPatterns: string[];

  constructor(config: ModuleConfig = {}) {
    super(config);
    this.suspiciousPaths = this.configValue<string[]>(
      "suspicious_paths",
      SUSPICIOUS_PATHS_DEFAULT
    );
    this.suspiciousPatterns = this.configValue<string[]>(
      "suspicious_patterns",
      SUSPICIOUS_PATTERNS_DEFAULT
    );
  }

  protected onEnable(): void {
    this.hookDlopen();
    this.registerDyldCallback();
  }

  protected onDisable(): void {
    for (const listener of this.listeners) {
      listener.detach();
    }
    this.listeners = [];
  }

  /**
   * Hook dlopen to catch explicit dynamic library loading.
   *
   * dlopen(const char *path, int mode) is the POSIX API for loading
   * shared libraries. On iOS, it's used by apps and frameworks to load
   * dylibs at runtime. Substrate and other injection frameworks also
   * use dlopen to load tweaks.
   */
  private hookDlopen(): void {
    const dlopenAddr = Module.findExportByName(null, "dlopen");
    if (dlopenAddr === null) {
      this.emit("warning", {
        event: "symbol_not_found",
        symbol: "dlopen",
      });
      return;
    }

    const self = this;
    const listener = Interceptor.attach(dlopenAddr, {
      onEnter(args) {
        const pathPtr = args[0];
        if (pathPtr === undefined || pathPtr.isNull()) {
          return;
        }
        const path = pathPtr.readUtf8String();
        if (path === null) {
          return;
        }

        (this as InvocationContext & { _libPath: string })._libPath = path;

        self.emit("info", {
          event: "dlopen_call",
          path,
          source: "dlopen",
        });

        const matchedRule = self.matchSuspicious(path);
        if (matchedRule !== null) {
          self.emit(
            "critical",
            {
              event: "suspicious_dylib_load",
              path,
              matched_rule: matchedRule,
              source: "dlopen",
            },
            Thread.backtrace(this.context, Backtracer.ACCURATE)
              .map(DebugSymbol.fromAddress)
              .join("\n")
          );
        }
      },
      onLeave(retval) {
        const path = (this as InvocationContext & { _libPath?: string })
          ._libPath;
        if (path === undefined) {
          return;
        }
        self.emit("info", {
          event: "dlopen_result",
          path,
          success: !retval.isNull(),
          handle: retval.isNull() ? null : retval.toString(),
        });
      },
    });
    this.listeners.push(listener);
  }

  /**
   * Register a dyld notification callback for image additions.
   *
   * _dyld_register_func_for_add_image registers a callback that fires
   * whenever a new Mach-O image is mapped into the process — including
   * images loaded by dyld itself (lazy binding, framework deps) that
   * don't go through dlopen. This catches loads that the dlopen hook misses.
   *
   * Callback signature: void callback(const struct mach_header *mh, intptr_t vmaddr_slide)
   */
  private registerDyldCallback(): void {
    const registerFn = Module.findExportByName(
      null,
      "_dyld_register_func_for_add_image"
    );
    if (registerFn === null) {
      this.emit("warning", {
        event: "symbol_not_found",
        symbol: "_dyld_register_func_for_add_image",
      });
      return;
    }

    const self = this;

    // Create a native callback that dyld will invoke for each new image
    const callback = new NativeCallback(
      (mhPtr: NativePointer, slide: NativePointer) => {
        try {
          // Resolve the image path from the mach_header address
          const mod = Process.findModuleByAddress(mhPtr);
          if (mod === null) {
            return;
          }

          self.emit("info", {
            event: "dyld_image_added",
            name: mod.name,
            path: mod.path,
            base: mod.base.toString(),
            size: mod.size,
            source: "dyld_callback",
          });

          const matchedRule = self.matchSuspicious(mod.path);
          if (matchedRule !== null) {
            self.emit("critical", {
              event: "suspicious_dylib_load",
              path: mod.path,
              name: mod.name,
              matched_rule: matchedRule,
              source: "dyld_callback",
            });
          }
        } catch {
          // Silently skip — never crash in a dyld callback
        }
      },
      "void",
      ["pointer", "pointer"]
    );

    // Call the registration function
    const register = new NativeFunction(
      registerFn,
      "void",
      ["pointer"]
    );
    register(callback);

    // Keep a reference to prevent garbage collection
    (this as unknown as Record<string, NativeCallback>)._dyldCallback = callback;
  }

  /** Check a library path against suspicious paths and patterns. */
  private matchSuspicious(path: string): string | null {
    const lowerPath = path.toLowerCase();

    for (const suspiciousPath of this.suspiciousPaths) {
      if (lowerPath.includes(suspiciousPath.toLowerCase())) {
        return `path:${suspiciousPath}`;
      }
    }

    for (const pattern of this.suspiciousPatterns) {
      if (lowerPath.includes(pattern.toLowerCase())) {
        return `pattern:${pattern}`;
      }
    }

    return null;
  }
}
