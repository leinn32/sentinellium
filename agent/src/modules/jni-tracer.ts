/**
 * JNITransitionTracer — Traces Java↔Native boundary calls through ART's JNI layer.
 *
 * What:  Hooks ART internal JNI call functions (`art::JNI::Call*MethodV` variants)
 *        by resolving mangled C++ symbols from libart.so.
 *
 * Why:   RASP SDKs implement their critical integrity checks (signature verification,
 *        root detection, environment validation) in native code called via JNI.
 *        By tracing this boundary, we map which native functions the RASP relies on,
 *        revealing the exact attack surface an adversary would target for bypass.
 *        Hooking at the ART level rather than individual JNI functions means we
 *        catch *all* JNI transitions, including those from obfuscated or dynamically
 *        registered native methods.
 *
 * RASP:  Maps the RASP SDK's native call surface. Output directly tells a researcher
 *        "these are the functions to focus reverse engineering efforts on." Also
 *        validates that RASP checks are actually being invoked at runtime.
 */

import { BaseHookModule, type ModuleConfig } from "../core/hook-module";

/**
 * Patterns associated with RASP integrity/security checks.
 * If a JNI method name matches any of these, severity is upgraded to "warning".
 */
const RASP_METHOD_PATTERNS: string[] = [
  "checkroot",
  "isrooted",
  "rootcheck",
  "verifysignature",
  "checksignature",
  "signatureverif",
  "isdebugger",
  "debuggercheck",
  "isdebugg",
  "antifrida",
  "fridacheck",
  "integrity",
  "tamper",
  "emulator",
  "isemulator",
  "hookdetect",
  "checkenv",
  "safetynet",
  "attestation",
  "devicebind",
];

/**
 * ART symbol patterns for JNI Call*Method* functions.
 * The mangled names follow the pattern: _ZN3art3JNI<N><MethodName>...
 * We match broadly to handle variations across Android versions (5.0 – 14+).
 */
const JNI_SYMBOL_PATTERNS: RegExp[] = [
  /^_ZN3art3JNI\d+Call.*Method/,
  /^_ZN3art3JNI\d+Get.*Field/,
  /^_ZN3art3JNI\d+Set.*Field/,
  /^_ZN3art3JNI\d+NewObject/,
];

interface ResolvedSymbol {
  name: string;
  address: NativePointer;
}

export class JNITransitionTracer extends BaseHookModule {
  readonly id = "jni-tracer";

  /** Interceptor listener handles for clean detach. */
  private listeners: InvocationListener[] = [];

  /** Resolved ART symbols for telemetry. */
  private resolvedSymbols: ResolvedSymbol[] = [];

  /** Throttle: track recently logged methods to avoid flooding. */
  private recentMethods: Map<string, number> = new Map();

  /** Minimum interval between duplicate method logs (ms). */
  private readonly THROTTLE_MS = 100;

  constructor(config: ModuleConfig = {}) {
    super(config);
  }

  protected onEnable(): void {
    this.resolvedSymbols = this.resolveArtSymbols();

    if (this.resolvedSymbols.length === 0) {
      this.emit("warning", {
        event: "no_symbols_resolved",
        detail:
          "JNI tracing unavailable — could not resolve any art::JNI::Call*Method symbols. " +
          "This may indicate an unsupported ART version or stripped libart.so.",
      });
      return;
    }

    this.emit("info", {
      event: "symbols_resolved",
      count: this.resolvedSymbols.length,
      symbols: this.resolvedSymbols.map((s) => s.name),
    });

    this.attachHooks();
  }

  protected onDisable(): void {
    for (const listener of this.listeners) {
      listener.detach();
    }
    this.listeners = [];
    this.recentMethods.clear();
  }

  /**
   * Resolve JNI-related symbols from libart.so.
   *
   * ART's symbol mangling changes across Android versions. We enumerate all
   * exported and internal symbols, then match against known patterns. This
   * approach is more resilient than hardcoding specific mangled names.
   */
  private resolveArtSymbols(): ResolvedSymbol[] {
    const resolved: ResolvedSymbol[] = [];
    const seen = new Set<string>();

    try {
      const symbols = Module.enumerateSymbols("libart.so");

      for (const sym of symbols) {
        if (sym.type !== "function" || seen.has(sym.name)) {
          continue;
        }

        for (const pattern of JNI_SYMBOL_PATTERNS) {
          if (pattern.test(sym.name)) {
            resolved.push({
              name: sym.name,
              address: sym.address,
            });
            seen.add(sym.name);
            break;
          }
        }
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("warning", {
        event: "symbol_enumeration_failed",
        source: "enumerateSymbols",
        error: msg,
      });
    }

    // Fallback: try enumerateExports if enumerateSymbols returned nothing
    if (resolved.length === 0) {
      try {
        const exports = Module.enumerateExports("libart.so");
        for (const exp of exports) {
          if (exp.type !== "function" || seen.has(exp.name)) {
            continue;
          }
          for (const pattern of JNI_SYMBOL_PATTERNS) {
            if (pattern.test(exp.name)) {
              resolved.push({
                name: exp.name,
                address: exp.address,
              });
              seen.add(exp.name);
              break;
            }
          }
        }
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        this.emit("warning", {
          event: "symbol_enumeration_failed",
          source: "enumerateExports",
          error: msg,
        });
      }
    }

    return resolved;
  }

  /**
   * Attach interceptors to resolved JNI symbols.
   *
   * We only hook the most common Call*Method variants to keep overhead
   * manageable. Each hook extracts the JNI method ID and attempts to
   * resolve it to a human-readable name via the JNI environment.
   */
  private attachHooks(): void {
    const self = this;

    for (const sym of this.resolvedSymbols) {
      try {
        const listener = Interceptor.attach(sym.address, {
          onEnter(args) {
            try {
              self.traceJniCall(sym.name, this.context);
            } catch {
              // Silently skip — never crash the target for tracing
            }
          },
        });
        this.listeners.push(listener);
      } catch {
        // Some symbols may not be hookable — skip and continue
        this.emit("info", {
          event: "hook_skipped",
          symbol: sym.name,
          detail: "Symbol exists but could not be hooked",
        });
      }
    }
  }

  /**
   * Process a JNI call event.
   *
   * Attempts to resolve the Java method name via the JNI environment.
   * If resolution fails (which can happen if we're called at an
   * inconvenient time in ART's lifecycle), we fall back to logging
   * just the ART symbol name with a native backtrace.
   */
  private traceJniCall(artSymbol: string, context: CpuContext): void {
    const now = Date.now();

    // Attempt to resolve the Java method name
    let methodName = "unknown";
    let className = "unknown";

    try {
      Java.performNow(() => {
        // We can't directly extract the method ID from the args in a
        // version-independent way, so we log the call with what we know
        // from the ART symbol name and backtrace.
        const backtrace = Thread.backtrace(context, Backtracer.FUZZY)
          .map(DebugSymbol.fromAddress)
          .map((s) => s.toString());

        // Try to infer method info from the backtrace
        for (const frame of backtrace) {
          const jniMatch = frame.match(
            /(\w+(?:\.\w+)+)\.(\w+)/
          );
          if (jniMatch) {
            className = jniMatch[1] ?? className;
            methodName = jniMatch[2] ?? methodName;
            break;
          }
        }
      });
    } catch {
      // Java.performNow may fail if we're not on a JNI thread — acceptable
    }

    // Throttle: skip if we logged this exact method recently
    const key = `${className}.${methodName}`;
    const lastLog = this.recentMethods.get(key);
    if (lastLog !== undefined && now - lastLog < this.THROTTLE_MS) {
      return;
    }
    this.recentMethods.set(key, now);

    // Periodically clean the throttle map to prevent memory growth
    if (this.recentMethods.size > 1000) {
      const cutoff = now - this.THROTTLE_MS * 10;
      for (const [k, v] of this.recentMethods.entries()) {
        if (v < cutoff) {
          this.recentMethods.delete(k);
        }
      }
    }

    // Check if this looks like a RASP-related method
    const isRaspRelated = this.isRaspMethod(methodName, className);

    const callerModule = this.getCallerModule(context);

    if (isRaspRelated) {
      this.emit(
        "warning",
        {
          event: "rasp_jni_call",
          art_symbol: artSymbol,
          class: className,
          method: methodName,
          caller_module: callerModule,
        },
        Thread.backtrace(context, Backtracer.ACCURATE)
          .map(DebugSymbol.fromAddress)
          .join("\n")
      );
    } else {
      this.emit("info", {
        event: "jni_call",
        art_symbol: artSymbol,
        class: className,
        method: methodName,
        caller_module: callerModule,
      });
    }
  }

  /**
   * Check if a method name/class matches known RASP-related patterns.
   */
  private isRaspMethod(method: string, className: string): boolean {
    const combined = `${className}.${method}`.toLowerCase();
    return RASP_METHOD_PATTERNS.some((pattern) => combined.includes(pattern));
  }

  /**
   * Determine which native module initiated the JNI call
   * by inspecting the return address from the backtrace.
   */
  private getCallerModule(context: CpuContext): string {
    try {
      const backtrace = Thread.backtrace(context, Backtracer.FUZZY);
      if (backtrace.length > 1) {
        const callerAddr = backtrace[1];
        if (callerAddr !== undefined) {
          const mod = Process.findModuleByAddress(callerAddr);
          if (mod !== null) {
            return mod.name;
          }
        }
      }
    } catch {
      // Backtrace may fail — return unknown
    }
    return "unknown";
  }
}
