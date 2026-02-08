/**
 * HookModule interface and BaseHookModule abstract class.
 *
 * Every detection module in Sentinellium implements HookModule. The base class
 * provides an error boundary around enable()/disable() so that a failing module
 * never crashes the target application — a critical requirement when
 * instrumenting production apps during RASP audits.
 */

import { emitEvent, type Severity } from "./event-bus";

/** Configuration block passed to each module from the parsed YAML config. */
export type ModuleConfig = Record<string, unknown>;

/**
 * Contract that every Sentinellium hook module must satisfy.
 *
 * Modules are loaded by the registry (index.ts) and their lifecycle is:
 *   construct → enable() → … events … → disable()
 */
export interface HookModule {
  /** Unique identifier, e.g. "native-loader". Used as module_id in telemetry. */
  readonly id: string;

  /** Activate hooks. Must be idempotent — calling twice should not double-hook. */
  enable(): void;

  /** Cleanly detach all hooks and release resources. */
  disable(): void;
}

/**
 * Abstract base class that wraps enable()/disable() in error boundaries
 * and provides convenience helpers for emitting telemetry.
 *
 * Subclasses implement onEnable() and onDisable() instead of the raw
 * interface methods.
 */
export abstract class BaseHookModule implements HookModule {
  abstract readonly id: string;

  /** Module-specific configuration loaded from YAML. */
  protected config: ModuleConfig;

  /** Track whether the module is currently active to prevent double-hooking. */
  private _enabled: boolean = false;

  constructor(config: ModuleConfig = {}) {
    this.config = config;
  }

  /**
   * Wraps onEnable() in a try/catch. If the module fails to initialize
   * (e.g., a symbol isn't found on this Android version), we emit a warning
   * and continue rather than crashing the target app.
   */
  enable(): void {
    if (this._enabled) {
      return;
    }
    try {
      this.onEnable();
      this._enabled = true;
      this.emit("info", { status: "enabled" });
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : String(error);
      this.emit("warning", {
        status: "enable_failed",
        error: message,
      });
    }
  }

  /**
   * Wraps onDisable() in a try/catch. Ensures we always mark the module
   * as disabled even if cleanup throws.
   */
  disable(): void {
    if (!this._enabled) {
      return;
    }
    try {
      this.onDisable();
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : String(error);
      this.emit("warning", {
        status: "disable_failed",
        error: message,
      });
    } finally {
      this._enabled = false;
    }
  }

  /** Subclasses implement this to set up their hooks. */
  protected abstract onEnable(): void;

  /** Subclasses implement this to tear down their hooks. */
  protected abstract onDisable(): void;

  /**
   * Convenience wrapper around the global emitEvent that automatically
   * fills in module_id and timestamp.
   */
  protected emit(
    severity: Severity,
    data: Record<string, unknown>,
    stacktrace?: string
  ): void {
    emitEvent(this.id, severity, data, stacktrace);
  }

  /**
   * Read a typed config value with a default fallback.
   * Uses a runtime check rather than trusting the YAML blindly.
   */
  protected configValue<T>(key: string, defaultValue: T): T {
    const raw = this.config[key];
    if (raw === undefined || raw === null) {
      return defaultValue;
    }
    // Basic type guard: only return if the type matches the default
    if (typeof raw === typeof defaultValue) {
      return raw as T;
    }
    // For arrays, check if default is an array and raw is an array
    if (Array.isArray(defaultValue) && Array.isArray(raw)) {
      return raw as T;
    }
    return defaultValue;
  }
}
