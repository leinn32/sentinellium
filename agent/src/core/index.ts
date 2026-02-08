/**
 * Module registry and agent entry point.
 *
 * This file is the compilation target for frida-compile. It:
 *   1. Receives configuration from the host via Frida's rpc.exports
 *   2. Detects the platform (Android/iOS) to load appropriate modules
 *   3. Instantiates all hook modules with their config blocks
 *   4. Enables modules marked as active in the config
 *   5. Exposes disable_all() for clean detach
 *
 * Platform detection uses Process.platform:
 *   - "linux" → Android (Android is Linux-based)
 *   - "darwin" → iOS/macOS
 */

import { type HookModule, type ModuleConfig } from "./hook-module";

// Android modules
import { NativeLoaderMonitor } from "../modules/native-loader";
import { FridaDetectionAuditor } from "../modules/frida-detection";
import { JNITransitionTracer } from "../modules/jni-tracer";
import { IntegrityBaseline } from "../modules/integrity";
import { NetworkProbe } from "../modules/network-probe";
import { RaspFingerprinter } from "../modules/rasp-fingerprint";

// iOS modules
import { DyldMonitor } from "../modules/ios/dyld-monitor";
import { ObjCTracer } from "../modules/ios/objc-tracer";
import { MachOIntegrity } from "../modules/ios/macho-integrity";
import { JailbreakDetectionAuditor } from "../modules/ios/jailbreak-detection";

/** Map of module id → constructor, organized by platform. */
const ANDROID_MODULES: Record<
  string,
  new (config: ModuleConfig) => HookModule
> = {
  "rasp-fingerprint": RaspFingerprinter,
  "native-loader": NativeLoaderMonitor,
  "frida-detection": FridaDetectionAuditor,
  "jni-tracer": JNITransitionTracer,
  "integrity": IntegrityBaseline,
  "network-probe": NetworkProbe,
};

const IOS_MODULES: Record<
  string,
  new (config: ModuleConfig) => HookModule
> = {
  "rasp-fingerprint": RaspFingerprinter,
  "dyld-monitor": DyldMonitor,
  "objc-tracer": ObjCTracer,
  "macho-integrity": MachOIntegrity,
  "jailbreak-detection": JailbreakDetectionAuditor,
};

/** Active module instances. */
const activeModules: HookModule[] = [];

/**
 * Parsed module config from the host.
 * Shape: { "module-id": { enabled: true, ...options } }
 */
interface ModulesConfig {
  [moduleId: string]: ModuleConfig & { enabled?: boolean };
}

/**
 * Detect which platform we're running on and return the appropriate
 * module constructor map.
 *
 * Android uses "linux" since it's Linux-based.
 * iOS/macOS uses "darwin".
 */
function getPlatformModules(): Record<
  string,
  new (config: ModuleConfig) => HookModule
> {
  const platform = Process.platform;

  if (platform === "darwin") {
    return IOS_MODULES;
  }

  // Default to Android modules (platform === "linux")
  return ANDROID_MODULES;
}

/**
 * Initialize and enable modules based on the provided configuration.
 * Automatically selects Android or iOS modules based on the platform.
 */
function initModules(config: ModulesConfig): void {
  const moduleConstructors = getPlatformModules();

  for (const [moduleId, Constructor] of Object.entries(moduleConstructors)) {
    const moduleConfig = config[moduleId];

    // Skip modules not present in config or explicitly disabled
    if (!moduleConfig || moduleConfig.enabled === false) {
      continue;
    }

    const instance = new Constructor(moduleConfig);
    instance.enable();
    activeModules.push(instance);
  }
}

/**
 * Disable all active modules. Called by the host on detach for clean teardown.
 */
function disableAll(): void {
  for (const mod of activeModules) {
    mod.disable();
  }
  activeModules.length = 0;
}

/**
 * Frida RPC exports — the host calls these via script.exports_sync.
 *
 * init(config): Pass the YAML-parsed module config to the agent.
 * disable_all(): Clean shutdown before detach.
 * get_platform(): Returns the detected platform for host-side logic.
 */
rpc.exports = {
  init(configJson: string): void {
    const config = JSON.parse(configJson) as ModulesConfig;
    initModules(config);
  },

  disableAll(): void {
    disableAll();
  },

  getPlatform(): string {
    return Process.platform;
  },
};
