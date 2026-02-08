/**
 * ObjCTracer — Selective Objective-C message tracing for iOS.
 *
 * What:  Intercepts specific Objective-C method implementations using Frida's
 *        ObjC API rather than hooking objc_msgSend directly.
 *
 * Why:   objc_msgSend is called millions of times per second on iOS — directly
 *        hooking it would freeze the app. Instead, we selectively hook specific
 *        class/selector combinations that are relevant to RASP behavior:
 *        file existence checks, URL scheme queries, environment access, and
 *        network calls. This targeted approach captures RASP-relevant API calls
 *        without the performance impact of blanket message tracing.
 *
 * RASP:  Maps the Objective-C API surface that iOS RASP SDKs use for environment
 *        checks. Output tells a researcher exactly which ObjC calls the SDK
 *        relies on for jailbreak detection, file system checks, and network
 *        security validation.
 */

import { BaseHookModule, type ModuleConfig } from "../../core/hook-module";

/** Default targets: ObjC classes and selectors commonly used in RASP checks. */
const DEFAULT_TARGETS: ObjCTarget[] = [
  {
    className: "NSFileManager",
    selectors: ["fileExistsAtPath:", "contentsOfDirectoryAtPath:error:"],
  },
  {
    className: "NSURLSession",
    selectors: ["dataTaskWithRequest:completionHandler:"],
  },
  {
    className: "UIApplication",
    selectors: ["canOpenURL:"],
  },
  {
    className: "NSProcessInfo",
    selectors: ["environment"],
  },
];

/** Paths that indicate jailbreak detection when passed to file system APIs. */
const JAILBREAK_PATHS = [
  "/applications/cydia.app",
  "/usr/bin/ssh",
  "/bin/bash",
  "/usr/sbin/sshd",
  "/etc/apt",
  "/private/var/lib/apt",
  "/private/var/lib/cydia",
  "/library/mobilesubstrate",
  "/usr/bin/cycript",
  "/private/var/stash",
  "/usr/lib/tweakinject",
];

/** URL schemes associated with jailbreak tools. */
const JAILBREAK_SCHEMES = ["cydia://", "sileo://", "zbra://"];

interface ObjCTarget {
  className: string;
  selectors: string[];
}

export class ObjCTracer extends BaseHookModule {
  readonly id = "objc-tracer";

  /** Original implementations to restore on disable. */
  private origImplementations: Map<string, NativePointer> = new Map();

  /** Configurable trace targets. */
  private targets: ObjCTarget[];

  constructor(config: ModuleConfig = {}) {
    super(config);

    // Load custom targets from config or use defaults
    const rawTargets = config["targets"];
    if (Array.isArray(rawTargets)) {
      this.targets = rawTargets as ObjCTarget[];
    } else {
      this.targets = DEFAULT_TARGETS;
    }
  }

  protected onEnable(): void {
    if (!ObjC.available) {
      throw new Error("ObjC runtime not available — not an iOS process");
    }

    for (const target of this.targets) {
      this.hookTarget(target);
    }
  }

  protected onDisable(): void {
    // Restore original implementations
    for (const [key, origImpl] of this.origImplementations.entries()) {
      try {
        const [className, selector] = key.split("::", 2) as [string, string];
        const cls = ObjC.classes[className];
        if (cls !== undefined) {
          const method = cls[`- ${selector}`] || cls[`+ ${selector}`];
          if (method !== undefined) {
            method.implementation = origImpl;
          }
        }
      } catch {
        // Best-effort restoration
      }
    }
    this.origImplementations.clear();
  }

  /**
   * Hook all selectors for a given ObjC class.
   *
   * Uses Frida's ObjC.classes[name][selector].implementation replacement
   * rather than Interceptor.attach. This is the idiomatic way to hook
   * ObjC methods in Frida — it handles the message dispatch mechanism
   * correctly and avoids interfering with objc_msgSend's fastpath.
   */
  private hookTarget(target: ObjCTarget): void {
    const cls = ObjC.classes[target.className];
    if (cls === undefined) {
      this.emit("info", {
        event: "class_not_found",
        class: target.className,
        detail: `ObjC class ${target.className} not loaded`,
      });
      return;
    }

    for (const selector of target.selectors) {
      this.hookSelector(target.className, cls, selector);
    }
  }

  /**
   * Hook a single ObjC selector on a class.
   *
   * We replace the method implementation with a wrapper that logs the
   * call, checks for RASP-relevant arguments, then calls through to
   * the original implementation.
   */
  private hookSelector(
    className: string,
    cls: ObjC.Object,
    selector: string
  ): void {
    // Try instance method first, then class method
    const method = cls[`- ${selector}`] || cls[`+ ${selector}`];
    if (method === undefined) {
      this.emit("info", {
        event: "selector_not_found",
        class: className,
        selector,
      });
      return;
    }

    const key = `${className}::${selector}`;
    const self = this;

    try {
      const origImpl = method.implementation;
      this.origImplementations.set(key, origImpl);

      method.implementation = ObjC.implement(method, function (
        this: InvocationContext,
        ...args: NativePointer[]
      ): NativePointer {
        try {
          self.traceCall(className, selector, args);
        } catch {
          // Never crash the app for tracing
        }
        return origImpl.apply(this, args) as NativePointer;
      });

      this.emit("info", {
        event: "selector_hooked",
        class: className,
        selector,
      });
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("info", {
        event: "hook_failed",
        class: className,
        selector,
        error: msg,
      });
    }
  }

  /**
   * Process an intercepted ObjC call.
   *
   * Extracts the first argument (if it's a string) and checks for
   * RASP-relevant patterns like jailbreak file paths and URL schemes.
   */
  private traceCall(
    className: string,
    selector: string,
    args: NativePointer[]
  ): void {
    // args[0] = self, args[1] = _cmd, args[2+] = actual parameters
    let firstArg = "";

    // Try to extract the first real argument as a string
    if (args.length > 2 && args[2] !== undefined && !args[2].isNull()) {
      try {
        const nsStr = new ObjC.Object(args[2]);
        if (nsStr.$className === "NSString" || nsStr.$className === "__NSCFString") {
          firstArg = nsStr.toString();
        } else if (nsStr.$className === "NSURL" || nsStr.$className === "__NSCFConstantString") {
          firstArg = nsStr.toString();
        }
      } catch {
        // Not an ObjC object or can't convert — skip
      }
    }

    // Check if this is a RASP-relevant call
    const raspRelevance = this.checkRaspRelevance(
      className,
      selector,
      firstArg
    );

    if (raspRelevance !== null) {
      this.emit("warning", {
        event: "rasp_objc_call",
        class: className,
        selector,
        argument: firstArg,
        rasp_check: raspRelevance,
      });
    } else {
      this.emit("info", {
        event: "objc_call",
        class: className,
        selector,
        argument: firstArg || undefined,
      });
    }
  }

  /**
   * Determine if an ObjC call is related to RASP detection checks.
   *
   * Returns a description of the RASP check type, or null if not relevant.
   */
  private checkRaspRelevance(
    className: string,
    selector: string,
    firstArg: string
  ): string | null {
    const lowerArg = firstArg.toLowerCase();

    // File existence checks with jailbreak paths
    if (
      className === "NSFileManager" &&
      selector.includes("fileExists")
    ) {
      for (const jbPath of JAILBREAK_PATHS) {
        if (lowerArg.includes(jbPath)) {
          return `jailbreak_file_check:${firstArg}`;
        }
      }
    }

    // Directory listing of jailbreak-related paths
    if (
      className === "NSFileManager" &&
      selector.includes("contentsOfDirectory")
    ) {
      for (const jbPath of JAILBREAK_PATHS) {
        if (lowerArg.includes(jbPath)) {
          return `jailbreak_dir_check:${firstArg}`;
        }
      }
    }

    // URL scheme checks (canOpenURL: with cydia://, sileo://)
    if (className === "UIApplication" && selector === "canOpenURL:") {
      for (const scheme of JAILBREAK_SCHEMES) {
        if (lowerArg.startsWith(scheme)) {
          return `jailbreak_scheme_check:${firstArg}`;
        }
      }
    }

    // Environment access (often used to check for injected env vars)
    if (className === "NSProcessInfo" && selector === "environment") {
      return "environment_enumeration";
    }

    return null;
  }
}
