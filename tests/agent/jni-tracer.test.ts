/**
 * Tests for JNITransitionTracer — RASP method pattern matching, ART symbol
 * regex patterns, and throttle map logic.
 *
 * Frida APIs are unavailable in vitest, so we replicate the pure logic
 * portions of the module for unit testing.
 */

import { describe, it, expect, beforeEach } from "vitest";

/** Replicated from JNITransitionTracer. */
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

/** Replicated from JNITransitionTracer. */
const JNI_SYMBOL_PATTERNS: RegExp[] = [
  /^_ZN3art3JNI\d+Call.*Method/,
  /^_ZN3art3JNI\d+Get.*Field/,
  /^_ZN3art3JNI\d+Set.*Field/,
  /^_ZN3art3JNI\d+NewObject/,
];

/** Replicated from JNITransitionTracer.isRaspMethod. */
function isRaspMethod(method: string, className: string): boolean {
  const combined = `${className}.${method}`.toLowerCase();
  return RASP_METHOD_PATTERNS.some((pattern) => combined.includes(pattern));
}

describe("JNI RASP method pattern matching", () => {
  it("should detect root check method", () => {
    expect(isRaspMethod("checkRootStatus", "com.security.RootDetector")).toBe(
      true
    );
  });

  it("should detect isRooted method", () => {
    expect(isRaspMethod("isRooted", "com.app.SecurityManager")).toBe(true);
  });

  it("should detect signature verification", () => {
    expect(
      isRaspMethod("verifySignature", "com.security.IntegrityCheck")
    ).toBe(true);
  });

  it("should detect debugger check", () => {
    expect(isRaspMethod("isDebuggerAttached", "com.rasp.AntiDebug")).toBe(true);
  });

  it("should detect anti-Frida method", () => {
    expect(isRaspMethod("antiFridaScan", "com.shield.Protection")).toBe(true);
  });

  it("should detect SafetyNet attestation", () => {
    expect(isRaspMethod("requestAttestation", "com.app.SafetyNetHelper")).toBe(
      true
    );
  });

  it("should detect integrity check in class name", () => {
    expect(isRaspMethod("run", "com.security.IntegrityVerifier")).toBe(true);
  });

  it("should detect emulator check", () => {
    expect(isRaspMethod("isEmulator", "com.device.EnvironmentCheck")).toBe(
      true
    );
  });

  it("should detect tamper detection", () => {
    expect(isRaspMethod("onTamperDetected", "com.rasp.TamperGuard")).toBe(true);
  });

  it("should not flag normal app methods", () => {
    expect(isRaspMethod("onClick", "com.app.MainActivity")).toBe(false);
    expect(isRaspMethod("onResume", "com.app.BaseActivity")).toBe(false);
    expect(isRaspMethod("loadData", "com.app.DataManager")).toBe(false);
    expect(isRaspMethod("getUserProfile", "com.api.UserService")).toBe(false);
  });

  it("should be case-insensitive", () => {
    expect(isRaspMethod("CHECKROOT", "COM.SECURITY.ROOT")).toBe(true);
    expect(isRaspMethod("CheckRoot", "Com.Security.Root")).toBe(true);
  });
});

describe("JNI ART symbol pattern matching", () => {
  function matchesAnyJniPattern(symbolName: string): boolean {
    return JNI_SYMBOL_PATTERNS.some((p) => p.test(symbolName));
  }

  it("should match CallVoidMethodV", () => {
    expect(
      matchesAnyJniPattern("_ZN3art3JNI14CallVoidMethodVEP7_JNIEnvP8_jobjectP10_jmethodIDP13__va_list_tag")
    ).toBe(true);
  });

  it("should match CallObjectMethodV", () => {
    expect(
      matchesAnyJniPattern("_ZN3art3JNI16CallObjectMethodVEP7_JNIEnvP8_jobjectP10_jmethodIDP13__va_list_tag")
    ).toBe(true);
  });

  it("should match CallStaticBooleanMethodV", () => {
    expect(
      matchesAnyJniPattern("_ZN3art3JNI25CallStaticBooleanMethodVEP7_JNIEnvP7_jclassP10_jmethodIDP13__va_list_tag")
    ).toBe(true);
  });

  it("should match GetIntField", () => {
    expect(
      matchesAnyJniPattern("_ZN3art3JNI11GetIntFieldEP7_JNIEnvP8_jobjectP9_jfieldID")
    ).toBe(true);
  });

  it("should match SetObjectField", () => {
    expect(
      matchesAnyJniPattern("_ZN3art3JNI14SetObjectFieldEP7_JNIEnvP8_jobjectP9_jfieldIDS4_")
    ).toBe(true);
  });

  it("should match NewObject", () => {
    expect(
      matchesAnyJniPattern("_ZN3art3JNI9NewObjectVEP7_JNIEnvP7_jclassP10_jmethodIDP13__va_list_tag")
    ).toBe(true);
  });

  it("should not match unrelated ART symbols", () => {
    expect(matchesAnyJniPattern("_ZN3art7Runtime4InitEv")).toBe(false);
    expect(matchesAnyJniPattern("_ZN3art6Thread6CreateEv")).toBe(false);
    expect(matchesAnyJniPattern("malloc")).toBe(false);
    expect(matchesAnyJniPattern("__libc_init")).toBe(false);
  });
});

describe("JNI tracer throttle logic", () => {
  const THROTTLE_MS = 100;

  /** Replicated throttle check logic. */
  function shouldThrottle(
    key: string,
    now: number,
    recentMethods: Map<string, number>
  ): boolean {
    const lastLog = recentMethods.get(key);
    if (lastLog !== undefined && now - lastLog < THROTTLE_MS) {
      return true;
    }
    recentMethods.set(key, now);
    return false;
  }

  let recentMethods: Map<string, number>;

  beforeEach(() => {
    recentMethods = new Map();
  });

  it("should not throttle first call", () => {
    expect(shouldThrottle("com.app.Foo.bar", 1000, recentMethods)).toBe(false);
  });

  it("should throttle rapid duplicate calls", () => {
    shouldThrottle("com.app.Foo.bar", 1000, recentMethods);
    expect(shouldThrottle("com.app.Foo.bar", 1050, recentMethods)).toBe(true);
  });

  it("should allow call after throttle window expires", () => {
    shouldThrottle("com.app.Foo.bar", 1000, recentMethods);
    expect(shouldThrottle("com.app.Foo.bar", 1200, recentMethods)).toBe(false);
  });

  it("should throttle different methods independently", () => {
    shouldThrottle("com.app.Foo.bar", 1000, recentMethods);
    expect(shouldThrottle("com.app.Foo.baz", 1050, recentMethods)).toBe(false);
  });

  it("should allow at exactly the boundary", () => {
    shouldThrottle("com.app.Foo.bar", 1000, recentMethods);
    // At exactly 100ms later, lastLog=1000, now=1100 → 1100-1000 = 100, not < 100
    expect(shouldThrottle("com.app.Foo.bar", 1100, recentMethods)).toBe(false);
  });
});
