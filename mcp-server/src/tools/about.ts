/**
 * About Tool — Tool inventory, module descriptions, and RASP glossary.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { listKnownSDKs } from "../analysis/fingerprint-db.js";

const TOOL_INVENTORY = [
  {
    name: "sentinellium_about",
    description: "Tool inventory, module descriptions, and RASP glossary",
  },
  {
    name: "sentinellium_bootstrap",
    description: "Register all Sentinellium detection modules in Kahlo's module store",
  },
  {
    name: "sentinellium_audit",
    description: "Full audit: fingerprint RASP SDK → start detection modules → poll events → score",
  },
  {
    name: "sentinellium_fingerprint",
    description: "Quick RASP SDK identification — which vendor protects this app?",
  },
  {
    name: "sentinellium_report",
    description: "Format audit results as JSON or Markdown",
  },
  {
    name: "sentinellium_simulate",
    description: "Real-time RASP policy simulation with kill/log actions",
  },
];

const MODULE_DESCRIPTIONS = [
  {
    name: "native-loader",
    file: "modules/native-loader.js",
    type: "daemon",
    description: "Hooks android_dlopen_ext to trace native library loading and detect injection",
    rasp_feature: "Tamper detection, library injection monitoring",
  },
  {
    name: "frida-detect",
    file: "modules/frida-detect.js",
    type: "oneshot",
    description: "Scores Frida visibility via /proc/self/maps, port scan, trampolines, threads",
    rasp_feature: "Anti-instrumentation, detection surface mapping",
  },
  {
    name: "rasp-fingerprint",
    file: "modules/rasp-fingerprint.js",
    type: "oneshot",
    description: "Identifies RASP SDK via native modules, Java classes, string patterns, behavior",
    rasp_feature: "RASP SDK identification (Wultra, Promon, Guardsquare, etc.)",
  },
  {
    name: "jni-tracer",
    file: "modules/jni-tracer.js",
    type: "daemon",
    description: "Traces art::JNI::Call*MethodV to map all Java↔native transitions",
    rasp_feature: "Native call surface enumeration, RASP check discovery",
  },
  {
    name: "integrity",
    file: "modules/integrity.js",
    type: "daemon",
    description: "SHA-256 baselines of .text sections, periodic re-check for modifications",
    rasp_feature: "Code integrity verification, anti-patching validation",
  },
  {
    name: "network-probe",
    file: "modules/network-probe.js",
    type: "daemon",
    description: "Hooks libc connect() to monitor native-layer TCP connections",
    rasp_feature: "C2 detection, hardcoded IP flagging, proxy evasion",
  },
];

const RASP_GLOSSARY: Record<string, string> = {
  "RASP": "Runtime Application Self-Protection — in-app security that detects and prevents attacks at runtime",
  "Frida": "Dynamic instrumentation toolkit for reverse engineering and security research",
  "Kahlo": "Wultra's Frida orchestration layer — manages devices, targets, jobs, and events via MCP",
  "Trampoline": "Inline hook prologue pattern (e.g., LDR X16, #8; BR X16 on arm64) that replaces function entry",
  "Detection Surface": "Percentage of standard RASP checks that detect the current instrumentation setup",
  "Integrity Baseline": "SHA-256 hash snapshot of executable memory, used to detect runtime code patching",
  "JNI Transition": "Java↔Native boundary call through ART's JNI layer — attack surface for RASP bypass",
  "C2": "Command and Control — server that malware communicates with, often via hardcoded IPs",
  "Risk Score": "0-100 aggregate measure of RASP audit findings (higher = more gaps found)",
};

export function registerAboutTool(server: McpServer): void {
  server.tool(
    "sentinellium_about",
    "Sentinellium tool inventory, detection module descriptions, RASP glossary, and known SDK list",
    {},
    async () => {
      let knownSdks: { id: string; name: string }[] = [];
      try {
        knownSdks = listKnownSDKs();
      } catch {
        // Signature DB not available — return empty list
      }

      const result = {
        tools: TOOL_INVENTORY,
        modules: MODULE_DESCRIPTIONS,
        glossary: RASP_GLOSSARY,
        known_rasp_sdks: knownSdks,
      };

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    },
  );
}
