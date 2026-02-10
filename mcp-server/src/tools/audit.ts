/**
 * Audit Tool — Full RASP audit workflow.
 *
 * Orchestrates: fingerprint → start detection modules → poll events → score.
 * Returns a complete audit result with risk score and per-module breakdown.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { KahloClient, type KahloEvent, type KahloJob } from "../kahlo-client.js";
import { computeScore, type AuditEvent } from "../analysis/scoring.js";
import { identifySDK } from "../analysis/fingerprint-db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface AuditModuleSpec {
  name: string;
  file: string;
  type: "daemon" | "oneshot";
  params?: Record<string, unknown>;
}

const DEFAULT_MODULES: AuditModuleSpec[] = [
  { name: "rasp-fingerprint", file: "rasp-fingerprint.js", type: "oneshot" },
  { name: "frida-detect", file: "frida-detect.js", type: "oneshot" },
  { name: "native-loader", file: "native-loader.js", type: "daemon" },
  { name: "jni-tracer", file: "jni-tracer.js", type: "daemon" },
  { name: "integrity", file: "integrity.js", type: "daemon" },
];

function loadModuleSource(filename: string): string {
  const modulesDir = resolve(__dirname, "..", "..", "..", "modules");
  return readFileSync(resolve(modulesDir, filename), "utf-8");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function registerAuditTool(server: McpServer): void {
  server.tool(
    "sentinellium_audit",
    "Run a full RASP audit: fingerprint the SDK, start detection modules, " +
    "collect events for the specified duration, compute risk score. " +
    "Returns structured results with per-module breakdown.",
    {
      kahlo_dist_path: z.string().describe("Path to Kahlo's dist/index.js"),
      device_id: z.string().describe("Kahlo device ID"),
      package_name: z.string().describe("Target app package name"),
      mode: z.enum(["attach", "spawn"]).default("attach").describe("Attach to running or spawn"),
      duration_seconds: z.number().min(5).max(300).default(30).describe("Audit duration in seconds"),
      include_network: z.boolean().default(false).describe("Include network-probe (noisy)"),
    },
    async ({ kahlo_dist_path, device_id, package_name, mode, duration_seconds, include_network }) => {
      const kahlo = new KahloClient();
      const jobs: KahloJob[] = [];
      let targetId: string | undefined;

      try {
        await kahlo.connect(kahlo_dist_path);

        // 1. Ensure target
        const target = await kahlo.ensureTarget(device_id, package_name, mode);
        targetId = target.id;

        // 2. Build module list
        const modules = [...DEFAULT_MODULES];
        if (include_network) {
          modules.push({ name: "network-probe", file: "network-probe.js", type: "daemon" });
        }

        // 3. Start all modules
        for (const mod of modules) {
          try {
            const source = loadModuleSource(mod.file);
            const job = await kahlo.startJob(targetId, source, mod.type, mod.params ?? {});
            jobs.push(job);
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            // Non-fatal: continue with other modules
            jobs.push({
              id: "failed",
              status: "error",
              type: mod.type,
              target_id: targetId,
            });
          }
        }

        // 4. Wait for oneshot modules to complete, then wait for daemon duration
        const oneshotJobs = jobs.filter((j) => j.type === "oneshot" && j.id !== "failed");

        // Poll oneshot completion (max 30s)
        for (let i = 0; i < 30; i++) {
          const statuses = await Promise.all(
            oneshotJobs.map((j) => kahlo.getJobStatus(j.id)),
          );
          if (statuses.every((s) => s.status === "completed" || s.status === "error")) break;
          await sleep(1000);
        }

        // Let daemon modules run for the configured duration
        await sleep(duration_seconds * 1000);

        // 5. Fetch all events
        const allEvents = await kahlo.fetchEvents({ target_id: targetId });

        // 6. Cancel daemon jobs
        const daemonJobs = jobs.filter((j) => j.type === "daemon" && j.id !== "failed");
        for (const job of daemonJobs) {
          try {
            await kahlo.cancelJob(job.id);
          } catch {
            // Best effort cleanup
          }
        }

        // 7. Compute risk score
        const auditEvents: AuditEvent[] = allEvents.map((e: KahloEvent) => ({
          job_id: e.job_id,
          module: inferModule(e),
          level: e.level,
          payload: e.payload,
        }));

        const scoring = computeScore(auditEvents);

        // 8. Identify RASP SDK from fingerprint events
        const fpEvent = allEvents.find(
          (e: KahloEvent) =>
            e.payload?.event === "rasp_identified" ||
            e.payload?.event === "rasp_unknown" ||
            e.payload?.event === "no_rasp_detected",
        );
        const identification = fpEvent ? identifySDK(fpEvent.payload) : null;

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "complete",
              target: { package: package_name, device: device_id, mode },
              duration_seconds,
              rasp_sdk: identification,
              risk_score: scoring.score,
              module_breakdown: scoring.modules,
              bonuses: scoring.bonuses,
              total_events: allEvents.length,
              jobs: jobs.map((j) => ({
                id: j.id,
                type: j.type,
                status: j.status,
              })),
            }, null, 2),
          }],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "error",
              error: msg,
              hint: "Ensure Kahlo is running and the target app is installed.",
            }, null, 2),
          }],
        };
      } finally {
        // Cleanup
        try {
          if (targetId) await kahlo.detachTarget(targetId);
        } catch { /* best effort */ }
        await kahlo.disconnect();
      }
    },
  );
}

/**
 * Infer which Sentinellium module produced an event based on payload content.
 */
function inferModule(event: KahloEvent): string {
  const p = event.payload;
  if (!p) return "unknown";

  const eventType = p.event as string | undefined;
  if (!eventType) return "unknown";

  if (eventType.startsWith("rasp_") || eventType === "no_rasp_detected") return "rasp-fingerprint";
  if (eventType.includes("library_load") || eventType === "suspicious_library_load") return "native-loader";
  if (eventType.includes("frida_") || eventType.includes("detection_summary")) return "frida-detect";
  if (eventType.includes("jni_") || eventType === "rasp_jni_call") return "jni-tracer";
  if (eventType.includes("integrity") || eventType.includes("baseline")) return "integrity";
  if (eventType.includes("connect") || eventType === "suspicious_connect") return "network-probe";

  if (p.check) {
    const check = p.check as string;
    if (check.includes("memory_maps") || check.includes("port_scan") ||
        check.includes("trampoline") || check.includes("thread_scan")) {
      return "frida-detect";
    }
  }

  return "unknown";
}
