/**
 * Simulate Tool — Real-time RASP policy simulation with kill/log actions.
 *
 * Runs detection modules and applies a configurable policy to events in real-time.
 * "kill" policy on critical findings triggers target detach (simulating app termination).
 * "log" policy observes without intervention.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import yaml from "js-yaml";
import { KahloClient, type KahloEvent, type KahloJob } from "../kahlo-client.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface SimulationPolicy {
  critical: "kill" | "log";
  warning: "kill" | "log";
}

const SIMULATION_MODULES = [
  { name: "native-loader", file: "native-loader.js", type: "daemon" as const },
  { name: "frida-detect", file: "frida-detect.js", type: "oneshot" as const },
  { name: "integrity", file: "integrity.js", type: "daemon" as const },
];

function loadModuleSource(filename: string): string {
  const modulesDir = resolve(__dirname, "..", "..", "..", "modules");
  return readFileSync(resolve(modulesDir, filename), "utf-8");
}

function loadPolicy(policyName: string): SimulationPolicy {
  const policiesDir = resolve(__dirname, "..", "..", "..", "config", "policies");
  try {
    const raw = readFileSync(resolve(policiesDir, `${policyName}.yaml`), "utf-8");
    const parsed = yaml.load(raw) as Record<string, unknown>;
    return {
      critical: (parsed?.critical as string) === "kill" ? "kill" : "log",
      warning: (parsed?.warning as string) === "kill" ? "kill" : "log",
    };
  } catch {
    // Default: strict policy
    return { critical: "kill", warning: "log" };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function registerSimulateTool(server: McpServer): void {
  server.tool(
    "sentinellium_simulate",
    "Real-time RASP simulation. Runs detection modules and applies a policy " +
    "(strict/monitor/custom) to events. 'kill' actions detach the target, " +
    "simulating app termination. Returns a timeline of events and actions taken.",
    {
      kahlo_dist_path: z.string().describe("Path to Kahlo's dist/index.js"),
      device_id: z.string().describe("Kahlo device ID"),
      package_name: z.string().describe("Target app package name"),
      mode: z.enum(["attach", "spawn"]).default("attach"),
      policy: z.enum(["strict", "monitor"]).default("strict").describe("Policy: strict (kill on critical) or monitor (log only)"),
      duration_seconds: z.number().min(5).max(120).default(15).describe("Simulation duration"),
    },
    async ({ kahlo_dist_path, device_id, package_name, mode, policy: policyName, duration_seconds }) => {
      const kahlo = new KahloClient();
      let targetId: string | undefined;
      const jobs: KahloJob[] = [];
      const timeline: { timestamp: string; level: string; event: string; action: string; detail?: string }[] = [];
      let killed = false;

      const simPolicy = loadPolicy(policyName);

      try {
        await kahlo.connect(kahlo_dist_path);

        const target = await kahlo.ensureTarget(device_id, package_name, mode);
        targetId = target.id;

        // Start simulation modules
        for (const mod of SIMULATION_MODULES) {
          try {
            const source = loadModuleSource(mod.file);
            const job = await kahlo.startJob(targetId, source, mod.type);
            jobs.push(job);
          } catch {
            // Non-fatal
          }
        }

        // Poll events and apply policy
        let cursor: string | undefined;
        const endTime = Date.now() + duration_seconds * 1000;

        while (Date.now() < endTime && !killed) {
          await sleep(2000);

          const events = await kahlo.fetchEvents({
            target_id: targetId,
            cursor,
            limit: 100,
          });

          if (events.length === 0) continue;
          cursor = events[events.length - 1]!.id;

          for (const event of events) {
            let action = "observed";

            if (event.level === "error" && simPolicy.critical === "kill") {
              action = "KILL — detaching target";
              killed = true;
            } else if (event.level === "warn" && simPolicy.warning === "kill") {
              action = "KILL — detaching target";
              killed = true;
            } else if (event.level === "error") {
              action = "LOG — critical finding recorded";
            } else if (event.level === "warn") {
              action = "LOG — warning recorded";
            }

            timeline.push({
              timestamp: event.timestamp,
              level: event.level,
              event: (event.payload?.event as string) ?? "unknown",
              action,
              detail: event.level === "error"
                ? JSON.stringify(event.payload)
                : undefined,
            });

            if (killed) {
              // Simulate app termination
              try {
                if (targetId) {
                  await kahlo.detachTarget(targetId);
                  targetId = undefined; // Prevent double-detach in finally
                }
              } catch { /* best effort */ }
              break;
            }
          }
        }

        // Cancel remaining daemon jobs
        for (const job of jobs) {
          if (job.type === "daemon") {
            try { await kahlo.cancelJob(job.id); } catch { /* best effort */ }
          }
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: killed ? "killed" : "completed",
              policy: { name: policyName, ...simPolicy },
              target: { package: package_name, device: device_id },
              duration_seconds: killed
                ? Math.round((Date.now() - (endTime - duration_seconds * 1000)) / 1000)
                : duration_seconds,
              timeline,
              summary: {
                total_events: timeline.length,
                kills: timeline.filter((t) => t.action.startsWith("KILL")).length,
                criticals: timeline.filter((t) => t.level === "error").length,
                warnings: timeline.filter((t) => t.level === "warn").length,
              },
            }, null, 2),
          }],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({ status: "error", error: msg }, null, 2),
          }],
        };
      } finally {
        try {
          if (targetId) await kahlo.detachTarget(targetId);
        } catch { /* best effort */ }
        await kahlo.disconnect();
      }
    },
  );
}
