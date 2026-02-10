/**
 * Fingerprint Tool — Quick RASP SDK identification.
 *
 * Runs only the rasp-fingerprint module for a fast SDK identification
 * without the full audit overhead.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { KahloClient, type KahloEvent } from "../kahlo-client.js";
import { identifySDK, listKnownSDKs } from "../analysis/fingerprint-db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function loadModuleSource(filename: string): string {
  const modulesDir = resolve(__dirname, "..", "..", "..", "modules");
  return readFileSync(resolve(modulesDir, filename), "utf-8");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function registerFingerprintTool(server: McpServer): void {
  server.tool(
    "sentinellium_fingerprint",
    "Quick RASP SDK identification. Attaches to the target app, runs the " +
    "fingerprint module, and reports which RASP SDK is detected with confidence score.",
    {
      kahlo_dist_path: z.string().describe("Path to Kahlo's dist/index.js"),
      device_id: z.string().describe("Kahlo device ID"),
      package_name: z.string().describe("Target app package name"),
      mode: z.enum(["attach", "spawn"]).default("attach").describe("Attach or spawn"),
    },
    async ({ kahlo_dist_path, device_id, package_name, mode }) => {
      const kahlo = new KahloClient();
      let targetId: string | undefined;

      try {
        await kahlo.connect(kahlo_dist_path);

        // Attach to target
        const target = await kahlo.ensureTarget(device_id, package_name, mode);
        targetId = target.id;

        // Run fingerprint module (oneshot)
        const source = loadModuleSource("rasp-fingerprint.js");
        const job = await kahlo.startJob(targetId, source, "oneshot");

        // Wait for completion (max 15s)
        for (let i = 0; i < 15; i++) {
          const status = await kahlo.getJobStatus(job.id);
          if (status.status === "completed" || status.status === "error") break;
          await sleep(1000);
        }

        // Fetch events
        const events = await kahlo.fetchEvents({ job_id: job.id });

        // Find the identification result
        const fpEvent = events.find(
          (e: KahloEvent) =>
            e.payload?.event === "rasp_identified" ||
            e.payload?.event === "rasp_unknown" ||
            e.payload?.event === "no_rasp_detected",
        );

        if (!fpEvent) {
          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                status: "error",
                error: "Fingerprint module completed but produced no identification event",
                events_count: events.length,
              }, null, 2),
            }],
          };
        }

        const identification = identifySDK(fpEvent.payload);

        let knownSdks: { id: string; name: string }[] = [];
        try {
          knownSdks = listKnownSDKs();
        } catch { /* non-critical */ }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "complete",
              target: { package: package_name, device: device_id },
              identification,
              all_candidates: fpEvent.payload.all_candidates ?? {},
              known_sdks: knownSdks,
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
            }, null, 2),
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
