/**
 * Bootstrap Tool — Registers all Sentinellium detection modules in Kahlo's module store.
 *
 * Reads each JS file from modules/ and calls kahlo_modules_create_draft + promote
 * to make them available for job execution.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { KahloClient } from "../kahlo-client.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const MODULE_MANIFEST = [
  { name: "sentinellium/native-loader", file: "native-loader.js", version: "0.1.0" },
  { name: "sentinellium/frida-detect", file: "frida-detect.js", version: "0.1.0" },
  { name: "sentinellium/rasp-fingerprint", file: "rasp-fingerprint.js", version: "0.1.0" },
  { name: "sentinellium/jni-tracer", file: "jni-tracer.js", version: "0.1.0" },
  { name: "sentinellium/integrity", file: "integrity.js", version: "0.1.0" },
  { name: "sentinellium/network-probe", file: "network-probe.js", version: "0.1.0" },
];

function loadModuleSource(filename: string): string {
  const modulesDir = resolve(__dirname, "..", "..", "..", "modules");
  return readFileSync(resolve(modulesDir, filename), "utf-8");
}

export function registerBootstrapTool(server: McpServer): void {
  server.tool(
    "sentinellium_bootstrap",
    "Register all Sentinellium detection modules in Kahlo's module store. " +
    "Required before running audits. Connects to Kahlo, uploads each module, " +
    "and returns registration status.",
    { kahlo_dist_path: z.string().describe("Path to Kahlo's dist/index.js entry point") },
    async ({ kahlo_dist_path }) => {
      const kahlo = new KahloClient();
      const results: { name: string; status: string; module_id?: string; error?: string }[] = [];

      try {
        await kahlo.connect(kahlo_dist_path);

        for (const mod of MODULE_MANIFEST) {
          try {
            const source = loadModuleSource(mod.file);
            const registered = await kahlo.createModule(mod.name, source, mod.version);
            results.push({
              name: mod.name,
              status: "registered",
              module_id: registered.id,
            });
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            results.push({
              name: mod.name,
              status: "failed",
              error: msg,
            });
          }
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "error",
              error: `Failed to connect to Kahlo: ${msg}`,
              hint: "Ensure Kahlo is installed and the dist path is correct.",
            }, null, 2),
          }],
        };
      } finally {
        await kahlo.disconnect();
      }

      const succeeded = results.filter((r) => r.status === "registered").length;
      const failed = results.filter((r) => r.status === "failed").length;

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            status: failed === 0 ? "success" : "partial",
            registered: succeeded,
            failed,
            total: MODULE_MANIFEST.length,
            modules: results,
          }, null, 2),
        }],
      };
    },
  );
}
