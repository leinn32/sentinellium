#!/usr/bin/env node

/**
 * Sentinellium MCP Server — RASP auditing orchestration layer for Kahlo.
 *
 * Exposes 6 tools to AI agents:
 *   sentinellium_about       — Tool inventory and RASP glossary
 *   sentinellium_bootstrap   — Register detection modules in Kahlo
 *   sentinellium_audit       — Full audit workflow: fingerprint → detect → score
 *   sentinellium_fingerprint — Quick RASP SDK identification
 *   sentinellium_report      — Format results as JSON or Markdown
 *   sentinellium_simulate    — Real-time RASP simulation with policies
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { registerAboutTool } from "./tools/about.js";
import { registerBootstrapTool } from "./tools/bootstrap.js";
import { registerAuditTool } from "./tools/audit.js";
import { registerFingerprintTool } from "./tools/fingerprint.js";
import { registerReportTool } from "./tools/report.js";
import { registerSimulateTool } from "./tools/simulate.js";

const server = new McpServer({
  name: "sentinellium",
  version: "0.1.0",
});

// Register all tools
registerAboutTool(server);
registerBootstrapTool(server);
registerAuditTool(server);
registerFingerprintTool(server);
registerReportTool(server);
registerSimulateTool(server);

// Start the server on stdio
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`Sentinellium MCP server failed to start: ${msg}\n`);
  process.exit(1);
});
