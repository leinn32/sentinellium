/**
 * Kahlo MCP Client — Communicates with Kahlo's MCP server over stdio transport.
 *
 * Wraps the @modelcontextprotocol/sdk Client to provide typed methods for
 * Kahlo's tool surface: device listing, target management, job lifecycle,
 * event fetching, and module registration.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

export interface KahloDevice {
  id: string;
  name: string;
  type: string;
}

export interface KahloTarget {
  id: string;
  pid: number;
  name: string;
}

export interface KahloJob {
  id: string;
  status: string;
  type: string;
  target_id: string;
}

export interface KahloEvent {
  id: string;
  job_id: string;
  target_id: string;
  level: string;
  payload: Record<string, unknown>;
  timestamp: string;
}

export interface KahloModule {
  id: string;
  name: string;
  version: string;
  status: string;
}

export class KahloClient {
  private client: Client | null = null;
  private transport: StdioClientTransport | null = null;

  /**
   * Connect to Kahlo by spawning it as a child process over stdio.
   */
  async connect(kahloDistPath: string): Promise<void> {
    this.transport = new StdioClientTransport({
      command: "node",
      args: [kahloDistPath],
    });

    this.client = new Client(
      { name: "sentinellium", version: "0.1.0" },
      { capabilities: {} },
    );

    await this.client.connect(this.transport);
  }

  /**
   * Disconnect from Kahlo gracefully.
   */
  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.close();
      this.client = null;
      this.transport = null;
    }
  }

  get isConnected(): boolean {
    return this.client !== null;
  }

  /**
   * List available Frida devices via Kahlo.
   */
  async listDevices(): Promise<KahloDevice[]> {
    return this.callTool<KahloDevice[]>("kahlo_devices_list", {});
  }

  /**
   * Ensure a target process is attached/spawned.
   */
  async ensureTarget(
    deviceId: string,
    pkg: string,
    mode: "attach" | "spawn" = "attach",
  ): Promise<KahloTarget> {
    return this.callTool<KahloTarget>("kahlo_targets_ensure", {
      device_id: deviceId,
      package: pkg,
      mode,
    });
  }

  /**
   * Start a job (run a module) on a target.
   */
  async startJob(
    targetId: string,
    moduleSource: string,
    jobType: "daemon" | "oneshot",
    params: Record<string, unknown> = {},
  ): Promise<KahloJob> {
    return this.callTool<KahloJob>("kahlo_jobs_start", {
      target_id: targetId,
      source: moduleSource,
      type: jobType,
      params,
    });
  }

  /**
   * Fetch events from Kahlo's event store.
   */
  async fetchEvents(options: {
    target_id?: string;
    job_id?: string;
    cursor?: string;
    limit?: number;
  } = {}): Promise<KahloEvent[]> {
    return this.callTool<KahloEvent[]>("kahlo_events_fetch", options);
  }

  /**
   * Cancel a running job.
   */
  async cancelJob(jobId: string): Promise<{ success: boolean }> {
    return this.callTool<{ success: boolean }>("kahlo_jobs_cancel", {
      job_id: jobId,
    });
  }

  /**
   * Detach from a target process.
   */
  async detachTarget(targetId: string): Promise<{ success: boolean }> {
    return this.callTool<{ success: boolean }>("kahlo_targets_detach", {
      target_id: targetId,
    });
  }

  /**
   * Get the status of a specific job.
   */
  async getJobStatus(jobId: string): Promise<KahloJob> {
    return this.callTool<KahloJob>("kahlo_jobs_status", {
      job_id: jobId,
    });
  }

  /**
   * Register a module in Kahlo's module store (draft → promote).
   */
  async createModule(
    name: string,
    source: string,
    version: string,
  ): Promise<KahloModule> {
    // Create draft first
    const draft = await this.callTool<KahloModule>(
      "kahlo_modules_create_draft",
      { name, source, version },
    );

    // Promote to active
    const promoted = await this.callTool<KahloModule>(
      "kahlo_modules_promote",
      { module_id: draft.id },
    );

    return promoted;
  }

  /**
   * Generic tool invocation on the Kahlo MCP server.
   */
  private async callTool<T>(
    toolName: string,
    args: Record<string, unknown>,
  ): Promise<T> {
    if (!this.client) {
      throw new Error(
        "Not connected to Kahlo. Call connect() first, or ensure Kahlo is " +
        "installed and the path is correct.",
      );
    }

    const result = await this.client.callTool({ name: toolName, arguments: args });

    // Extract the text content from the MCP response
    if (result.content && Array.isArray(result.content) && result.content.length > 0) {
      const first = result.content[0];
      if (first && "text" in first && typeof first.text === "string") {
        return JSON.parse(first.text) as T;
      }
    }

    if (result.isError) {
      const errMsg = Array.isArray(result.content)
        ? result.content.map((c: { type: string; text?: string }) => c.text ?? "").join(" ")
        : "unknown error";
      throw new Error(`Kahlo error in ${toolName}: ${errMsg}`);
    }

    throw new Error(`Unexpected response format from Kahlo tool ${toolName}`);
  }
}
