/**
 * Typed event bus for agent-to-host communication.
 *
 * All telemetry flows through emitEvent(), which enforces the TelemetryEvent
 * schema before calling Frida's send(). This single chokepoint ensures the
 * host never receives malformed messages, simplifying Pydantic deserialization
 * on the Python side.
 */

/** Severity levels aligned with RASP threat classification. */
export type Severity = "info" | "warning" | "critical";

/**
 * The single message schema for all agent→host communication.
 *
 * Design rationale: using one interface with a discriminator field ("type")
 * rather than per-module message types keeps the host's on('message') handler
 * simple and makes it trivial to add new modules without touching host code.
 */
export interface TelemetryEvent {
  type: "telemetry";
  module_id: string;
  timestamp: number;
  severity: Severity;
  data: Record<string, unknown>;
  stacktrace?: string;
}

/**
 * Emit a telemetry event to the host via Frida's send() IPC.
 *
 * This is the only function that should call send() in the entire agent.
 * Centralizing IPC here lets us add batching, rate-limiting, or filtering
 * in the future without modifying any module code.
 */
export function emitEvent(
  moduleId: string,
  severity: Severity,
  data: Record<string, unknown>,
  stacktrace?: string
): void {
  const event: TelemetryEvent = {
    type: "telemetry",
    module_id: moduleId,
    timestamp: Date.now(),
    severity,
    data,
  };

  if (stacktrace !== undefined) {
    event.stacktrace = stacktrace;
  }

  send(event);
}
