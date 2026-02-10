/**
 * Risk Scoring Engine — Computes a 0-100 RASP audit risk score from events.
 *
 * Scoring rules:
 *   - level: "error" event:   +15 per event
 *   - level: "warn" event:    +5  per event
 *   - Unique module with any error events: +10 bonus per module
 *   - Frida detection surface < 50%: +10 (stealth is too easy)
 *   - RASP SDK "unknown": +5 (unidentified SDK is a risk signal)
 *   - Cap at 100
 */

export interface ScoredEvent {
  module: string;
  level: string;
  event: string;
  points: number;
  payload: Record<string, unknown>;
}

export interface ModuleBreakdown {
  module: string;
  events: number;
  errors: number;
  warnings: number;
  infos: number;
  score: number;
}

export interface ScoringResult {
  score: number;
  modules: ModuleBreakdown[];
  scored_events: ScoredEvent[];
  bonuses: { reason: string; points: number }[];
}

export interface AuditEvent {
  job_id?: string;
  module?: string;
  level: string;
  payload: Record<string, unknown>;
}

const POINTS_ERROR = 15;
const POINTS_WARNING = 5;
const BONUS_MODULE_WITH_ERRORS = 10;
const BONUS_LOW_DETECTION_SURFACE = 10;
const BONUS_UNKNOWN_SDK = 5;
const MAX_SCORE = 100;

export function computeScore(events: AuditEvent[]): ScoringResult {
  const scored: ScoredEvent[] = [];
  const moduleMap = new Map<string, ModuleBreakdown>();
  const bonuses: { reason: string; points: number }[] = [];

  let rawScore = 0;

  // Score individual events
  for (const event of events) {
    const moduleName = event.module ?? event.payload?.module as string ?? "unknown";
    let points = 0;

    if (event.level === "error") {
      points = POINTS_ERROR;
    } else if (event.level === "warn") {
      points = POINTS_WARNING;
    }

    if (points > 0) {
      rawScore += points;
      scored.push({
        module: moduleName,
        level: event.level,
        event: event.payload?.event as string ?? "unknown",
        points,
        payload: event.payload,
      });
    }

    // Track per-module breakdown
    let breakdown = moduleMap.get(moduleName);
    if (!breakdown) {
      breakdown = { module: moduleName, events: 0, errors: 0, warnings: 0, infos: 0, score: 0 };
      moduleMap.set(moduleName, breakdown);
    }
    breakdown.events++;
    if (event.level === "error") breakdown.errors++;
    else if (event.level === "warn") breakdown.warnings++;
    else breakdown.infos++;
    breakdown.score += points;
  }

  // Bonus: unique modules with errors
  for (const [, breakdown] of moduleMap) {
    if (breakdown.errors > 0) {
      rawScore += BONUS_MODULE_WITH_ERRORS;
      breakdown.score += BONUS_MODULE_WITH_ERRORS;
      bonuses.push({
        reason: `Module "${breakdown.module}" has critical findings`,
        points: BONUS_MODULE_WITH_ERRORS,
      });
    }
  }

  // Bonus: low Frida detection surface
  const fridaEvent = events.find(
    (e) => e.payload?.event === "frida_detection_summary",
  );
  if (fridaEvent) {
    const surface = fridaEvent.payload?.detection_surface_pct as number;
    if (typeof surface === "number" && surface < 50) {
      rawScore += BONUS_LOW_DETECTION_SURFACE;
      bonuses.push({
        reason: `Frida detection surface only ${surface}% — stealth is too easy`,
        points: BONUS_LOW_DETECTION_SURFACE,
      });
    }
  }

  // Bonus: unknown SDK
  const fingerprintEvent = events.find(
    (e) =>
      e.payload?.event === "rasp_unknown" ||
      e.payload?.event === "no_rasp_detected",
  );
  if (fingerprintEvent) {
    const sdk = fingerprintEvent.payload?.detected_sdk as string;
    if (sdk === "unknown" || sdk === "none") {
      rawScore += BONUS_UNKNOWN_SDK;
      bonuses.push({
        reason: "RASP SDK unidentified — unknown protection posture",
        points: BONUS_UNKNOWN_SDK,
      });
    }
  }

  const finalScore = Math.min(rawScore, MAX_SCORE);

  return {
    score: finalScore,
    modules: Array.from(moduleMap.values()).sort((a, b) => b.score - a.score),
    scored_events: scored,
    bonuses,
  };
}
