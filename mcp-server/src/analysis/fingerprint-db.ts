/**
 * Fingerprint Database — Loads RASP SDK signatures from config/rasp-signatures.yaml.
 *
 * Provides identifySDK() for matching event payloads against known signatures.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface RaspIndicators {
  native_libs?: string[];
  java_classes?: string[];
  asset_files?: string[];
  string_patterns?: string[];
  manifest_components?: string[];
  dex_patterns?: string[];
  heuristic_native_behaviors?: string[];
}

export interface RaspSignature {
  display_name: string;
  indicators: RaspIndicators;
}

export interface SignatureDatabase {
  signatures: Record<string, RaspSignature>;
}

export interface IdentificationResult {
  sdk_id: string;
  display_name: string;
  confidence: number;
  matched_indicators: string[];
}

let cachedDb: SignatureDatabase | null = null;

/**
 * Load the signature database from disk. Results are cached.
 */
export function loadSignatureDb(
  customPath?: string,
): SignatureDatabase {
  if (cachedDb && !customPath) return cachedDb;

  const sigPath =
    customPath ??
    resolve(__dirname, "..", "..", "..", "config", "rasp-signatures.yaml");

  try {
    const raw = readFileSync(sigPath, "utf-8");
    const parsed = yaml.load(raw) as Record<string, unknown>;

    const db: SignatureDatabase = {
      signatures: (parsed?.signatures ?? parsed) as Record<string, RaspSignature>,
    };

    if (!customPath) cachedDb = db;
    return db;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to load RASP signatures from ${sigPath}: ${msg}`);
  }
}

/**
 * Identify a RASP SDK from fingerprint event data.
 *
 * Accepts the payload from a rasp-fingerprint module run and returns
 * a structured identification result.
 */
export function identifySDK(
  fingerprintPayload: Record<string, unknown>,
): IdentificationResult {
  const detectedSdk = fingerprintPayload.detected_sdk as string | undefined;
  const confidence = fingerprintPayload.confidence as number | undefined;
  const matchedIndicators =
    (fingerprintPayload.matched_indicators as string[]) ?? [];

  if (!detectedSdk || detectedSdk === "none") {
    return {
      sdk_id: "none",
      display_name: "No RASP detected",
      confidence: 0,
      matched_indicators: [],
    };
  }

  // Look up display name from our database
  let displayName = fingerprintPayload.detected_sdk_name as string | undefined;

  if (!displayName) {
    try {
      const db = loadSignatureDb();
      const sig = db.signatures[detectedSdk];
      displayName = sig?.display_name ?? detectedSdk;
    } catch {
      displayName = detectedSdk;
    }
  }

  return {
    sdk_id: detectedSdk,
    display_name: displayName,
    confidence: confidence ?? 0,
    matched_indicators: matchedIndicators,
  };
}

/**
 * Get a summary of all known SDKs in the database.
 */
export function listKnownSDKs(): { id: string; name: string }[] {
  const db = loadSignatureDb();
  return Object.entries(db.signatures)
    .filter(([id]) => id !== "unknown")
    .map(([id, sig]) => ({
      id,
      name: sig.display_name,
    }));
}
