# Scenario 03: Full End-to-End Audit

## Objective

Run a complete RASP audit workflow: fingerprint SDK, start all detection modules, collect events, compute risk score, and generate a Markdown report.

## Setup

1. Kahlo + Sentinellium MCP servers running
2. Android device with target app (ideally RASP-protected)
3. Modules bootstrapped via `sentinellium_bootstrap`

## Steps

### Step 1: Run full audit

```
Tool: sentinellium_audit
Params:
  kahlo_dist_path: <path-to-kahlo>
  device_id: <device>
  package_name: com.target.app
  mode: attach
  duration_seconds: 30
  include_network: false
```

### Step 2: Verify audit output structure

The response should contain:

- `status`: "complete"
- `rasp_sdk`: identification result with sdk_id, display_name, confidence
- `risk_score`: 0-100 integer
- `module_breakdown`: per-module event counts and scores
- `bonuses`: any score adjustments applied
- `total_events`: total events collected

### Step 3: Generate Markdown report

```
Tool: sentinellium_report
Params:
  audit_result: <paste the JSON from step 2>
  format: markdown
```

### Step 4: Verify report content

The Markdown report should include:
- Target info header
- Risk score with HIGH/MEDIUM/LOW level
- RASP SDK identification
- Module breakdown table
- Score bonuses section

## Expected Results

### Unprotected App

- RASP SDK: "none" / "No RASP detected"
- Risk score: moderate (Frida detection events still generate findings)
- Module breakdown: frida-detect and integrity modules produce most events

### RASP-Protected App (e.g., Wultra)

- RASP SDK: "wultra" with confidence 70+
- Risk score: higher due to RASP-related JNI calls and integrity checks
- Module breakdown: jni-tracer flags RASP method calls, rasp-fingerprint identifies SDK

## Failure Modes

- **Audit times out**: Increase `duration_seconds` or check Kahlo connectivity
- **No events**: Target may have crashed — check if Frida detach happened
- **Score is 0**: No warning/error events generated — modules may have failed silently
