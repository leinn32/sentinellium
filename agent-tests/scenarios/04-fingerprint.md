# Scenario 04: RASP SDK Fingerprinting

## Objective

Verify that the `rasp-fingerprint` module correctly identifies known RASP SDKs and returns appropriate confidence scores.

## Setup

1. Kahlo + Sentinellium MCP servers running
2. Android device with a RASP-protected app installed

## Steps

### Step 1: Quick fingerprint

```
Tool: sentinellium_fingerprint
Params:
  kahlo_dist_path: <path-to-kahlo>
  device_id: <device>
  package_name: com.target.app
  mode: attach
```

### Step 2: Verify identification result

Response should contain:

```json
{
  "identification": {
    "sdk_id": "wultra",
    "display_name": "Wultra In-App Protection",
    "confidence": 85,
    "matched_indicators": [
      "native_lib:libwultraappprotection.so",
      "java_class:Lio/wultra/app/protection/...",
      "string:WultraAppProtection"
    ]
  },
  "all_candidates": {
    "wultra": 85,
    "promon": 15
  }
}
```

## Test Matrix

| Target App | Expected SDK | Min Confidence |
|------------|-------------|----------------|
| App with Wultra SDK | wultra | 60 |
| App with Promon SHIELD | promon | 60 |
| App with DexGuard | guardsquare | 60 |
| App with freeRASP | talsec | 60 |
| Unprotected app | none | 0 |
| Custom RASP app | unknown | >0 (behavioral) |

## Confidence Scoring

| Indicator Type | Points | How Verified |
|---------------|--------|--------------|
| Native lib match | +40 | Process.enumerateModules() |
| Java class match | +30 | Java.enumerateLoadedClasses() |
| String pattern match | +15 | /proc/self/maps content |
| Behavioral indicator | +15 | Thread names, exports, TracerPid |

Positive identification threshold: 60 points.

## Failure Modes

- **Java classes not found**: VM may not be available — module falls back to native+string
- **False positive**: Multiple SDKs match — highest confidence wins
- **Packed app**: Signatures may be hidden until unpacking — try spawn mode
- **confidence: 0 on protected app**: SDK may use heavy obfuscation — check behavioral indicators
