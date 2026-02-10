# Scenario 09: Multi-Module Event Correlation

## Objective

Verify that running all modules together produces correlated findings that paint a complete picture of the RASP audit — not just isolated events from each module.

## Setup

1. Kahlo + Sentinellium MCP servers running
2. Android device with a RASP-protected app
3. Frida server active on default port

## Steps

### Step 1: Run full audit with all modules

```
Tool: sentinellium_audit
Params:
  kahlo_dist_path: <path-to-kahlo>
  device_id: <device>
  package_name: com.rasp.protected.app
  duration_seconds: 30
  include_network: false
```

### Step 2: Cross-reference findings

Build a correlation matrix from the audit output:

| Finding | native-loader | frida-detect | jni-tracer | integrity | rasp-fingerprint |
|---------|--------------|--------------|------------|-----------|-----------------|
| Frida injection visible | | Maps + port + trampolines | | .text hash changed | |
| RASP SDK identified | | | RASP JNI calls detected | | SDK: wultra (85%) |
| Native hooks active | Suspicious lib loads | Hook trampolines found | | Integrity violations | |
| RASP checking actively | | | checkRoot, verifySignature calls | Periodic re-hash running | RASP threads detected |

### Step 3: Verify scoring reflects correlation

The risk score should account for:
- Events from multiple modules confirm each other (+10 per module with errors)
- Low Frida detection surface + unknown SDK = extra bonuses
- The score reflects the aggregate, not just individual module counts

### Step 4: Generate and review report

```
Tool: sentinellium_report
Params:
  audit_result: <paste audit JSON>
  format: markdown
```

## Correlation Patterns to Verify

### Pattern 1: Frida Visibility Consistency
If `frida-detect` reports trampolines in libart.so, then `integrity` should report hash changes in libart.so's `.text` section. If integrity doesn't catch it, there's a gap.

### Pattern 2: RASP Activity Confirmation
If `rasp-fingerprint` identifies a known SDK, then `jni-tracer` should show RASP-related JNI calls. If fingerprinting finds the SDK but no RASP JNI calls appear, the SDK may use a non-JNI mechanism.

### Pattern 3: Library Load → Hook → Violation Chain
Timeline: `native-loader` sees Frida agent load → `frida-detect` finds trampolines → `integrity` detects hash changes. The events should be temporally ordered.

### Pattern 4: Detection Surface vs. Integrity
If `frida-detect` reports 100% detection surface (all 4 checks positive), the RASP should also be detecting Frida. Cross-check with `jni-tracer` — are anti-Frida methods being called?

## Expected Module Interaction

```
rasp-fingerprint (oneshot) → identifies SDK → informs analysis
frida-detect (oneshot) → maps detection surface → feeds scoring bonuses
native-loader (daemon) → catches injection events → ongoing monitoring
jni-tracer (daemon) → maps RASP call surface → ongoing monitoring
integrity (daemon) → detects code modifications → ongoing monitoring
```

All feed into the scoring engine, which produces the aggregate risk score.
