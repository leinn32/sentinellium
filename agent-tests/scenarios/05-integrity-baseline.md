# Scenario 05: Integrity Baseline Verification

## Objective

Verify that the `integrity` module detects runtime code patching by establishing SHA-256 baselines and detecting modifications.

## Setup

1. Kahlo + Sentinellium MCP servers running
2. Android device with target app
3. Frida server active (this guarantees at least some hooks exist for detection)

## Steps

### Step 1: Run audit with integrity monitoring

```
Tool: sentinellium_audit
Params:
  kahlo_dist_path: <path-to-kahlo>
  device_id: <device>
  package_name: com.target.app
  duration_seconds: 20
```

### Step 2: Verify baseline establishment

Look for these events in sequence:

1. `baseline_established` — lists monitored libraries and section count
2. `integrity_check_passed` — periodic checks confirming no modification (every 5s default)
3. `integrity_stats` — heartbeat with check count and violation count

### Step 3: Trigger a violation (advanced)

While the module is running, use a separate Frida session to patch memory:

```javascript
// From a second Frida session:
var libart = Module.findBaseAddress("libart.so");
var textRange = libart.enumerateRanges("r-x")[0];
Memory.patchCode(textRange.base, 4, function(code) {
  code.writeU32(0x90909090); // NOP sled
});
```

Expected: `integrity_violation` event with:
- `library`: "libart.so"
- `expected_hash` vs `actual_hash` mismatch
- Level: "error"

## Expected Results

| Scenario | Expected Events |
|----------|----------------|
| Clean run (Frida server) | `baseline_established` → repeated `integrity_check_passed` |
| Frida with Interceptor hooks | `integrity_violation` on hooked library within 5s |
| Memory patching | `integrity_violation` within one check interval |

## Security Considerations

- The integrity module itself runs via Frida, which modifies memory. This creates a known false positive: Frida's own trampolines in hooked functions will be detected as violations.
- This is actually useful — it demonstrates the integrity checker works. A RASP SDK's own integrity checks face the same bootstrapping problem.

## Failure Modes

- **No baseline sections**: Watched libs not loaded — check if target app uses native code
- **All checks pass despite hooks**: Check interval may be too long, or hooks are in non-monitored modules
- **Hash computation errors**: Large `.text` sections may timeout on slow devices
