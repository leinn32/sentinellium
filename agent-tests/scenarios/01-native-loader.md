# Scenario 01: Native Loader Detection

## Objective

Verify that the `native-loader` module detects library injection via `android_dlopen_ext`.

## Setup

1. Start Kahlo MCP server
2. Connect Sentinellium MCP server
3. Bootstrap modules: call `sentinellium_bootstrap`
4. Target: any Android app on a device with frida-server running

## Steps

### Step 1: Start the module via audit

```
Tool: sentinellium_audit
Params:
  kahlo_dist_path: <path-to-kahlo>
  device_id: <device>
  package_name: com.target.app
  duration_seconds: 15
```

### Step 2: Trigger library loads

While the audit is running, use adb to push a test .so to the device:

```bash
adb push /tmp/test-lib.so /data/local/tmp/test-lib.so
```

Or simply let the app run — normal app startup loads multiple libraries.

### Step 3: Review events

Look for events in the audit output:

- `library_load_attempt` — every `android_dlopen_ext` call
- `library_load_result` — success/failure of each load
- `suspicious_library_load` — any load matching suspicious paths/patterns

## Expected Results

- **Symbol resolved**: `symbol_resolved` event showing which linker module was hooked
- **Normal loads**: Multiple `library_load_attempt` events for system/app libraries
- **Frida detection**: If Frida is injected via server mode, `suspicious_library_load` with `pattern:frida` match
- **Heartbeat**: Periodic `native_loader_stats` showing load counts

## Failure Modes

- **No symbol resolved**: Device may be pre-Android 7 (no `android_dlopen_ext`)
- **No events**: Module may have failed to attach — check for error events
- **False positives**: Adjust `suspicious_patterns` in ctx.params if legitimate libs match
