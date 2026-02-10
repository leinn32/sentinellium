# Scenario 06: JNI Transition Tracing

## Objective

Verify that the `jni-tracer` module correctly traces Java-to-native boundary calls through ART's JNI layer, and identifies RASP-related method invocations.

## Setup

1. Kahlo + Sentinellium MCP servers running
2. Android device with a RASP-protected app (Wultra, Promon, etc.)
3. Frida server running — the app must be alive long enough for JNI tracing

## Steps

### Step 1: Run audit with JNI tracing

```
Tool: sentinellium_audit
Params:
  kahlo_dist_path: <path-to-kahlo>
  device_id: <device>
  package_name: com.rasp.protected.app
  duration_seconds: 30
```

### Step 2: Verify symbol resolution

Check for `symbols_resolved` event:
- `count`: number of ART JNI symbols hooked (expect 5-50 depending on ART version)
- `symbols`: list of mangled C++ names like `_ZN3art3JNI13CallVoidMethodV...`

### Step 3: Identify RASP calls

Filter events for `rasp_jni_call` (level: "warn"):
- These indicate JNI calls matching RASP-related patterns (checkroot, verifysignature, etc.)
- `class_name` and `method` fields reveal what the RASP is calling
- `caller_module` shows which native library initiated the call

### Step 4: Review call surface map

The `jni_tracer_stats` heartbeat shows:
- `total_traces`: all JNI calls intercepted
- `rasp_related_calls`: calls matching RASP patterns

## Expected Results

### Unprotected App
- Symbols resolve successfully
- Only `jni_call` (info) events for normal app JNI usage
- Zero `rasp_jni_call` (warning) events

### RASP-Protected App
- `rasp_jni_call` events for methods matching patterns like:
  - `checkRoot`, `isRooted`
  - `verifySignature`, `checkSignature`
  - `isDebugger`, `debuggerCheck`
  - `checkIntegrity`, `antiTamper`
- `caller_module` often points to the RASP SDK's native library

## Throttle Behavior

The tracer uses a 100ms dedup window per method. Rapidly-called methods (like periodic integrity checks) will only appear once per 100ms interval. This is intentional to prevent event flooding.

## Failure Modes

- **No symbols resolved**: ART version may strip JNI symbols (Android 14+ with restricted symbol visibility). Check for `no_symbols_resolved` warning.
- **High noise**: Non-RASP JNI calls dominate. Increase `throttle_ms` to reduce volume.
- **App crashes**: Hooking ART internals is inherently risky. Some ART versions don't tolerate it. If the app crashes, try a different target.
