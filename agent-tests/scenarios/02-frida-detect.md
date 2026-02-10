# Scenario 02: Frida Detection Surface Mapping

## Objective

Verify that the `frida-detect` module correctly maps Frida's detection surface from the defender's perspective.

## Setup

1. Kahlo + Sentinellium MCP servers running
2. Android device with frida-server active on default port (27042)
3. Target app attached via Frida (so Frida artifacts are present)

## Steps

### Step 1: Run fingerprint + frida-detect

```
Tool: sentinellium_audit
Params:
  kahlo_dist_path: <path-to-kahlo>
  device_id: <device>
  package_name: com.target.app
  duration_seconds: 10
```

### Step 2: Analyze detection summary

Find the `frida_detection_summary` event in the output. It contains:

```json
{
  "detection_surface_pct": 75,
  "checks_detected": 3,
  "total_checks": 4,
  "maps_detected": true,
  "port_detected": true,
  "trampolines_detected": true,
  "threads_detected": false
}
```

## Expected Results (Standard Frida Server)

| Check | Expected | Why |
|-------|----------|-----|
| Memory maps | **Detected** | frida-agent.so visible in /proc/self/maps |
| Port scan | **Detected** | frida-server listening on 27042 |
| Trampolines | **Detected** | Interceptor hooks leave arm64 trampoline patterns |
| Named threads | **Detected** | gmain, gdbus threads from GLib |

Detection surface should be 75-100% with standard Frida server.

## Stealth Configuration Test

To test with stealth Frida:

1. Use `frida-server --listen 0.0.0.0:12345` (non-default port)
2. Set `frida_port: 12345` in module params
3. Use `frida --runtime=v8` to avoid GLib threads

Expected: Detection surface drops — document which checks still trigger.

## Failure Modes

- **Port check fails**: Module falls back to native socket API — check for `port_scan_native` events
- **Trampoline scan timeout**: Too many modules loaded — reduce scope in target app
- **0% detection**: Frida may not actually be injected — verify with `frida-ps -U`
