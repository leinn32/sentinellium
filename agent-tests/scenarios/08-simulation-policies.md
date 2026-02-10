# Scenario 08: RASP Simulation — Policy Comparison

## Objective

Compare strict vs. monitor simulation policies to validate RASP response behavior. Test that strict mode correctly detaches the target on critical findings.

## Setup

1. Kahlo + Sentinellium MCP servers running
2. Android device with Frida server on default port (27042)
3. Target app that will survive at least a few seconds of instrumentation

## Steps

### Step 1: Run monitor mode first (safe baseline)

```
Tool: sentinellium_simulate
Params:
  kahlo_dist_path: <path-to-kahlo>
  device_id: <device>
  package_name: com.target.app
  policy: monitor
  duration_seconds: 15
```

Expected: All events logged, no kills, target stays alive for full duration.

### Step 2: Review monitor timeline

```json
{
  "status": "completed",
  "timeline": [
    {"level": "error", "event": "frida_server_listening", "action": "LOG — critical finding recorded"},
    {"level": "warn", "event": "frida_artifact_in_maps", "action": "LOG — warning recorded"},
    ...
  ],
  "summary": {
    "kills": 0,
    "criticals": 1,
    "warnings": 4
  }
}
```

### Step 3: Run strict mode

```
Tool: sentinellium_simulate
Params:
  kahlo_dist_path: <path-to-kahlo>
  device_id: <device>
  package_name: com.target.app
  policy: strict
  duration_seconds: 15
```

Expected: Target detached on first critical finding. Duration will be shorter than 15s.

### Step 4: Compare results

| Metric | Monitor | Strict |
|--------|---------|--------|
| Status | `completed` | `killed` |
| Duration | 15s (full) | <15s (early termination) |
| Kills | 0 | 1+ |
| Total events | Many | Few (stopped early) |

## What Triggers a Kill in Strict Mode

| Event | Level | Kill? |
|-------|-------|-------|
| `frida_server_listening` | error | Yes |
| `suspicious_library_load` | error | Yes |
| `integrity_violation` | error | Yes |
| `suspicious_connect` | error | Yes |
| `frida_artifact_in_maps` | warn | No (warn → log in strict) |
| `hook_detected` | warn | No |

## Security Implications

This simulation reveals:
1. **Time to detection**: How quickly would a real RASP kill the app after Frida injection?
2. **Detection ordering**: Which check fires first? (Usually port scan or memory maps)
3. **Survival window**: In monitor mode, how many events occur before the first critical? This is the attacker's stealth window.

## Failure Modes

- **No critical events**: If using stealth Frida (non-default port, no server mode), frida-detect may not produce errors. This is a valid finding — stealth is working.
- **Kill too fast**: If the port scan fires immediately, you may get only 1 event. Increase poll interval or use monitor mode first.
- **Target already dead**: RASP may have killed the app before Frida attaches. Use `mode: spawn` to get in first.
