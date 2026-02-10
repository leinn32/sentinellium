# Scenario 07: Network Probe — C2 Detection

## Objective

Verify that the `network-probe` module detects suspicious native-layer TCP connections, particularly hardcoded IP addresses on unusual ports (potential C2 indicators).

## Setup

1. Kahlo + Sentinellium MCP servers running
2. Android device with a target app that makes network connections
3. For C2 simulation: a simple TCP listener on the host machine

## Steps

### Step 1: Run audit with network probe enabled

```
Tool: sentinellium_audit
Params:
  kahlo_dist_path: <path-to-kahlo>
  device_id: <device>
  package_name: com.target.app
  duration_seconds: 30
  include_network: true
```

### Step 2: Generate test traffic

**Normal traffic (should be info-level):**
- Let the app make standard HTTPS requests (port 443)
- DNS lookups followed by connections = normal pattern

**Suspicious traffic (simulate C2):**
```bash
# On host: start a listener on unusual port
nc -l 0.0.0.0 4444

# On device: connect to it from the app's context
# (or use adb shell to test: busybox nc <host-ip> 4444)
```

### Step 3: Analyze events

| Event Type | Level | Meaning |
|------------|-------|---------|
| `connect_external` | info | Normal connection to known port (80, 443, etc.) |
| `connect_private` | info | Connection to private IP range — expected |
| `unusual_port_connect` | warn | DNS-resolved but unusual port |
| `suspicious_connect` | error | Non-private IP, unusual port, no preceding DNS — potential C2 |

### Step 4: Verify DNS heuristic

The module tracks `getaddrinfo` calls. Connections within 10s of a DNS lookup are considered DNS-resolved. Connections without preceding DNS are flagged as potential hardcoded IPs.

## Expected Results

| Traffic Pattern | Expected Level | Why |
|----------------|---------------|-----|
| HTTPS to google.com:443 | info | Standard port, DNS-resolved |
| HTTP to api.example.com:80 | info | Standard port |
| TCP to 8.8.8.8:53 | info | DNS port |
| TCP to 192.168.1.100:4444 | info | Private IP |
| TCP to 203.0.113.50:4444 (no DNS) | **error** | Hardcoded IP, unusual port, no DNS |
| TCP to 203.0.113.50:4444 (after DNS) | **warn** | Unusual port but DNS-resolved |

## Warning: Event Volume

This module hooks `connect()` in libc, which catches ALL TCP connections including:
- Android system services (GMS, push notifications)
- DNS resolution itself
- Internal IPC
- Media streaming buffers

Expect **hundreds** of events in 30s. This is why the module is disabled by default. Production use requires UID-based filtering (not yet implemented in the Kahlo version).

## Failure Modes

- **No events**: `connect()` symbol not found in libc.so (unlikely on standard Android)
- **Too many events**: Expected — use short duration and filter by level
- **False positives**: System services connecting to Google IPs on unusual ports. Review backtrace in error events.
