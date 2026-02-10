# Sentinellium Agent Test Scenarios

Manual test scenarios for validating Sentinellium modules running via Kahlo.

These are not automated tests — they document step-by-step procedures for verifying each module's behavior against a live target app on a real device or emulator.

## Prerequisites

- Kahlo MCP server running (or accessible via stdio)
- Android device/emulator with Frida server
- A target app installed (any app works; a RASP-protected app is ideal)
- Sentinellium modules bootstrapped via `sentinellium_bootstrap`

## Scenarios

| # | Scenario | Modules Tested | Expected Outcome |
|---|----------|----------------|------------------|
| 01 | [Native Loader](scenarios/01-native-loader.md) | native-loader | Detects lib injection, flags suspicious paths |
| 02 | [Frida Detection](scenarios/02-frida-detect.md) | frida-detect | Maps Frida detection surface (maps, port, trampolines, threads) |
| 03 | [Full Audit](scenarios/03-full-audit.md) | All modules | End-to-end audit with risk score and report |
| 04 | [Fingerprint](scenarios/04-fingerprint.md) | rasp-fingerprint | Identifies RASP SDK with confidence score |

## Running

Each scenario describes which MCP tool to invoke and what to verify in the output. Use any MCP client (Claude Desktop, custom client, etc.) connected to Sentinellium's MCP server.
