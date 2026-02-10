# Scenario 10: Edge Cases and Failure Modes

## Objective

Test Sentinellium's resilience against known edge cases: packed apps, symbol stripping, aggressive RASP, process crashes, and partial module failures.

## Test Cases

### 10.1: Packed/Obfuscated APK

**Setup:** Target an app using a packer (Bangcle, Tencent Legu, Qihoo 360).

**Expected behavior:**
- `rasp-fingerprint`: May report `no_rasp_detected` initially — signatures hidden until unpacking
- `jni-tracer`: Fewer symbols resolved from libart.so on packed apps
- `native-loader`: Should still see library loads during unpacking phase

**Test:**
```
Tool: sentinellium_audit
Params:
  mode: spawn  # Important: get in before unpacking
  duration_seconds: 45  # Give unpacker time to run
```

**Verify:** Events should start appearing after the unpacker loads the real code. Look for a burst of `library_load_attempt` events as the unpacker loads DEX and native libs.

---

### 10.2: Stripped libart.so (Android 14+)

**Setup:** Android 14+ device where ART symbols are stripped.

**Expected behavior:**
- `jni-tracer`: `no_symbols_resolved` warning — graceful fallback, no crash
- Other modules: Unaffected — they don't depend on ART symbols

**Verify:** The audit completes with a degraded jni-tracer module but full results from other modules. The risk score should still be meaningful.

---

### 10.3: Aggressive RASP Kills App on Attach

**Setup:** App with immediate Frida detection that kills the process within seconds.

**Expected behavior:**
- Modules may only partially execute before the app dies
- Oneshot modules (fingerprint, frida-detect) race against RASP termination
- Daemon modules may never complete a full heartbeat cycle

**Test:**
```
Tool: sentinellium_simulate
Params:
  mode: spawn  # Get in before RASP initializes
  policy: monitor  # Don't add our own kills
  duration_seconds: 10
```

**Verify:** Even partial results are useful — if fingerprinting succeeds before death, we know which SDK killed us.

---

### 10.4: No Frida Server (Gadget Mode)

**Setup:** App repackaged with Frida Gadget (no frida-server running on device).

**Expected behavior:**
- `frida-detect` port scan: `clean` (no server listening)
- `frida-detect` memory maps: May still find `frida-gadget` in maps
- `frida-detect` threads: May find gmain thread from Gadget's runtime
- Detection surface: Lower than server mode (expect 25-50%)

**Verify:** The detection surface percentage accurately reflects the reduced Frida footprint in Gadget mode vs. server mode.

---

### 10.5: Multiple RASP SDKs

**Setup:** App using two RASP SDKs simultaneously (rare but exists — e.g., Wultra + DexGuard obfuscation).

**Expected behavior:**
- `rasp-fingerprint`: `all_candidates` should show multiple SDKs with confidence > 0
- The top match wins, but the full candidates list reveals layered protection

**Verify:** The `all_candidates` field in the fingerprint output contains both SDKs with appropriate confidence scores.

---

### 10.6: Module Failure Isolation

**Setup:** Run audit where one module fails (e.g., integrity fails because no native libs are found).

**Expected behavior:**
- Failed module emits a warning event and stops gracefully
- Other modules continue unaffected
- Risk score is computed from successful modules only
- Audit status is still "complete" (not "error")

**Verify:** The `module_breakdown` in audit output shows the failed module with 0 errors/warnings and the other modules with full data.

---

### 10.7: Extremely Short Audit Duration

**Setup:** Run audit with `duration_seconds: 5` (minimum allowed).

**Expected behavior:**
- Oneshot modules (fingerprint, frida-detect) complete within 5s
- Daemon modules get 1-2 check cycles (integrity at 5s interval gets ~1 check)
- Risk score is valid but may be lower due to fewer events

**Verify:** Audit completes without errors. Compare score to a 30s audit — the 5s audit should capture the same oneshot findings but fewer daemon events.

## Security Note

These edge cases are particularly important for production use:
- **Packed apps** represent the majority of apps in markets like China
- **Symbol stripping** is increasingly common on newer Android versions
- **Aggressive RASP** is what we're trying to audit — our tools must handle it gracefully
- **Partial failures** must never leave the target app in a broken state
