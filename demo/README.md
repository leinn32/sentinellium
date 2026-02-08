# Sentinellium Demo

Step-by-step instructions for running Sentinellium against a test target.

## Prerequisites

1. **Host machine setup:**
   ```bash
   # Install Python package
   pip install -e .

   # Build the Frida agent
   cd agent && npm install && npm run build && cd ..
   ```

2. **Android device/emulator:**
   - Android 7.0+ (API 24+) device or emulator
   - Root access (or use `frida-gadget` for non-rooted targets)
   - `frida-server` running on the device:
     ```bash
     # Download frida-server for your architecture
     # https://github.com/frida/frida/releases

     adb push frida-server /data/local/tmp/
     adb shell "chmod 755 /data/local/tmp/frida-server"
     adb shell "/data/local/tmp/frida-server &"
     ```

3. **Test target app:**
   Install one of these open-source vulnerable apps:
   - **DIVA (Damn Insecure and Vulnerable App):** https://github.com/payatu/diva-android
   - **InsecureBankv2:** https://github.com/dineshshetty/Android-InsecureBankv2

   ```bash
   adb install diva-beta.apk
   # or
   adb install InsecureBankv2.apk
   ```

## Running the Demo

### Quick Scan (30 seconds)

```bash
# Launch the target app on the device first, then:
make scan PKG=jakhar.aseem.diva

# Or with InsecureBankv2:
make scan PKG=com.android.insecurebankv2
```

This will:
1. Attach to the running app
2. Collect telemetry for 30 seconds
3. Compute a risk score
4. Save a JSON report to `report.json`
5. Print a summary to the terminal

### Interactive Monitoring

```bash
make attach PKG=jakhar.aseem.diva
```

This opens a live-updating table showing events as they arrive. Interact with the target app to trigger different code paths. Press `Ctrl+C` to detach.

### RASP Simulation

```bash
make simulate PKG=jakhar.aseem.diva
```

This simulates a RASP SDK's response to detected threats. When a critical event is detected (e.g., Frida artifacts found in memory), the session is terminated — just as a real RASP SDK would kill the app.

### Spawn Mode

To instrument the app from startup (catches early initialization hooks):

```bash
make attach-spawn PKG=jakhar.aseem.diva
```

## Expected Output

See `expected-output.txt` for what the Rich table should look like during a typical scan.

### What You Should See

1. **NativeLoaderMonitor** events as the app loads its native libraries
2. **FridaDetectionAuditor** findings showing where Frida is visible:
   - Memory maps containing `frida-agent`
   - Frida server port open on 27042
   - GLib threads (`gmain`, `gdbus`, `gum-js-loop`)
3. **JNITransitionTracer** events showing Java↔Native calls
4. **IntegrityBaseline** periodic integrity checks (every 5s by default)

### Risk Score Interpretation

| Score | Meaning |
|-------|---------|
| 0-20  | Low risk — Frida is well-hidden, RASP coverage is strong |
| 21-50 | Moderate — Some detection gaps exist |
| 51-80 | High — Multiple detection vectors are exposed |
| 81-100 | Critical — RASP implementation has significant gaps |

## Troubleshooting

- **"Agent bundle not found":** Run `cd agent && npm run build`
- **"Failed to enumerate devices":** Ensure `frida-server` is running on the device
- **"Process not found":** The target app must be running before `attach` (or use `--spawn`)
- **No events appearing:** Check that modules are enabled in `config/default.yaml`
