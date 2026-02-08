#!/bin/bash
# Sentinellium CI entrypoint — starts emulator, waits for boot, runs scan.
#
# Arguments are passed through to ci/runner.py.
# Environment variables:
#   ANDROID_API_LEVEL: API level to test (default: 30)
#   EMULATOR_NAME: AVD name (default: api30)

set -euo pipefail

API_LEVEL="${ANDROID_API_LEVEL:-30}"
AVD_NAME="${EMULATOR_NAME:-api${API_LEVEL}}"
BOOT_TIMEOUT=300  # 5 minutes

echo "=== Sentinellium CI ==="
echo "API Level: ${API_LEVEL}"
echo "AVD: ${AVD_NAME}"

# Start the emulator in headless mode
echo "Starting emulator (headless)..."
emulator -avd "${AVD_NAME}" \
    -no-window \
    -no-audio \
    -no-snapshot \
    -gpu swiftshader_indirect \
    -no-boot-anim \
    -wipe-data \
    &

EMULATOR_PID=$!

# Wait for the emulator to boot
echo "Waiting for emulator boot..."
SECONDS_WAITED=0

while [ ${SECONDS_WAITED} -lt ${BOOT_TIMEOUT} ]; do
    BOOT_COMPLETE=$(adb shell getprop sys.boot_completed 2>/dev/null || echo "")

    if [ "${BOOT_COMPLETE}" = "1" ]; then
        echo "Emulator booted successfully (${SECONDS_WAITED}s)"
        break
    fi

    sleep 5
    SECONDS_WAITED=$((SECONDS_WAITED + 5))
done

if [ ${SECONDS_WAITED} -ge ${BOOT_TIMEOUT} ]; then
    echo "ERROR: Emulator failed to boot within ${BOOT_TIMEOUT}s"
    kill ${EMULATOR_PID} 2>/dev/null || true
    exit 1
fi

# Additional settle time for system services
sleep 10

# Push frida-server to the device
ARCH=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
echo "Device architecture: ${ARCH}"

if [ -f "/app/tools/frida-server-${ARCH}" ]; then
    adb push "/app/tools/frida-server-${ARCH}" /data/local/tmp/frida-server
    adb shell chmod 755 /data/local/tmp/frida-server
    adb shell /data/local/tmp/frida-server &
    sleep 3
else
    echo "WARNING: frida-server binary not found for ${ARCH}"
    echo "Attempting to continue without frida-server..."
fi

# Run the sentinellium CI runner
echo "Running RASP audit..."
python3 -m ci.runner "$@"
EXIT_CODE=$?

# Cleanup
echo "Cleaning up..."
kill ${EMULATOR_PID} 2>/dev/null || true

exit ${EXIT_CODE}
