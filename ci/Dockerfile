# Sentinellium CI — Docker image for automated RASP regression testing.
#
# Layer strategy (optimized for CI caching):
#   1. System packages (rarely changes)
#   2. Android SDK + emulator system images (changes with API level updates)
#   3. Python dependencies (changes when requirements change)
#   4. Node.js + agent build (changes when agent code changes)
#   5. Sentinellium source (changes frequently)
#
# Usage:
#   docker build -t sentinellium-ci .
#   docker run --privileged sentinellium-ci \
#     --apk /app/target.apk --config /app/config/default.yaml

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV ANDROID_HOME=/opt/android-sdk
ENV PATH="${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${ANDROID_HOME}/emulator:${PATH}"

# ============================================================
# Layer 1: System packages (changes least frequently)
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    curl wget unzip git ca-certificates \
    # Python 3.11
    python3.11 python3.11-venv python3-pip \
    # Java (for Android SDK tools)
    openjdk-17-jdk-headless \
    # Emulator dependencies
    libgl1-mesa-glx libpulse0 libnss3 libxcomposite1 \
    libxcursor1 libxdamage1 libxi6 libxtst6 \
    # Node.js (for frida-compile)
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# ============================================================
# Layer 2: Android SDK + emulator system images
# ============================================================
RUN mkdir -p ${ANDROID_HOME}/cmdline-tools && \
    cd ${ANDROID_HOME}/cmdline-tools && \
    wget -q "https://dl.google.com/android/repository/commandlinetools-linux-10406996_latest.zip" -O tools.zip && \
    unzip -q tools.zip && \
    mv cmdline-tools latest && \
    rm tools.zip

# Accept licenses and install SDK components
RUN yes | sdkmanager --licenses > /dev/null 2>&1 && \
    sdkmanager \
    "platform-tools" \
    "emulator" \
    "platforms;android-30" \
    "platforms;android-33" \
    "platforms;android-34" \
    "system-images;android-30;google_apis;x86_64" \
    "system-images;android-33;google_apis;x86_64" \
    "system-images;android-34;google_apis;x86_64" \
    "build-tools;34.0.0"

# Pre-create AVDs for each API level
RUN echo "no" | avdmanager create avd -n api30 -k "system-images;android-30;google_apis;x86_64" --force && \
    echo "no" | avdmanager create avd -n api33 -k "system-images;android-33;google_apis;x86_64" --force && \
    echo "no" | avdmanager create avd -n api34 -k "system-images;android-34;google_apis;x86_64" --force

# ============================================================
# Layer 3: Python dependencies
# ============================================================
WORKDIR /app

COPY pyproject.toml ./
RUN pip3 install --no-cache-dir -e ".[dev]" 2>/dev/null || \
    pip3 install --no-cache-dir \
    frida frida-tools click rich pydantic pyyaml pytest

# ============================================================
# Layer 4: Node.js dependencies + agent build
# ============================================================
COPY agent/package.json agent/tsconfig.json ./agent/
RUN cd agent && npm install --no-audit --no-fund

COPY agent/src/ ./agent/src/
RUN cd agent && npm run build

# ============================================================
# Layer 5: Sentinellium source (changes most frequently)
# ============================================================
COPY host/ ./host/
COPY config/ ./config/
COPY ci/ ./ci/
COPY ebpf/ ./ebpf/
COPY gadget/ ./gadget/
COPY tests/ ./tests/

# ============================================================
# Boot script: starts emulator, waits for boot, runs scan
# ============================================================
COPY ci/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
