.PHONY: build-agent test test-agent test-host attach scan simulate devices demo clean \
       fingerprint diff gadget-patch ci-build ci-run

# Default target package for make attach/scan/simulate
PKG ?= com.target.package

# Build the Frida agent bundle from TypeScript sources
build-agent:
	cd agent && npm run build

# Run all tests (agent + host)
test: test-agent test-host

# Run TypeScript agent tests via vitest
test-agent:
	cd agent && npx vitest run

# Run Python host tests via pytest
test-host:
	python -m pytest tests/host/ -v

# Attach to a running app with live telemetry display
attach: build-agent
	python -m host.cli attach $(PKG)

# Attach with spawn mode
attach-spawn: build-agent
	python -m host.cli attach $(PKG) --spawn

# Attach with eBPF kernel probes (requires root)
attach-ebpf: build-agent
	sudo python -m host.cli attach $(PKG) --ebpf

# Run a timed scan and generate a JSON report
scan: build-agent
	python -m host.cli scan $(PKG) --duration 30 --output report.json

# Run RASP simulation mode with default policy
simulate: build-agent
	python -m host.cli simulate $(PKG) --config config/default.yaml

# Run RASP simulation with strict policy
simulate-strict: build-agent
	python -m host.cli simulate $(PKG) --config config/strict.yaml

# Fingerprint the RASP SDK protecting the target app
fingerprint: build-agent
	python -m host.cli fingerprint $(PKG)

# Differential analysis across multiple devices
# Usage: make diff PKG=com.target.package DEVICES=emulator-5554,emulator-5556
DEVICES ?= emulator-5554,emulator-5556
diff: build-agent
	python -m host.cli diff $(PKG) --devices $(DEVICES) --duration 30

# APK patching with Frida Gadget
# Usage: make gadget-patch APK=target.apk GADGET_LIB=frida-gadget.so
APK ?= target.apk
GADGET_LIB ?= frida-gadget.so
gadget-patch:
	python -m host.cli gadget patch $(APK) --gadget-lib $(GADGET_LIB)

# List available Frida devices
devices:
	python -m host.cli devices

# Build CI Docker image
ci-build:
	docker build -t sentinellium-ci -f ci/Dockerfile .

# Run CI scan (inside Docker or locally)
ci-run:
	python -m ci.runner --package $(PKG) --config config/default.yaml \
		--thresholds ci/thresholds.yaml --output report.json --junit results.xml

# Demo instructions
demo:
	@echo "============================================"
	@echo "  Sentinellium Demo"
	@echo "============================================"
	@echo ""
	@echo "Prerequisites:"
	@echo "  1. pip install -e ."
	@echo "  2. cd agent && npm install && npm run build"
	@echo "  3. Android device/emulator with frida-server running"
	@echo "  4. Target app installed (e.g., DIVA or InsecureBankv2)"
	@echo ""
	@echo "Commands:"
	@echo "  make scan PKG=com.target.package"
	@echo "  make attach PKG=com.target.package"
	@echo "  make fingerprint PKG=com.target.package"
	@echo "  make simulate PKG=com.target.package"
	@echo "  make diff PKG=com.target.package DEVICES=emu1,emu2"

# Install Python package in development mode
install:
	pip install -e ".[dev]"
	cd agent && npm install

# Clean build artifacts
clean:
	rm -f agent/_agent.js
	rm -f report.json results.xml
	rm -rf agent/dist
	rm -rf agent/node_modules
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
