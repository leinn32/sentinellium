// Frida Detection Auditor — Scores Frida visibility from the defender's perspective.
// Runs the same checks RASP SDKs use: /proc/self/maps, port scan, trampolines, threads.
// RASP relevance: produces a detection surface map showing which stealth techniques work.

const fridaPort = ctx.params.frida_port || 27042;

const ARM64_TRAMPOLINE = [0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6];
const ARM32_TRAMPOLINE = [0x00, 0x00, 0x9f, 0xe5];

const results = {
  maps: { detected: false, artifacts: [] },
  port: { detected: false },
  trampolines: { detected: false, count: 0, total_scanned: 0 },
  threads: { detected: false, suspicious: [] },
};

// Check 1: Memory maps scan
try {
  const file = new File("/proc/self/maps", "r");
  const content = file.readAllText();
  file.close();

  const markers = ["frida-agent", "frida-gadget", "gmain"];
  const lines = content.split("\n");

  for (const line of lines) {
    for (const marker of markers) {
      if (line.toLowerCase().includes(marker)) {
        results.maps.detected = true;
        results.maps.artifacts.push({ marker: marker, entry: line.trim() });
        ctx.emit("warn", {
          check: "memory_maps",
          finding: "frida_artifact_in_maps",
          marker: marker,
          map_entry: line.trim(),
        });
      }
    }
  }

  if (!results.maps.detected) {
    ctx.emit("info", {
      check: "memory_maps",
      finding: "clean",
      detail: "No Frida artifacts found in /proc/self/maps",
    });
  }
} catch (e) {
  ctx.emit("warn", {
    check: "memory_maps",
    finding: "check_failed",
    error: e.message || String(e),
  });
}

// Check 2: Frida port scan
try {
  var AF_INET = 2;
  var SOCK_STREAM = 1;
  var IPPROTO_TCP = 6;

  var socketFn = new NativeFunction(
    Module.findExportByName("libc.so", "socket"),
    "int", ["int", "int", "int"]
  );
  var connectFn = new NativeFunction(
    Module.findExportByName("libc.so", "connect"),
    "int", ["int", "pointer", "int"]
  );
  var closeFn = new NativeFunction(
    Module.findExportByName("libc.so", "close"),
    "int", ["int"]
  );

  var fd = socketFn(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd >= 0) {
    var sockaddr = Memory.alloc(16);
    sockaddr.writeU16(AF_INET);
    sockaddr.add(2).writeU16(((fridaPort >> 8) & 0xff) | ((fridaPort & 0xff) << 8));
    sockaddr.add(4).writeU32(0x0100007f); // 127.0.0.1

    var result = connectFn(fd, sockaddr, 16);
    closeFn(fd);

    if (result === 0) {
      results.port.detected = true;
      ctx.emit("error", {
        check: "port_scan",
        finding: "frida_server_listening",
        port: fridaPort,
        detail: "Frida server detected on 127.0.0.1:" + fridaPort,
      });
    } else {
      ctx.emit("info", {
        check: "port_scan",
        finding: "clean",
        port: fridaPort,
      });
    }
  }
} catch (e) {
  ctx.emit("warn", {
    check: "port_scan",
    finding: "check_failed",
    error: e.message || String(e),
  });
}

// Check 3: Trampoline scan
try {
  var arch = Process.arch;
  var pattern = arch === "arm64" ? ARM64_TRAMPOLINE : ARM32_TRAMPOLINE;

  var modules = Process.enumerateModules();
  for (var mi = 0; mi < modules.length; mi++) {
    var mod = modules[mi];
    if (mod.path.startsWith("/system/") && !mod.name.includes("libart")) {
      continue;
    }

    try {
      var exports = mod.enumerateExports();
      for (var ei = 0; ei < exports.length; ei++) {
        var exp = exports[ei];
        if (exp.type !== "function") continue;
        results.trampolines.total_scanned++;

        try {
          var bytes = exp.address.readByteArray(pattern.length);
          if (bytes === null) continue;

          var view = new Uint8Array(bytes);
          var match = true;
          for (var pi = 0; pi < pattern.length; pi++) {
            if (view[pi] !== pattern[pi]) { match = false; break; }
          }

          if (match) {
            results.trampolines.detected = true;
            results.trampolines.count++;
            ctx.emit("warn", {
              check: "trampoline_scan",
              finding: "hook_detected",
              library: mod.name,
              function_name: exp.name,
              address: exp.address.toString(),
              arch: arch,
            });
          }
        } catch (_) { /* unreadable memory */ }
      }
    } catch (_) { /* can't enumerate exports */ }
  }

  ctx.emit("info", {
    check: "trampoline_scan",
    finding: "scan_complete",
    total_exports_scanned: results.trampolines.total_scanned,
    trampolines_found: results.trampolines.count,
    arch: arch,
  });
} catch (e) {
  ctx.emit("warn", {
    check: "trampoline_scan",
    finding: "check_failed",
    error: e.message || String(e),
  });
}

// Check 4: Named thread scan
try {
  var suspiciousNames = ["gmain", "gdbus", "gum-js-loop"];
  var threads = Process.enumerateThreads();

  for (var ti = 0; ti < threads.length; ti++) {
    try {
      var commPath = "/proc/self/task/" + threads[ti].id + "/comm";
      var f = new File(commPath, "r");
      var name = f.readAllText().trim();
      f.close();

      for (var si = 0; si < suspiciousNames.length; si++) {
        if (name === suspiciousNames[si]) {
          results.threads.detected = true;
          results.threads.suspicious.push({
            thread_id: threads[ti].id,
            thread_name: name,
          });
          ctx.emit("warn", {
            check: "thread_scan",
            finding: "suspicious_thread",
            thread_id: threads[ti].id,
            thread_name: name,
          });
        }
      }
    } catch (_) { /* can't read comm */ }
  }

  if (!results.threads.detected) {
    ctx.emit("info", {
      check: "thread_scan",
      finding: "clean",
      threads_scanned: threads.length,
    });
  }
} catch (e) {
  ctx.emit("warn", {
    check: "thread_scan",
    finding: "check_failed",
    error: e.message || String(e),
  });
}

// Final summary
var checksDetected = 0;
var totalChecks = 4;
if (results.maps.detected) checksDetected++;
if (results.port.detected) checksDetected++;
if (results.trampolines.detected) checksDetected++;
if (results.threads.detected) checksDetected++;

var detectionSurface = Math.round((checksDetected / totalChecks) * 100);

ctx.emit("info", {
  event: "frida_detection_summary",
  detection_surface_pct: detectionSurface,
  checks_detected: checksDetected,
  total_checks: totalChecks,
  maps_detected: results.maps.detected,
  port_detected: results.port.detected,
  trampolines_detected: results.trampolines.detected,
  threads_detected: results.threads.detected,
  trampoline_count: results.trampolines.count,
  detail: "Frida is detectable by " + checksDetected + "/" + totalChecks +
          " standard RASP checks (" + detectionSurface + "% surface)",
});
