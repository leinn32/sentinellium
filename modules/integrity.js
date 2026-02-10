// Integrity Baseline — Detects runtime code patching via .text section SHA-256 hashing.
// Snapshots executable memory on attach, periodically re-checks for modifications.
// RASP relevance: validates RASP integrity checking effectiveness and exposes race windows.

var CHUNK_SIZE = 65536; // 64KB
var intervalSeconds = ctx.params.interval_seconds || 5;
var heartbeatInterval = (ctx.params.heartbeat_seconds || 10) * 1000;

var watchedLibs = ctx.params.watched_libs || ["libart.so"];

var baselines = {};
var violationCount = 0;
var checkCount = 0;

function sha256(data) {
  var checksum = new Checksum("sha256");
  checksum.update(data);
  return checksum.getString();
}

function hashMemoryRegion(base, size) {
  try {
    if (size <= CHUNK_SIZE) {
      var bytes = base.readByteArray(size);
      if (bytes === null) return null;
      return sha256(bytes);
    }

    // Large region: hash in chunks then combine
    var chunkHashes = [];
    var offset = 0;
    while (offset < size) {
      var chunkLen = Math.min(CHUNK_SIZE, size - offset);
      var bytes = base.add(offset).readByteArray(chunkLen);
      if (bytes === null) return null;
      chunkHashes.push(sha256(bytes));
      offset += chunkLen;
    }

    // Hash the concatenated chunk hashes
    var combined = chunkHashes.join("");
    var buf = new ArrayBuffer(combined.length);
    var view = new Uint8Array(buf);
    for (var i = 0; i < combined.length; i++) {
      view[i] = combined.charCodeAt(i) & 0xff;
    }
    return sha256(buf);
  } catch (_) {
    return null;
  }
}

// Build baseline: collect all watched libs + app-specific libs
var targetLibs = {};
for (var i = 0; i < watchedLibs.length; i++) {
  targetLibs[watchedLibs[i].toLowerCase()] = true;
}

try {
  var modules = Process.enumerateModules();

  // Auto-discover app libs
  for (var mi = 0; mi < modules.length; mi++) {
    var mod = modules[mi];
    if (mod.path.includes("/data/app/") || mod.path.includes("/data/data/")) {
      targetLibs[mod.name.toLowerCase()] = true;
    }
  }

  // Hash executable sections of target libs
  for (var mi = 0; mi < modules.length; mi++) {
    var mod = modules[mi];
    if (!targetLibs[mod.name.toLowerCase()]) continue;

    try {
      var ranges = mod.enumerateRanges("r-x");
      for (var ri = 0; ri < ranges.length; ri++) {
        var range = ranges[ri];
        var key = mod.name + "+" + range.base;
        var hash = hashMemoryRegion(range.base, range.size);

        if (hash !== null) {
          baselines[key] = {
            moduleName: mod.name,
            baseAddress: range.base.toString(),
            size: range.size,
            hash: hash,
          };
        }
      }
    } catch (e) {
      ctx.emit("warn", {
        event: "baseline_failed",
        library: mod.name,
        error: e.message || String(e),
      });
    }
  }
} catch (e) {
  ctx.emit("warn", {
    event: "baseline_build_failed",
    error: e.message || String(e),
  });
}

var baselineCount = Object.keys(baselines).length;

if (baselineCount === 0) {
  ctx.emit("warn", {
    event: "no_baseline",
    detail: "No executable sections found for watched libraries",
    watched_libs: watchedLibs,
  });
} else {
  var libNames = {};
  for (var key in baselines) {
    libNames[baselines[key].moduleName] = true;
  }

  ctx.emit("info", {
    event: "baseline_established",
    sections: baselineCount,
    libraries: Object.keys(libNames),
  });

  // Periodic integrity check
  var checkInterval = setInterval(function () {
    checkCount++;
    var currentViolations = 0;

    for (var key in baselines) {
      var bl = baselines[key];
      try {
        var base = ptr(bl.baseAddress);
        var currentHash = hashMemoryRegion(base, bl.size);

        if (currentHash === null) {
          ctx.emit("warn", {
            event: "hash_failed",
            library: bl.moduleName,
            address: bl.baseAddress,
            detail: "Could not read memory — module may have been unloaded",
          });
          continue;
        }

        if (currentHash !== bl.hash) {
          currentViolations++;
          violationCount++;
          ctx.emit("error", {
            event: "integrity_violation",
            library: bl.moduleName,
            section_base: bl.baseAddress,
            section_size: bl.size,
            expected_hash: bl.hash,
            actual_hash: currentHash,
            detail: "Executable code modified at runtime — active hooking or memory patching detected",
          });
        }
      } catch (e) {
        ctx.emit("warn", {
          event: "check_error",
          key: key,
          error: e.message || String(e),
        });
      }
    }

    if (currentViolations === 0) {
      ctx.emit("info", {
        event: "integrity_check_passed",
        check_number: checkCount,
        sections_verified: baselineCount,
      });
    }
  }, intervalSeconds * 1000);
}

// Daemon heartbeat
var hb = setInterval(function () {
  ctx.heartbeat();
  ctx.emit("info", {
    event: "integrity_stats",
    checks_completed: checkCount,
    total_violations: violationCount,
    sections_monitored: baselineCount,
  });
}, heartbeatInterval);
