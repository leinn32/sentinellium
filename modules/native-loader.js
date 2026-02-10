// Native Loader Monitor — Hooks android_dlopen_ext to trace native library loading.
// Detects injection of Frida gadgets, Xposed modules, and custom native payloads.
// RASP relevance: audits tamper detection coverage at the linker level.

const suspiciousPaths = ctx.params.suspicious_paths || [
  "/data/local/tmp",
  "/data/data/*/lib-custom/",
];

const suspiciousPatterns = ctx.params.suspicious_patterns || [
  "frida", "xposed", "substrate", "magisk", "lsposed",
];

const heartbeatInterval = (ctx.params.heartbeat_seconds || 10) * 1000;
let loadCount = 0;
let suspiciousCount = 0;

function matchSuspicious(path) {
  const lower = path.toLowerCase();

  for (const sp of suspiciousPaths) {
    if (sp.includes("*")) {
      const pattern = sp
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, "[^/]+");
      if (new RegExp(pattern, "i").test(path)) {
        return "path:" + sp;
      }
    } else if (lower.startsWith(sp.toLowerCase())) {
      return "path:" + sp;
    }
  }

  for (const pat of suspiciousPatterns) {
    if (lower.includes(pat.toLowerCase())) {
      return "pattern:" + pat;
    }
  }

  return null;
}

// Resolve android_dlopen_ext across linker variants
function resolveSymbol() {
  const candidates = ["linker64", "linker", "libdl.so"];
  for (const mod of candidates) {
    const addr = Module.findExportByName(mod, "android_dlopen_ext");
    if (addr !== null) {
      ctx.emit("info", {
        event: "symbol_resolved",
        module: mod,
        symbol: "android_dlopen_ext",
        address: addr.toString(),
      });
      return addr;
    }
  }
  // Fallback: global search
  const addr = Module.findExportByName(null, "android_dlopen_ext");
  if (addr !== null) {
    ctx.emit("info", {
      event: "symbol_resolved",
      module: "global",
      symbol: "android_dlopen_ext",
      address: addr.toString(),
    });
    return addr;
  }
  return null;
}

const target = resolveSymbol();

if (target === null) {
  ctx.emit("warn", {
    event: "symbol_not_found",
    detail: "Could not resolve android_dlopen_ext in linker64, linker, or libdl.so. " +
            "This module requires Android 7+.",
  });
} else {
  Interceptor.attach(target, {
    onEnter(args) {
      const pathPtr = args[0];
      if (pathPtr === undefined || pathPtr.isNull()) return;

      const path = pathPtr.readUtf8String();
      if (path === null) return;

      this._libPath = path;
      loadCount++;

      ctx.emit("info", {
        event: "library_load_attempt",
        path: path,
        load_number: loadCount,
      });

      const matchedRule = matchSuspicious(path);
      if (matchedRule !== null) {
        suspiciousCount++;
        ctx.emit("error", {
          event: "suspicious_library_load",
          path: path,
          matched_rule: matchedRule,
          backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join("\n"),
        });
      }
    },

    onLeave(retval) {
      const path = this._libPath;
      if (path === undefined) return;

      const success = !retval.isNull();
      ctx.emit("info", {
        event: "library_load_result",
        path: path,
        success: success,
        handle: success ? retval.toString() : null,
      });
    },
  });

  ctx.emit("info", {
    event: "module_ready",
    module: "native-loader",
    detail: "Monitoring android_dlopen_ext for library injection",
  });
}

// Daemon heartbeat
const hb = setInterval(function () {
  ctx.heartbeat();
  ctx.emit("info", {
    event: "native_loader_stats",
    total_loads: loadCount,
    suspicious_loads: suspiciousCount,
  });
}, heartbeatInterval);
