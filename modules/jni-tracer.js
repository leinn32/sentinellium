// JNI Transition Tracer — Traces Java-to-native boundary calls through ART's JNI layer.
// Hooks art::JNI::Call*MethodV symbols to map all JNI transitions regardless of obfuscation.
// RASP relevance: reveals the native call surface that an adversary would target for bypass.

var RASP_METHOD_PATTERNS = [
  "checkroot", "isrooted", "rootcheck", "verifysignature", "checksignature",
  "isdebugger", "debuggercheck", "antifrida", "fridacheck", "integrity",
  "tamper", "emulator", "isemulator", "hookdetect", "checkenv",
  "safetynet", "attestation", "devicebind",
];

var JNI_SYMBOL_PATTERNS = [
  /^_ZN3art3JNI\d+Call.*Method/,
  /^_ZN3art3JNI\d+Get.*Field/,
  /^_ZN3art3JNI\d+Set.*Field/,
  /^_ZN3art3JNI\d+NewObject/,
];

var heartbeatInterval = (ctx.params.heartbeat_seconds || 10) * 1000;
var THROTTLE_MS = ctx.params.throttle_ms || 100;

var recentMethods = {};
var traceCount = 0;
var raspCallCount = 0;

function isRaspMethod(method, className) {
  var combined = (className + "." + method).toLowerCase();
  for (var i = 0; i < RASP_METHOD_PATTERNS.length; i++) {
    if (combined.includes(RASP_METHOD_PATTERNS[i])) return true;
  }
  return false;
}

function getCallerModule(context) {
  try {
    var bt = Thread.backtrace(context, Backtracer.FUZZY);
    if (bt.length > 1) {
      var mod = Process.findModuleByAddress(bt[1]);
      if (mod !== null) return mod.name;
    }
  } catch (_) {}
  return "unknown";
}

// Resolve ART JNI symbols
var resolvedSymbols = [];

try {
  var symbols = Module.enumerateSymbols("libart.so");
  var seen = {};

  for (var si = 0; si < symbols.length; si++) {
    var sym = symbols[si];
    if (sym.type !== "function" || seen[sym.name]) continue;

    for (var pi = 0; pi < JNI_SYMBOL_PATTERNS.length; pi++) {
      if (JNI_SYMBOL_PATTERNS[pi].test(sym.name)) {
        resolvedSymbols.push({ name: sym.name, address: sym.address });
        seen[sym.name] = true;
        break;
      }
    }
  }
} catch (e) {
  ctx.emit("warn", {
    event: "symbol_enumeration_failed",
    source: "enumerateSymbols",
    error: e.message || String(e),
  });
}

// Fallback: try exports if symbols returned nothing
if (resolvedSymbols.length === 0) {
  try {
    var exports = Module.enumerateExports("libart.so");
    var seen2 = {};
    for (var ei = 0; ei < exports.length; ei++) {
      var exp = exports[ei];
      if (exp.type !== "function" || seen2[exp.name]) continue;
      for (var pi = 0; pi < JNI_SYMBOL_PATTERNS.length; pi++) {
        if (JNI_SYMBOL_PATTERNS[pi].test(exp.name)) {
          resolvedSymbols.push({ name: exp.name, address: exp.address });
          seen2[exp.name] = true;
          break;
        }
      }
    }
  } catch (e) {
    ctx.emit("warn", {
      event: "symbol_enumeration_failed",
      source: "enumerateExports",
      error: e.message || String(e),
    });
  }
}

if (resolvedSymbols.length === 0) {
  ctx.emit("warn", {
    event: "no_symbols_resolved",
    detail: "JNI tracing unavailable — could not resolve art::JNI::Call*Method symbols. " +
            "Unsupported ART version or stripped libart.so.",
  });
} else {
  ctx.emit("info", {
    event: "symbols_resolved",
    count: resolvedSymbols.length,
    symbols: resolvedSymbols.map(function (s) { return s.name; }),
  });

  // Attach hooks
  for (var hi = 0; hi < resolvedSymbols.length; hi++) {
    (function (sym) {
      try {
        Interceptor.attach(sym.address, {
          onEnter: function (args) {
            try {
              var now = Date.now();
              var methodName = "unknown";
              var className = "unknown";

              try {
                Java.performNow(function () {
                  var bt = Thread.backtrace(this.context, Backtracer.FUZZY)
                    .map(DebugSymbol.fromAddress)
                    .map(function (s) { return s.toString(); });
                  for (var fi = 0; fi < bt.length; fi++) {
                    var jniMatch = bt[fi].match(/(\w+(?:\.\w+)+)\.(\w+)/);
                    if (jniMatch) {
                      className = jniMatch[1] || className;
                      methodName = jniMatch[2] || methodName;
                      break;
                    }
                  }
                }.bind(this));
              } catch (_) {}

              // Throttle duplicates
              var key = className + "." + methodName;
              var lastLog = recentMethods[key];
              if (lastLog !== undefined && now - lastLog < THROTTLE_MS) return;
              recentMethods[key] = now;

              traceCount++;
              var callerModule = getCallerModule(this.context);
              var isRasp = isRaspMethod(methodName, className);

              if (isRasp) {
                raspCallCount++;
                ctx.emit("warn", {
                  event: "rasp_jni_call",
                  art_symbol: sym.name,
                  class_name: className,
                  method: methodName,
                  caller_module: callerModule,
                });
              } else {
                ctx.emit("info", {
                  event: "jni_call",
                  art_symbol: sym.name,
                  class_name: className,
                  method: methodName,
                  caller_module: callerModule,
                });
              }
            } catch (_) { /* never crash target */ }
          },
        });
      } catch (_) {
        ctx.emit("info", {
          event: "hook_skipped",
          symbol: sym.name,
        });
      }
    })(resolvedSymbols[hi]);
  }

  ctx.emit("info", {
    event: "module_ready",
    module: "jni-tracer",
    hooks_attached: resolvedSymbols.length,
  });
}

// Daemon heartbeat
var hb = setInterval(function () {
  ctx.heartbeat();
  ctx.emit("info", {
    event: "jni_tracer_stats",
    total_traces: traceCount,
    rasp_related_calls: raspCallCount,
  });

  // Periodically clean throttle map
  var now = Date.now();
  var cutoff = now - THROTTLE_MS * 10;
  for (var k in recentMethods) {
    if (recentMethods[k] < cutoff) delete recentMethods[k];
  }
}, heartbeatInterval);
