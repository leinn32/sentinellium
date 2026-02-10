// RASP Fingerprinter — Identifies which RASP SDK protects the target application.
// Scans native modules, Java classes, string patterns, and behavioral indicators.
// RASP relevance: prerequisite for targeted auditing — know what you're up against.

var SCORE_NATIVE_LIB = 40;
var SCORE_JAVA_CLASS = 30;
var SCORE_STRING_PATTERN = 15;
var SCORE_BEHAVIORAL = 15;
var CONFIDENCE_THRESHOLD = 60;

// Signature database — loaded from ctx.params or built-in defaults
var signatures = ctx.params.signatures || {
  wultra: {
    display_name: "Wultra In-App Protection",
    native_libs: ["libwultraappprotection.so", "libwultra*.so", "libpowerauth*.so"],
    java_classes: ["io.wultra.app.protection.*", "com.wultra.android.powerauth.*"],
    string_patterns: ["WultraAppProtection", "PowerAuth", "io.wultra"],
  },
  promon: {
    display_name: "Promon SHIELD",
    native_libs: ["libshield.so", "libpromon*.so"],
    java_classes: ["no.promon.shield.*", "no.promon.shieldlib.*"],
    string_patterns: ["PromonShield", "SHIELD_", "promon.shield"],
  },
  guardsquare: {
    display_name: "Guardsquare DexGuard/iXGuard",
    native_libs: ["libdexguard*.so"],
    java_classes: ["com.guardsquare.*"],
    string_patterns: ["dexguard", "guardsquare", "iXGuard"],
  },
  appdome: {
    display_name: "Appdome",
    native_libs: ["libappdome*.so", "libloader.so"],
    java_classes: ["com.appdome.*"],
    string_patterns: ["appdome"],
  },
  talsec: {
    display_name: "Talsec freeRASP",
    native_libs: ["libfreerasp.so", "libtalsec*.so"],
    java_classes: ["com.aheaditec.talsec_security.*", "com.aheaditec.talsec.*"],
    string_patterns: ["freeRASP", "talsec", "aheaditec"],
  },
  liapp: {
    display_name: "LIAPP",
    native_libs: ["libliapp*.so", "liblockin*.so"],
    java_classes: ["com.lockincomp.*"],
    string_patterns: ["LIAPP", "lockin"],
  },
  arxan: {
    display_name: "Digital.ai (Arxan) App Protection",
    native_libs: ["libaxan*.so", "libdigitalai*.so"],
    java_classes: ["com.arxan.*", "com.digitalai.*"],
    string_patterns: ["arxan", "digital.ai"],
  },
};

function matchModulePattern(moduleNames, pattern) {
  if (pattern.includes("*")) {
    var regex = new RegExp(
      "^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$", "i"
    );
    for (var i = 0; i < moduleNames.length; i++) {
      if (regex.test(moduleNames[i])) return moduleNames[i];
    }
  } else {
    for (var i = 0; i < moduleNames.length; i++) {
      if (moduleNames[i] === pattern) return moduleNames[i];
    }
  }
  return null;
}

function matchClassPattern(classNames, pattern) {
  var dotPattern = pattern.replace(/\//g, ".");
  var slashPattern = pattern.replace(/\./g, "/");

  if (dotPattern.endsWith(".*")) {
    var pkgPrefix = dotPattern.slice(0, -2);
    var slashPrefix = slashPattern.slice(0, -2);

    for (var i = 0; i < classNames.length; i++) {
      var cls = classNames[i];
      var normalized = cls.replace(/^L/, "").replace(/;$/, "");
      if (normalized.startsWith(slashPrefix + "/") || cls.startsWith(pkgPrefix + ".")) {
        return cls;
      }
    }
  } else {
    for (var i = 0; i < classNames.length; i++) {
      var cls = classNames[i];
      var normalized = cls.replace(/^L/, "").replace(/;$/, "").replace(/\//g, ".");
      if (normalized === dotPattern || cls === dotPattern) return cls;
    }
  }
  return null;
}

// Collect loaded native modules
var loadedModules = [];
try {
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    loadedModules.push(mods[i].name.toLowerCase());
  }
} catch (_) {}

// Collect loaded Java classes
var loadedClasses = [];
try {
  if (typeof Java !== "undefined" && Java.available) {
    Java.performNow(function () {
      Java.enumerateLoadedClasses({
        onMatch: function (name) { loadedClasses.push(name); },
        onComplete: function () {},
      });
    });
  }
} catch (_) {
  ctx.emit("info", {
    event: "java_enum_failed",
    detail: "Could not enumerate Java classes",
  });
}

// Read /proc/self/maps for string scanning
var mapsContent = "";
try {
  var f = new File("/proc/self/maps", "r");
  mapsContent = f.readAllText();
  f.close();
} catch (_) {}

// Score each known SDK
var candidates = [];

for (var sdkId in signatures) {
  var sig = signatures[sdkId];
  var confidence = 0;
  var matched = [];

  // Native libs
  var libs = sig.native_libs || [];
  for (var i = 0; i < libs.length; i++) {
    var m = matchModulePattern(loadedModules, libs[i].toLowerCase());
    if (m !== null) {
      confidence += SCORE_NATIVE_LIB;
      matched.push("native_lib:" + m);
    }
  }

  // Java classes
  var classes = sig.java_classes || [];
  for (var i = 0; i < classes.length; i++) {
    var m = matchClassPattern(loadedClasses, classes[i]);
    if (m !== null) {
      confidence += SCORE_JAVA_CLASS;
      matched.push("java_class:" + m);
    }
  }

  // String patterns in maps
  var patterns = sig.string_patterns || [];
  for (var i = 0; i < patterns.length; i++) {
    if (mapsContent.toLowerCase().includes(patterns[i].toLowerCase())) {
      confidence += SCORE_STRING_PATTERN;
      matched.push("string:" + patterns[i]);
    }
  }

  if (confidence > 0) {
    candidates.push({
      sdk_id: sdkId,
      display_name: sig.display_name,
      confidence: confidence,
      matched_indicators: matched,
    });
  }
}

// Behavioral scan for unknown/custom RASP
var behavioralConfidence = 0;
var behavioralMatched = [];

try {
  var status = new File("/proc/self/status", "r").readAllText();
  var tracerMatch = status.match(/TracerPid:\s*(\d+)/);
  if (tracerMatch && parseInt(tracerMatch[1]) !== 0) {
    behavioralConfidence += SCORE_BEHAVIORAL;
    behavioralMatched.push("behavior:ptrace_self_attach(tracer_pid=" + tracerMatch[1] + ")");
  }
} catch (_) {}

try {
  var threads = Process.enumerateThreads();
  var raspThreads = ["rasp", "shield", "protect", "guard", "integrity", "tamper", "watchdog"];
  for (var ti = 0; ti < threads.length; ti++) {
    try {
      var cf = new File("/proc/self/task/" + threads[ti].id + "/comm", "r");
      var tname = cf.readAllText().trim().toLowerCase();
      cf.close();
      for (var ri = 0; ri < raspThreads.length; ri++) {
        if (tname.includes(raspThreads[ri])) {
          behavioralConfidence += SCORE_BEHAVIORAL;
          behavioralMatched.push("behavior:rasp_thread(" + tname + ")");
          break;
        }
      }
    } catch (_) {}
  }
} catch (_) {}

if (behavioralConfidence > 0) {
  candidates.push({
    sdk_id: "unknown",
    display_name: "Unknown/Custom RASP",
    confidence: behavioralConfidence,
    matched_indicators: behavioralMatched,
  });
}

// Sort by confidence descending
candidates.sort(function (a, b) { return b.confidence - a.confidence; });

// Build all_candidates map
var allCandidates = {};
for (var ci = 0; ci < candidates.length; ci++) {
  if (candidates[ci].confidence > 0) {
    allCandidates[candidates[ci].sdk_id] = candidates[ci].confidence;
  }
}

// Emit result
var top = candidates[0];
if (top && top.confidence >= CONFIDENCE_THRESHOLD && top.sdk_id !== "unknown") {
  ctx.emit("info", {
    event: "rasp_identified",
    detected_sdk: top.sdk_id,
    detected_sdk_name: top.display_name,
    confidence: top.confidence,
    matched_indicators: top.matched_indicators,
    all_candidates: allCandidates,
  });
} else if (top && top.sdk_id === "unknown" && top.confidence > 0) {
  ctx.emit("warn", {
    event: "rasp_unknown",
    detected_sdk: "unknown",
    detected_sdk_name: "Unknown/Custom RASP",
    confidence: top.confidence,
    matched_indicators: top.matched_indicators,
    all_candidates: allCandidates,
  });
} else {
  ctx.emit("info", {
    event: "no_rasp_detected",
    detected_sdk: "none",
    confidence: 0,
    all_candidates: allCandidates,
    detail: "No RASP SDK indicators found. App may be unprotected.",
  });
}
