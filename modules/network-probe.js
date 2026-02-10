// Network Probe — Monitors native-layer TCP connections via libc connect().
// Catches outgoing connections that bypass Java networking stacks entirely.
// RASP relevance: detects C2 channels using hardcoded IPs on unusual ports.

var AF_INET = 2;
var EXPECTED_PORTS = { 80: true, 443: true, 8080: true, 8443: true, 53: true };

var heartbeatInterval = (ctx.params.heartbeat_seconds || 10) * 1000;
var privateRangeStrs = ctx.params.private_ranges || [
  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
];

var connectionCount = 0;
var suspiciousCount = 0;
var recentDnsLookups = {};

function parseCidr(cidr) {
  var parts = cidr.split("/");
  if (parts.length !== 2) return null;

  var octets = parts[0].split(".");
  if (octets.length !== 4) return null;

  var bits = parseInt(parts[1], 10);
  if (isNaN(bits) || bits < 0 || bits > 32) return null;

  var ip = 0;
  for (var i = 0; i < 4; i++) {
    var val = parseInt(octets[i], 10);
    if (isNaN(val) || val < 0 || val > 255) return null;
    ip = (ip << 8) | val;
  }

  var mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return { network: (ip & mask) >>> 0, mask: mask >>> 0 };
}

var privateRanges = [];
for (var i = 0; i < privateRangeStrs.length; i++) {
  var r = parseCidr(privateRangeStrs[i]);
  if (r !== null) privateRanges.push(r);
}

function intToIp(addr) {
  return [addr & 0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff, (addr >> 24) & 0xff].join(".");
}

function isPrivateIp(addr) {
  var hostOrder = ((addr & 0xff) << 24) | (((addr >> 8) & 0xff) << 16) |
                  (((addr >> 16) & 0xff) << 8) | ((addr >> 24) & 0xff);
  for (var i = 0; i < privateRanges.length; i++) {
    if ((hostOrder & privateRanges[i].mask) === privateRanges[i].network) return true;
  }
  return false;
}

function wasRecentlyResolved() {
  var now = Date.now();
  for (var k in recentDnsLookups) {
    if (now - recentDnsLookups[k] < 10000) return true;
  }
  return false;
}

// Hook getaddrinfo for DNS resolution tracking
var getaddrinfoAddr = Module.findExportByName("libc.so", "getaddrinfo");
if (getaddrinfoAddr !== null) {
  Interceptor.attach(getaddrinfoAddr, {
    onEnter: function (args) {
      var hostnamePtr = args[0];
      if (hostnamePtr !== undefined && !hostnamePtr.isNull()) {
        var hostname = hostnamePtr.readUtf8String();
        if (hostname !== null) this._hostname = hostname;
      }
    },
    onLeave: function (retval) {
      if (this._hostname !== undefined && retval.toInt32() === 0) {
        recentDnsLookups[this._hostname] = Date.now();

        // Clean old entries
        if (Object.keys(recentDnsLookups).length > 500) {
          var cutoff = Date.now() - 10000;
          for (var k in recentDnsLookups) {
            if (recentDnsLookups[k] < cutoff) delete recentDnsLookups[k];
          }
        }
      }
    },
  });
}

// Hook connect()
var connectAddr = Module.findExportByName("libc.so", "connect");
if (connectAddr === null) {
  ctx.emit("warn", {
    event: "symbol_not_found",
    detail: "Could not resolve connect() in libc.so",
  });
} else {
  Interceptor.attach(connectAddr, {
    onEnter: function (args) {
      try {
        var sockaddrPtr = args[1];
        if (sockaddrPtr === undefined || sockaddrPtr.isNull()) return;

        var family = sockaddrPtr.readU16();
        if (family !== AF_INET) return;

        var portRaw = sockaddrPtr.add(2).readU16();
        var port = ((portRaw & 0xff) << 8) | ((portRaw >> 8) & 0xff);
        var addrRaw = sockaddrPtr.add(4).readU32();
        var ip = intToIp(addrRaw);

        connectionCount++;

        if (isPrivateIp(addrRaw)) {
          ctx.emit("info", {
            event: "connect_private",
            destination: ip + ":" + port,
            private: true,
          });
          return;
        }

        if (!EXPECTED_PORTS[port]) {
          var resolved = wasRecentlyResolved();
          if (!resolved) {
            suspiciousCount++;
            ctx.emit("error", {
              event: "suspicious_connect",
              destination: ip + ":" + port,
              port: port,
              ip: ip,
              dns_resolved: false,
              detail: "Connection to non-private IP on unusual port without DNS resolution. " +
                      "Possible hardcoded C2 address.",
              backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .join("\n"),
            });
          } else {
            ctx.emit("warn", {
              event: "unusual_port_connect",
              destination: ip + ":" + port,
              port: port,
              ip: ip,
              dns_resolved: true,
            });
          }
        } else {
          ctx.emit("info", {
            event: "connect_external",
            destination: ip + ":" + port,
          });
        }
      } catch (_) { /* never crash the app */ }
    },
  });

  ctx.emit("info", {
    event: "module_ready",
    module: "network-probe",
    detail: "Monitoring native connect() for suspicious connections",
  });
}

// Daemon heartbeat
var hb = setInterval(function () {
  ctx.heartbeat();
  ctx.emit("info", {
    event: "network_probe_stats",
    total_connections: connectionCount,
    suspicious_connections: suspiciousCount,
  });
}, heartbeatInterval);
