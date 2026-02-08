/**
 * MachOIntegrity — Mach-O binary integrity verification for iOS.
 *
 * What:  Parses Mach-O headers of loaded binaries, hashes their __TEXT/__text
 *        sections, and periodically re-verifies. Also validates the code
 *        signature status via the csops syscall.
 *
 * Why:   Runtime patching on iOS (Substrate hooks, Frida inline hooks, manual
 *        memory writes) modifies the executable __text section. RASP SDKs
 *        verify code signatures and binary integrity to detect these
 *        modifications. This module provides an independent integrity baseline
 *        to audit whether those checks are functioning correctly.
 *
 * RASP:  Directly mirrors iOS RASP code integrity features. Validates whether
 *        the SDK's own integrity checks detect active hooking and whether an
 *        attacker has patched those checks out. The csops validation catches
 *        cases where code signing has been invalidated by modification.
 */

import { BaseHookModule, type ModuleConfig } from "../../core/hook-module";

/** Mach-O magic numbers. */
const MH_MAGIC_64 = 0xfeedfacf;
const MH_MAGIC_32 = 0xfeedface;

/** Load command types. */
const LC_SEGMENT_64 = 0x19;
const LC_SEGMENT = 0x01;
const LC_CODE_SIGNATURE = 0x1d;

/** csops constants for code signature validation. */
const CS_OPS_STATUS = 0; // Get code signing status
const CS_VALID = 0x00000001; // Dynamically valid
const CS_HARD = 0x00000100; // Don't load invalid pages
const CS_KILL = 0x00000200; // Kill process if invalid

/** Chunk size for hashing large sections. */
const CHUNK_SIZE = 65536;

interface BaselineEntry {
  moduleName: string;
  segmentName: string;
  sectionName: string;
  baseAddress: string;
  size: number;
  hash: string;
}

export class MachOIntegrity extends BaseHookModule {
  readonly id = "macho-integrity";

  private baselines: Map<string, BaselineEntry> = new Map();
  private intervalHandle: ReturnType<typeof setInterval> | null = null;
  private watchedLibs: string[];
  private intervalSeconds: number;

  constructor(config: ModuleConfig = {}) {
    super(config);
    this.watchedLibs = this.configValue<string[]>("watched_libs", []);
    this.intervalSeconds = this.configValue<number>("interval_seconds", 5);
  }

  protected onEnable(): void {
    this.buildBaseline();
    this.checkCodeSignature();

    if (this.baselines.size === 0) {
      this.emit("warning", {
        event: "no_baseline",
        detail: "No __text sections found for watched modules",
      });
      return;
    }

    this.emit("info", {
      event: "baseline_established",
      sections: this.baselines.size,
      libraries: [
        ...new Set([...this.baselines.values()].map((b) => b.moduleName)),
      ],
    });

    this.intervalHandle = setInterval(() => {
      this.checkIntegrity();
    }, this.intervalSeconds * 1000);
  }

  protected onDisable(): void {
    if (this.intervalHandle !== null) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }
    this.baselines.clear();
  }

  /**
   * Build integrity baselines by parsing Mach-O headers.
   *
   * For each watched module, we:
   * 1. Read the Mach-O header to determine architecture (32/64-bit)
   * 2. Walk load commands to find LC_SEGMENT_64 with segname "__TEXT"
   * 3. Within __TEXT, find the __text section and hash its bytes
   * 4. Also hash LC_CODE_SIGNATURE data if present
   */
  private buildBaseline(): void {
    const modules = Process.enumerateModules();
    const targetNames = new Set(
      this.watchedLibs.map((l) => l.toLowerCase())
    );

    for (const mod of modules) {
      // Include explicitly watched libs, the main executable, and app frameworks
      const isWatched = targetNames.has(mod.name.toLowerCase());
      const isMainExe = mod.path === Process.mainModule.path;
      const isAppFramework =
        mod.path.includes("/Frameworks/") &&
        mod.path.includes(".app/");

      if (!isWatched && !isMainExe && !isAppFramework) {
        continue;
      }

      try {
        this.parseAndBaseline(mod);
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        this.emit("warning", {
          event: "baseline_failed",
          library: mod.name,
          error: msg,
        });
      }
    }
  }

  /**
   * Parse Mach-O header and baseline __text section.
   */
  private parseAndBaseline(mod: Module): void {
    const base = mod.base;
    const magic = base.readU32();

    let is64: boolean;
    let headerSize: number;
    let ncmds: number;
    let segmentCmd: number;

    if (magic === MH_MAGIC_64) {
      is64 = true;
      headerSize = 32; // sizeof(mach_header_64)
      ncmds = base.add(16).readU32();
      segmentCmd = LC_SEGMENT_64;
    } else if (magic === MH_MAGIC_32) {
      is64 = false;
      headerSize = 28; // sizeof(mach_header)
      ncmds = base.add(16).readU32();
      segmentCmd = LC_SEGMENT;
    } else {
      return; // Not a Mach-O binary
    }

    let cmdOffset = headerSize;

    for (let i = 0; i < ncmds; i++) {
      const cmdPtr = base.add(cmdOffset);
      const cmd = cmdPtr.readU32();
      const cmdSize = cmdPtr.add(4).readU32();

      if (cmd === segmentCmd) {
        // Read segment name (16 bytes at offset 8)
        const segName = cmdPtr.add(8).readUtf8String(16)?.replace(/\0/g, "") ?? "";

        if (segName === "__TEXT") {
          this.baselineTextSegment(mod, cmdPtr, is64);
        }
      } else if (cmd === LC_CODE_SIGNATURE) {
        this.baselineCodeSignature(mod, base, cmdPtr);
      }

      cmdOffset += cmdSize;
    }
  }

  /**
   * Hash the __text section within a __TEXT segment.
   *
   * The __text section contains the actual executable machine code.
   * Inline hooks modify these bytes, so any hash change indicates tampering.
   */
  private baselineTextSegment(
    mod: Module,
    segCmdPtr: NativePointer,
    is64: boolean
  ): void {
    // Parse sections within the segment
    // segment_command_64: 72 bytes header, then section_64 entries (80 bytes each)
    // segment_command: 56 bytes header, then section entries (68 bytes each)
    const segHeaderSize = is64 ? 72 : 56;
    const sectionSize = is64 ? 80 : 68;
    const nsects = segCmdPtr.add(is64 ? 64 : 48).readU32();

    for (let s = 0; s < nsects; s++) {
      const sectPtr = segCmdPtr.add(segHeaderSize + s * sectionSize);
      const sectName =
        sectPtr.readUtf8String(16)?.replace(/\0/g, "") ?? "";

      if (sectName === "__text") {
        // Read section address and size
        let addr: NativePointer;
        let size: number;

        if (is64) {
          addr = ptr(sectPtr.add(32).readU64().toString());
          size = Number(sectPtr.add(40).readU64());
        } else {
          addr = ptr(sectPtr.add(32).readU32().toString());
          size = sectPtr.add(36).readU32();
        }

        if (size > 0) {
          const hash = this.hashMemoryRegion(addr, size);
          if (hash !== null) {
            const key = `${mod.name}::__TEXT::__text`;
            this.baselines.set(key, {
              moduleName: mod.name,
              segmentName: "__TEXT",
              sectionName: "__text",
              baseAddress: addr.toString(),
              size,
              hash,
            });
          }
        }
      }
    }
  }

  /**
   * Hash the code signature blob for additional tamper detection.
   *
   * LC_CODE_SIGNATURE points to the code signature data embedded in the
   * binary. Any modification to the binary should invalidate this signature.
   */
  private baselineCodeSignature(
    mod: Module,
    base: NativePointer,
    cmdPtr: NativePointer
  ): void {
    // LC_CODE_SIGNATURE layout: cmd(4) + cmdsize(4) + dataoff(4) + datasize(4)
    const dataOff = cmdPtr.add(8).readU32();
    const dataSize = cmdPtr.add(12).readU32();

    if (dataSize > 0 && dataSize < 10 * 1024 * 1024) {
      const sigAddr = base.add(dataOff);
      const hash = this.hashMemoryRegion(sigAddr, dataSize);
      if (hash !== null) {
        const key = `${mod.name}::__LINKEDIT::code_signature`;
        this.baselines.set(key, {
          moduleName: mod.name,
          segmentName: "__LINKEDIT",
          sectionName: "code_signature",
          baseAddress: sigAddr.toString(),
          size: dataSize,
          hash,
        });
      }
    }
  }

  /**
   * Check code signature validity via the csops syscall.
   *
   * csops (syscall 169 on iOS) queries the kernel's code signing status
   * for the current process. If CS_VALID is not set, the binary's signature
   * has been invalidated — a definitive indicator of tampering.
   */
  private checkCodeSignature(): void {
    try {
      const csopsAddr = Module.findExportByName(null, "csops");
      if (csopsAddr === null) {
        // csops may not be exported — try syscall
        this.emit("info", {
          event: "csops_unavailable",
          detail: "csops not exported; skipping code signature check",
        });
        return;
      }

      const csops = new NativeFunction(csopsAddr, "int", [
        "int",    // pid (0 = self)
        "uint",   // ops
        "pointer", // useraddr
        "uint",   // usersize
      ]);

      const statusBuf = Memory.alloc(4);
      const result = csops(0, CS_OPS_STATUS, statusBuf, 4) as number;

      if (result === 0) {
        const flags = statusBuf.readU32();
        const isValid = (flags & CS_VALID) !== 0;
        const isHard = (flags & CS_HARD) !== 0;
        const isKill = (flags & CS_KILL) !== 0;

        if (!isValid) {
          this.emit("critical", {
            event: "code_signature_invalid",
            flags: `0x${flags.toString(16)}`,
            cs_valid: false,
            cs_hard: isHard,
            cs_kill: isKill,
            detail:
              "Code signature is invalid. The binary has been modified " +
              "or resigned with a different identity.",
          });
        } else {
          this.emit("info", {
            event: "code_signature_valid",
            flags: `0x${flags.toString(16)}`,
            cs_valid: true,
            cs_hard: isHard,
            cs_kill: isKill,
          });
        }
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("warning", {
        event: "csops_failed",
        error: msg,
      });
    }
  }

  /** Periodic integrity re-check. */
  private checkIntegrity(): void {
    let violations = 0;

    for (const [key, baseline] of this.baselines.entries()) {
      try {
        const base = ptr(baseline.baseAddress);
        const currentHash = this.hashMemoryRegion(base, baseline.size);

        if (currentHash === null) {
          this.emit("warning", {
            event: "hash_failed",
            library: baseline.moduleName,
            section: `${baseline.segmentName}::${baseline.sectionName}`,
          });
          continue;
        }

        if (currentHash !== baseline.hash) {
          violations++;
          this.emit("critical", {
            event: "integrity_violation",
            library: baseline.moduleName,
            segment: baseline.segmentName,
            section: baseline.sectionName,
            address: baseline.baseAddress,
            size: baseline.size,
            expected_hash: baseline.hash,
            actual_hash: currentHash,
            detail:
              "Mach-O section has been modified at runtime. " +
              "This indicates active hooking or binary patching.",
          });
        }
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        this.emit("warning", {
          event: "check_error",
          key,
          error: msg,
        });
      }
    }

    if (violations === 0) {
      this.emit("info", {
        event: "integrity_check_passed",
        sections_verified: this.baselines.size,
      });
    }
  }

  /** Compute SHA-256 hash of a memory region in chunks. */
  private hashMemoryRegion(base: NativePointer, size: number): string | null {
    try {
      if (size <= CHUNK_SIZE) {
        const bytes = base.readByteArray(size);
        if (bytes === null) {
          return null;
        }
        return this.sha256(bytes);
      }

      const chunkHashes: string[] = [];
      let offset = 0;
      while (offset < size) {
        const chunkLen = Math.min(CHUNK_SIZE, size - offset);
        const bytes = base.add(offset).readByteArray(chunkLen);
        if (bytes === null) {
          return null;
        }
        chunkHashes.push(this.sha256(bytes));
        offset += chunkLen;
      }

      const combined = chunkHashes.join("");
      const buf = new ArrayBuffer(combined.length * 2);
      const view = new Uint8Array(buf);
      for (let i = 0; i < combined.length; i++) {
        view[i] = combined.charCodeAt(i) & 0xff;
      }
      return this.sha256(buf);
    } catch {
      return null;
    }
  }

  private sha256(data: ArrayBuffer): string {
    const checksum = new Checksum("sha256");
    checksum.update(data);
    return checksum.getString();
  }
}
