/**
 * JailbreakDetectionAuditor — Scores jailbreak visibility on iOS.
 *
 * What:  Runs the common jailbreak detection checks that RASP SDKs use
 *        and reports which ones the current device fails (i.e., where
 *        jailbreak indicators are detectable).
 *
 * Why:   This is the iOS counterpart to the Android FridaDetectionAuditor.
 *        Instead of just detecting jailbreaks, it *inverts* the RASP
 *        perspective: running each check independently and reporting the
 *        results. This produces a "jailbreak visibility score" showing how
 *        exposed the device is to standard RASP detection.
 *
 * RASP:  This is literally what Wultra's iOS SDK does for jailbreak detection.
 *        Implementing it independently proves understanding of the detection
 *        logic from scratch and enables auditing whether the SDK's checks
 *        are comprehensive.
 */

import { BaseHookModule, type ModuleConfig } from "../../core/hook-module";

/** Filesystem artifacts indicating jailbreak. */
const JAILBREAK_FILES = [
  "/Applications/Cydia.app",
  "/Library/MobileSubstrate/MobileSubstrate.dylib",
  "/bin/bash",
  "/usr/sbin/sshd",
  "/etc/apt",
  "/usr/bin/ssh",
  "/private/var/lib/apt/",
  "/private/var/lib/cydia",
  "/private/var/stash",
  "/usr/bin/cycript",
  "/usr/local/bin/cycript",
  "/usr/lib/libcycript.dylib",
  "/var/cache/apt",
  "/var/lib/apt",
  "/var/log/syslog",
  "/Library/MobileSubstrate/DynamicLibraries/",
  "/usr/libexec/cydia/",
  "/Applications/Sileo.app",
  "/var/jb",
  "/var/binpack",
];

/** URL schemes associated with jailbreak package managers. */
const JAILBREAK_SCHEMES = ["cydia://", "sileo://", "zbra://", "filza://"];

/** Dylib paths that indicate injection frameworks. */
const SUSPICIOUS_DYLIB_PATTERNS = [
  "mobilesubstrate",
  "substrate",
  "cycript",
  "frida",
  "tweakinject",
  "libhooker",
  "substitute",
  "ellekit",
  "checkra1n",
  "unc0ver",
  "taurine",
  "dopamine",
];

export class JailbreakDetectionAuditor extends BaseHookModule {
  readonly id = "jailbreak-detection";

  constructor(config: ModuleConfig = {}) {
    super(config);
  }

  protected onEnable(): void {
    this.checkFileExistence();
    this.checkUrlSchemes();
    this.checkSandboxIntegrity();
    this.checkForkAbility();
    this.checkDyldImages();
    this.checkSymlinks();
  }

  protected onDisable(): void {
    // Scan-based module — nothing to detach.
  }

  /**
   * Check 1: Filesystem Artifact Detection
   *
   * Check for the existence of files/directories commonly present on
   * jailbroken devices. This is the most basic and widely-used detection
   * method. RASP SDKs maintain extensive lists of paths to check.
   */
  private checkFileExistence(): void {
    let detectionCount = 0;

    for (const filePath of JAILBREAK_FILES) {
      try {
        const exists = this.fileExists(filePath);
        if (exists) {
          detectionCount++;
          this.emit("warning", {
            check: "file_existence",
            finding: "jailbreak_artifact",
            path: filePath,
          });
        }
      } catch {
        // Access denied = sandboxed = good
      }
    }

    this.emit("info", {
      check: "file_existence",
      finding: detectionCount > 0 ? "artifacts_found" : "clean",
      artifacts_found: detectionCount,
      paths_checked: JAILBREAK_FILES.length,
    });
  }

  /**
   * Check 2: URL Scheme Detection
   *
   * Attempt to check if jailbreak-related URL schemes are registered.
   * On a non-jailbroken device, Cydia/Sileo schemes should not be available.
   * Uses UIApplication.canOpenURL: via ObjC bridge.
   */
  private checkUrlSchemes(): void {
    if (!ObjC.available) {
      this.emit("warning", {
        check: "url_schemes",
        finding: "check_failed",
        error: "ObjC runtime not available",
      });
      return;
    }

    let detectionCount = 0;

    try {
      const UIApplication = ObjC.classes["UIApplication"];
      if (UIApplication === undefined) {
        return;
      }

      const app = UIApplication.sharedApplication();
      const NSURL = ObjC.classes["NSURL"];

      for (const scheme of JAILBREAK_SCHEMES) {
        try {
          const url = NSURL.URLWithString_(scheme);
          if (url !== null) {
            const canOpen = app.canOpenURL_(url);
            if (canOpen) {
              detectionCount++;
              this.emit("warning", {
                check: "url_schemes",
                finding: "jailbreak_scheme_available",
                scheme,
              });
            }
          }
        } catch {
          // Can't check this scheme — skip
        }
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("warning", {
        check: "url_schemes",
        finding: "check_failed",
        error: msg,
      });
      return;
    }

    if (detectionCount === 0) {
      this.emit("info", {
        check: "url_schemes",
        finding: "clean",
        detail: "No jailbreak URL schemes detected",
      });
    }
  }

  /**
   * Check 3: Sandbox Write Test
   *
   * Attempt to write to a path outside the app's sandbox.
   * On a properly sandboxed (non-jailbroken) device, this should fail.
   * If it succeeds, the sandbox is compromised.
   */
  private checkSandboxIntegrity(): void {
    const testPath = "/private/sentinellium-jb-test.txt";
    const testContent = "sentinellium-test";

    try {
      // Attempt write using native open/write/close
      const openFn = new NativeFunction(
        Module.findExportByName("libSystem.B.dylib", "open")!,
        "int",
        ["pointer", "int", "int"]
      );
      const writeFn = new NativeFunction(
        Module.findExportByName("libSystem.B.dylib", "write")!,
        "int",
        ["int", "pointer", "int"]
      );
      const closeFn = new NativeFunction(
        Module.findExportByName("libSystem.B.dylib", "close")!,
        "int",
        ["int"]
      );
      const unlinkFn = new NativeFunction(
        Module.findExportByName("libSystem.B.dylib", "unlink")!,
        "int",
        ["pointer"]
      );

      const pathBuf = Memory.allocUtf8String(testPath);
      const O_WRONLY = 0x0001;
      const O_CREAT = 0x0200;
      const O_TRUNC = 0x0400;

      const fd = openFn(pathBuf, O_WRONLY | O_CREAT | O_TRUNC, 0o644) as number;
      if (fd >= 0) {
        // Write succeeded — sandbox is broken
        const contentBuf = Memory.allocUtf8String(testContent);
        writeFn(fd, contentBuf, testContent.length);
        closeFn(fd);

        // Clean up
        unlinkFn(pathBuf);

        this.emit("critical", {
          check: "sandbox_write",
          finding: "sandbox_compromised",
          path: testPath,
          detail:
            "Successfully wrote outside app sandbox. " +
            "Device is jailbroken or sandbox is disabled.",
        });
      } else {
        this.emit("info", {
          check: "sandbox_write",
          finding: "clean",
          detail: "Sandbox write test failed as expected — sandbox intact",
        });
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("info", {
        check: "sandbox_write",
        finding: "clean",
        detail: `Write blocked: ${msg}`,
      });
    }
  }

  /**
   * Check 4: Fork Test
   *
   * On a properly sandboxed iOS device, fork() returns -1 because the
   * sandbox prohibits process creation. If fork() succeeds, the sandbox
   * has been disabled (indicating jailbreak).
   */
  private checkForkAbility(): void {
    try {
      const forkFn = new NativeFunction(
        Module.findExportByName("libSystem.B.dylib", "fork")!,
        "int",
        []
      );

      const pid = forkFn() as number;

      if (pid === 0) {
        // We're in the child process — exit immediately
        const exitFn = new NativeFunction(
          Module.findExportByName("libSystem.B.dylib", "_exit")!,
          "void",
          ["int"]
        );
        exitFn(0);
      } else if (pid > 0) {
        // Fork succeeded in parent — jailbroken
        // Wait for child to prevent zombie
        const waitpidFn = new NativeFunction(
          Module.findExportByName("libSystem.B.dylib", "waitpid")!,
          "int",
          ["int", "pointer", "int"]
        );
        const status = Memory.alloc(4);
        waitpidFn(pid, status, 0);

        this.emit("critical", {
          check: "fork_test",
          finding: "sandbox_compromised",
          child_pid: pid,
          detail:
            "fork() succeeded — sandbox does not restrict process creation. " +
            "Device is jailbroken.",
        });
      } else {
        // Fork failed (-1) — expected on non-jailbroken device
        this.emit("info", {
          check: "fork_test",
          finding: "clean",
          detail: "fork() blocked — sandbox process restriction intact",
        });
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("info", {
        check: "fork_test",
        finding: "clean",
        detail: `fork test inconclusive: ${msg}`,
      });
    }
  }

  /**
   * Check 5: Dyld Image Enumeration
   *
   * Enumerate all loaded dynamic libraries via _dyld_image_count /
   * _dyld_get_image_name and flag any from known injection framework paths.
   */
  private checkDyldImages(): void {
    try {
      const imageCountFn = new NativeFunction(
        Module.findExportByName(null, "_dyld_image_count")!,
        "uint32",
        []
      );
      const imageNameFn = new NativeFunction(
        Module.findExportByName(null, "_dyld_get_image_name")!,
        "pointer",
        ["uint32"]
      );

      const count = imageCountFn() as number;
      let detectionCount = 0;

      for (let i = 0; i < count; i++) {
        const namePtr = imageNameFn(i) as NativePointer;
        if (namePtr.isNull()) {
          continue;
        }

        const name = namePtr.readUtf8String();
        if (name === null) {
          continue;
        }

        const lowerName = name.toLowerCase();
        for (const pattern of SUSPICIOUS_DYLIB_PATTERNS) {
          if (lowerName.includes(pattern)) {
            detectionCount++;
            this.emit("warning", {
              check: "dyld_images",
              finding: "suspicious_dylib",
              path: name,
              matched_pattern: pattern,
              image_index: i,
            });
            break;
          }
        }
      }

      this.emit("info", {
        check: "dyld_images",
        finding: detectionCount > 0 ? "suspicious_dylibs_found" : "clean",
        total_images: count,
        suspicious_count: detectionCount,
      });
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("warning", {
        check: "dyld_images",
        finding: "check_failed",
        error: msg,
      });
    }
  }

  /**
   * Check 6: Symbolic Link Detection
   *
   * Some jailbreaks create symbolic links from system paths to locations
   * on the data partition. Check if key system paths are symlinks.
   */
  private checkSymlinks(): void {
    const pathsToCheck = [
      "/Applications",
      "/Library/Ringtones",
      "/Library/Wallpaper",
      "/usr/arm-apple-darwin9",
      "/usr/include",
      "/usr/libexec",
      "/usr/share",
    ];

    try {
      const lstatFn = new NativeFunction(
        Module.findExportByName("libSystem.B.dylib", "lstat")!,
        "int",
        ["pointer", "pointer"]
      );

      // stat struct is large — allocate 256 bytes to be safe
      const statBuf = Memory.alloc(256);
      let symlinkCount = 0;

      for (const checkPath of pathsToCheck) {
        const pathBuf = Memory.allocUtf8String(checkPath);
        const result = lstatFn(pathBuf, statBuf) as number;

        if (result === 0) {
          // st_mode is at offset 4 (uint16 on iOS)
          const mode = statBuf.add(4).readU16();
          const S_IFLNK = 0xa000;
          const isSymlink = (mode & 0xf000) === S_IFLNK;

          if (isSymlink) {
            symlinkCount++;
            this.emit("warning", {
              check: "symlink_detection",
              finding: "suspicious_symlink",
              path: checkPath,
              detail: `System path ${checkPath} is a symbolic link`,
            });
          }
        }
      }

      if (symlinkCount === 0) {
        this.emit("info", {
          check: "symlink_detection",
          finding: "clean",
          paths_checked: pathsToCheck.length,
        });
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      this.emit("warning", {
        check: "symlink_detection",
        finding: "check_failed",
        error: msg,
      });
    }
  }

  /** Check if a file exists using native access() call. */
  private fileExists(path: string): boolean {
    try {
      const accessFn = new NativeFunction(
        Module.findExportByName("libSystem.B.dylib", "access")!,
        "int",
        ["pointer", "int"]
      );
      const pathBuf = Memory.allocUtf8String(path);
      const F_OK = 0;
      return (accessFn(pathBuf, F_OK) as number) === 0;
    } catch {
      return false;
    }
  }
}
