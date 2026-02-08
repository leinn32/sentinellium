/**
 * lib_load.bpf.c — Traces PROT_EXEC mmap calls to detect library loads.
 *
 * What:  Attaches to tracepoint/syscalls/sys_enter_mmap and filters for
 *        mappings with PROT_EXEC flag set, which indicates executable
 *        code being loaded into memory.
 *
 * Why:   Detects library loads at kernel level — if the Frida NativeLoaderMonitor
 *        misses a load (because the app bypassed dlopen entirely by calling
 *        mmap + manual ELF loading), this catches it. Some anti-Frida
 *        techniques load code through direct mmap to avoid hooking on dlopen.
 *
 * RASP:  Cross-references with Frida agent events to identify stealth library
 *        loads that bypass userspace hooks. Any load seen by eBPF but not by
 *        Frida is a critical finding — it means the RASP's userspace detection
 *        has a blind spot.
 *
 * Ring buffer chosen over perf buffer for:
 *   - Ordered event delivery (global ordering vs per-CPU)
 *   - No silent event drops under load
 *   - Lower memory footprint for single-PID filtering
 */

#include <linux/bpf.h>
#include <linux/mman.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

/**
 * Library load event sent to userspace.
 * Captures the mmap parameters that indicate code loading.
 */
struct lib_load_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp_ns;
    __u64 addr;         /* Requested/returned mapping address */
    __u64 length;       /* Mapping size */
    __s32 prot;         /* Protection flags (PROT_READ|PROT_EXEC etc.) */
    __s32 flags;        /* Mapping flags (MAP_PRIVATE|MAP_FIXED etc.) */
    __s32 fd;           /* File descriptor (-1 for anonymous) */
    __u64 offset;       /* File offset */
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

/**
 * Tracepoint handler for sys_enter_mmap.
 *
 * mmap args:
 *   args[0] = addr
 *   args[1] = length
 *   args[2] = prot
 *   args[3] = flags
 *   args[4] = fd
 *   args[5] = offset
 *
 * We only care about mappings with PROT_EXEC, which indicates executable
 * code. This filters out data-only mappings (heap, stack, shared memory)
 * and focuses on library/code loads.
 */
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    /* Filter by target PID */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);

    if (!tpid || *tpid != pid)
        return 0;

    /* Only trace executable mappings */
    __s32 prot = (__s32)ctx->args[2];
    if (!(prot & PROT_EXEC))
        return 0;

    struct lib_load_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->pid = pid;
    evt->tid = (__u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->addr = ctx->args[0];
    evt->length = ctx->args[1];
    evt->prot = prot;
    evt->flags = (__s32)ctx->args[3];
    evt->fd = (__s32)ctx->args[4];
    evt->offset = ctx->args[5];

    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
