/**
 * file_monitor.bpf.c — Traces open/openat syscalls for the target process.
 *
 * What:  Attaches to tracepoint/syscalls/sys_enter_openat to monitor all file
 *        access by the target PID.
 *
 * Why:   Catches file access that Frida hooks might miss if the app uses raw
 *        syscalls instead of libc wrappers. This is a common anti-Frida
 *        technique: apps call syscall(__NR_openat, ...) directly to bypass
 *        any Interceptor.attach on libc's open/openat.
 *
 * RASP:  Provides a tamper-resistant monitoring layer that validates what the
 *        Frida agent reports. eBPF programs run in kernel space and are
 *        invisible to userspace integrity checks.
 *
 * Ring buffer is used instead of perf buffer because:
 *   - Lower overhead (no per-CPU buffer management)
 *   - No event loss under moderate load (back-pressure instead of drop)
 *   - Simpler consumer API
 *   - Requires kernel >= 5.8
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH_LEN 256
#define TASK_COMM_LEN 16

/**
 * Event structure passed to userspace via ring buffer.
 * Keep it compact to minimize ring buffer pressure.
 */
struct file_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp_ns;
    __s32 flags;
    char filename[MAX_PATH_LEN];
    char comm[TASK_COMM_LEN];
};

/**
 * Ring buffer map for sending events to userspace.
 * 256KB is sufficient for typical file monitoring workloads.
 * Ring buffer auto-handles back-pressure, unlike perf buffers which
 * silently drop events when the consumer falls behind.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/**
 * Configuration map: stores the target PID to filter on.
 * Using an array map with a single element for simplicity.
 * The loader sets this before attaching the probe.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

/**
 * Tracepoint handler for sys_enter_openat.
 *
 * Tracepoint args for openat:
 *   args[0] = dfd (directory file descriptor, AT_FDCWD = -100)
 *   args[1] = filename (const char __user *)
 *   args[2] = flags
 *   args[3] = mode
 *
 * We filter by PID to avoid flooding with system-wide file access events.
 * On a typical Android device, system services generate thousands of
 * openat calls per second.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    /* Filter by target PID */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);

    if (!tpid || *tpid != pid)
        return 0;

    /* Reserve space in the ring buffer */
    struct file_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    /* Fill event fields */
    evt->pid = pid;
    evt->tid = (__u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->flags = (__s32)ctx->args[2];

    /* Read filename from userspace — may fault if pointer is invalid */
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), filename);

    /* Read process/thread name */
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    /* Submit the event to userspace */
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
