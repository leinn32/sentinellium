/**
 * process_monitor.bpf.c — Traces execve and ptrace syscalls.
 *
 * What:  Attaches to tracepoints for sys_enter_execve and sys_enter_ptrace
 *        to monitor process creation and debugging activity.
 *
 * Why:   Detects two critical RASP-related behaviors:
 *        1. Anti-debug ptrace self-attach: RASP SDKs call ptrace(PTRACE_TRACEME)
 *           on themselves to prevent debuggers from attaching. Monitoring this
 *           at the kernel level reveals the timing and frequency of these checks.
 *        2. Process spawning: Some RASP evasion techniques spawn helper processes
 *           or use fork+exec to perform checks outside the instrumented process.
 *
 * RASP:  Validates that anti-debug measures are active and reveals the RASP
 *        SDK's defensive process architecture. Invisible to userspace hooks
 *        that the target app might detect.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ARG_LEN 128
#define TASK_COMM_LEN 16

/* Event types for the process monitor. */
#define EVT_EXECVE  1
#define EVT_PTRACE  2

/**
 * Process event structure.
 * Uses a type discriminator to distinguish execve from ptrace events
 * in a single ring buffer stream.
 */
struct process_event {
    __u32 event_type;   /* EVT_EXECVE or EVT_PTRACE */
    __u32 pid;
    __u32 tid;
    __u64 timestamp_ns;
    char comm[TASK_COMM_LEN];

    /* execve fields */
    char filename[MAX_ARG_LEN];

    /* ptrace fields */
    __s64 ptrace_request;   /* PTRACE_TRACEME, PTRACE_ATTACH, etc. */
    __s32 ptrace_target_pid; /* PID being traced */
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
 * Trace execve calls from the target process.
 *
 * execve args:
 *   args[0] = filename (const char __user *)
 *   args[1] = argv (const char __user *const __user *)
 *   args[2] = envp (const char __user *const __user *)
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);

    if (!tpid || *tpid != pid)
        return 0;

    struct process_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->event_type = EVT_EXECVE;
    evt->pid = pid;
    evt->tid = (__u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    evt->timestamp_ns = bpf_ktime_get_ns();

    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), filename);
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    evt->ptrace_request = 0;
    evt->ptrace_target_pid = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/**
 * Trace ptrace calls — both from and targeting the monitored process.
 *
 * ptrace args:
 *   args[0] = request (PTRACE_TRACEME, PTRACE_ATTACH, etc.)
 *   args[1] = pid (target process)
 *   args[2] = addr
 *   args[3] = data
 *
 * We trace ptrace from the target PID (self-attach for anti-debug)
 * and also ptrace targeting the PID (external debugger attachment).
 */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);

    if (!tpid)
        return 0;

    __s32 ptrace_target = (__s32)ctx->args[1];

    /*
     * Trace if:
     * 1. The calling process is our target (self-ptrace for anti-debug)
     * 2. The ptrace target is our target PID (external debugger attaching)
     */
    if (*tpid != pid && (__u32)ptrace_target != *tpid)
        return 0;

    struct process_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->event_type = EVT_PTRACE;
    evt->pid = pid;
    evt->tid = (__u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->ptrace_request = (__s64)ctx->args[0];
    evt->ptrace_target_pid = ptrace_target;

    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    evt->filename[0] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
