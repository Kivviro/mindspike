#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#define FILENAME_LEN 256

struct event {
	__u32 pid;
	__u32 uid;
	__u32 syscall_type;

	char comm[16];
	char filename[FILENAME_LEN];
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int is_sudo(char *filename)
{
	int base = 0;

#pragma unroll
	for (int i = 0; i < FILENAME_LEN; i++)
	{
		if (filename[i] == '\0')
			break;

		if (filename[i] == '/')
			base = i + 1;
	}

	return filename[base] == 's' && filename[base + 1] == 'u' && filename[base + 2] == 'd' && 
		filename[base + 3] == 'o' && filename[base + 4] == '\0';
}

// common event processing

static __always_inline int process_exec(const char *user_filename, __u32 syscall_type)
{
	struct event *event;
	char filename[FILENAME_LEN];

	long ret;
	ret = bpf_probe_read_user_str(filename, sizeof(filename), user_filename);

	if (ret <= 0)
		return 0;

	if (!is_sudo(filename))
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

	if (!event) return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	event->pid = pid_tgid >> 32;
	event->uid = (__u32)uid_gid;
	even->syscall_type = syscall_type;

	bpf_get_current_comm(event->comm, sizeof(event->comm));

	__builtin_memcpy(event->filename, filename, sizeof(event->filename));

	bpf_ringbuf_submit(event, 0);

	return 0;
}

// tracepoint: syscalls/sys_enter_execve
// execve(filename, argv, envp)
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[0];

	return process_exec(filename, 0);
}

// tracepoinf: syscalls/sys_enter_execveat
// execveat(dirfd, filename, argv, envp, flags)

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[1];

	return process_exec(filename, 1);
}

char LICENSE[] SEC("license") = "GPL";