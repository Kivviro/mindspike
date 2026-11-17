#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "sudo_watch.skel.h"

#define RED "\033[31m"
#define RESET "\033[0m"

static volatile sig_atomic_t running = 1;

static void handle_signal(int signal)
{
	(void)signal;
	running = 0;
}


struct event {
	__u32 pid;
	__u32 uid;
	__u32 syscall_type;

	char comm[16];
	char filename[256];
};

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct event *event = data;

	(void)ctx;

	if (size < sizeof(*event))
		return 0;

	printf(
        RED "warning:" RESET
        " sudo execution attempt\n"
        "          PID: %u\n"
        "          UID: %u\n"
        "          COMM: %s\n"
        "          FILE: %s\n"
        "          SYSCALL: %s\n\n",

        event->pid,
        event->uid,
        event->comm,
        event->filename,
        event->syscall_type == 0
            ? "execve"
            : "execveat"
    );

    fflush(stdout);

    return 0;
}

int main(void)
{
	struct sudo_watch_bpf *skel = NULL;

	struct bpf_link *execve_link = NULL;
	struct bpf_link *execveat_link = NULL;

	struct ring_buffer *rb = NULL;

	int err = 0;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	// open bpf object
	skel = sudo_watch_bpf__open();

	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF object\n");
		return EXIT_FAILURE;
	}

	err = sudo_watch_bpf__load(skel);

	if (err)
	{
		fprintf(stderr, "Failed to open BPF object: %d\n", err);
		goto cleanup;
	}

	execve_link = bpf_program_attach_tracepoin(skel->progs.trace_execve, 
		"syscalls", "sys_enter_execve");

	err = libbpf_get_error(execve_link);

	if (err)
	{
		execve_link = NULL;
		fprintf(stderr, "Failed to attach execve: %d\n", err);
		goto cleanup;
	}

	execve_link = bpf_program_attach_tracepoin(skel->progs.trace_execveat, 
		"syscalls", "sys_enter_execveat");

	err = libbpf_get_error(execve_link);

	if (err) 
	{
        execveat_link = NULL;
        fprintf(stderr, "Failed to attach execveat: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);

    if (!rb) 
    {
        fprintf(stderr, "Failed to create Ring Buffer\n");
        goto cleanup;
    }

    printf("sudo monitor started\n");
    printf("Press Ctrl+C to stop\n\n");

    while (running) 
    {
        err = ring_buffer__poll(rb, 250);

        if (err == -EINTR) 
        {
            err = 0;
            continue;
        }

        if (err < 0) 
        {
            fprintf(stderr, "Ring Buffer polling error: %d\n", err);
            break;
        }
    }

cleanup:

    ring_buffer__free(rb);

    bpf_link__destroy(execve_link);
    bpf_link__destroy(execveat_link);

    sudo_watch_bpf__destroy(skel);

    return err < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}