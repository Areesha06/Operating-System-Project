/*
 * escape_probe.c - HARMLESS "jailbreak" probe used for the containment check.
 *
 * Imagine an attacker has taken over a jailed program. This probe tries the
 * dangerous syscalls such an attacker would want. Every call is made with
 * deliberately INVALID arguments, so even when it reaches the kernel it fails
 * (EFAULT/EINVAL/EBADF/...) and changes nothing - safe to run even as root.
 *
 * seccomp checks the syscall NUMBER before the kernel looks at arguments, so:
 *   - if the filter blocks the call   -> we get the marker errno 1234 (BLOCKED)
 *   - if the filter lets it through    -> we get some other result (REACHED_KERNEL)
 * (run_containment.py runs this under the launcher in "errno:1234" mode.)
 *
 * Output: one JSON object per line, e.g. {"syscall":"ptrace","outcome":"BLOCKED","errno":1234}
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define JAIL_ERRNO 1234

static void try_call(const char *name, long ret) {
    int e = errno;
    const char *outcome = (ret == -1 && e == JAIL_ERRNO) ? "BLOCKED" : "REACHED_KERNEL";
    printf("{\"syscall\":\"%s\",\"outcome\":\"%s\",\"ret\":%ld,\"errno\":%d}\n",
           name, outcome, ret, ret == -1 ? e : 0);
    fflush(stdout);
}

int main(void) {
    errno = 0; try_call("ptrace",            syscall(SYS_ptrace, -1L, 0L, 0L, 0L));        /* invalid request  -> EIO      */
    errno = 0; try_call("mount",             syscall(SYS_mount, 0L, 0L, 0L, 0L, 0L));      /* NULL target      -> EFAULT   */
    errno = 0; try_call("unshare",           syscall(SYS_unshare, -1L));                   /* invalid flags    -> EINVAL   */
    errno = 0; try_call("setns",             syscall(SYS_setns, -1L, 0L));                 /* bad fd           -> EBADF    */
    errno = 0; try_call("bpf",               syscall(SYS_bpf, -1L, 0L, 0L));               /* invalid command  -> EINVAL   */
    errno = 0; try_call("perf_event_open",   syscall(SYS_perf_event_open, 0L, 0L, -1L, -1L, 0L)); /* NULL attr -> EFAULT */
    errno = 0; try_call("init_module",       syscall(SYS_init_module, 0L, 0L, 0L));        /* NULL image       -> EFAULT/EPERM */
    errno = 0; try_call("keyctl",            syscall(SYS_keyctl, -1L, 0L, 0L, 0L, 0L));    /* invalid op       -> EOPNOTSUPP */
    errno = 0; try_call("process_vm_writev", syscall(SYS_process_vm_writev, -1L, 0L, 0L, 0L, 0L, 0L)); /* bad pid -> ESRCH */
    errno = 0; try_call("userfaultfd",       syscall(SYS_userfaultfd, -1L));               /* invalid flags    -> EINVAL   */
    return 0;
}
