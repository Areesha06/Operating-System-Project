/*
 * seccomp_launcher.c - runs a program inside a seccomp allow-list (libseccomp).
 *
 * Usage:
 *   seccomp_launcher [--mode kill|trap|errno:N] POLICY_NAMES_FILE -- /abs/path/program [args...]
 *
 * POLICY_NAMES_FILE: one syscall name per line ('#' comments and blank lines ignored).
 * The Python side (sandboxlab/policy.py) writes this file from a policy JSON.
 *
 * Steps:
 *   1. seccomp_init(default_action)         - everything not added below gets the default action
 *   2. for each name: seccomp_syscall_resolve_name(name) -> number for the native architecture
 *      (x86_64); names libseccomp does not know are skipped and reported on stderr
 *   3. seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0)   - allow it
 *   4. seccomp_load(ctx)  - libseccomp sets PR_SET_NO_NEW_PRIVS (required to install a filter
 *      without root; it also stops the program from gaining privileges via setuid binaries)
 *      and installs the BPF filter. libseccomp also adds an architecture check, so syscalls
 *      made through a foreign ABI (e.g. 32-bit int 0x80) get the default action.
 *   5. execv(program) - the filter survives exec and is inherited by every thread and child,
 *      so `execve` itself must be allowed (added by the Python side, see docs/METHODOLOGY.md).
 *
 * Default actions (--mode):
 *   kill     SCMP_ACT_KILL_PROCESS : the whole process is killed with SIGSYS (main experiment, "deny")
 *   trap     SCMP_ACT_TRAP         : SIGSYS is delivered; under strace this shows which syscall was
 *                                    blocked (used only to diagnose breakage)
 *   errno:N  SCMP_ACT_ERRNO(N)     : the syscall fails with errno N (used by the containment probe)
 *
 * Build: gcc seccomp_launcher.c -lseccomp   (Ubuntu: sudo apt install libseccomp-dev)
 */
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint32_t parse_mode(const char *m) {
    if (strcmp(m, "kill") == 0) return SCMP_ACT_KILL_PROCESS;
    if (strcmp(m, "trap") == 0) return SCMP_ACT_TRAP;
    if (strncmp(m, "errno:", 6) == 0) return SCMP_ACT_ERRNO((uint16_t)atoi(m + 6));
    fprintf(stderr, "launcher: unknown mode '%s'\n", m);
    exit(2);
}

int main(int argc, char **argv) {
    uint32_t default_action = SCMP_ACT_KILL_PROCESS;
    int i = 1;
    if (i + 1 < argc && strcmp(argv[i], "--mode") == 0) {
        default_action = parse_mode(argv[i + 1]);
        i += 2;
    }
    if (i + 2 >= argc || strcmp(argv[i + 1], "--") != 0) {
        fprintf(stderr, "usage: %s [--mode kill|trap|errno:N] POLICY_NAMES_FILE -- /abs/program [args]\n", argv[0]);
        return 2;
    }
    const char *names_file = argv[i];
    char **prog_argv = &argv[i + 2];

    scmp_filter_ctx ctx = seccomp_init(default_action);
    if (ctx == NULL) { fprintf(stderr, "launcher: seccomp_init failed\n"); return 2; }

    FILE *f = fopen(names_file, "r");
    if (!f) { perror("launcher: open policy names file"); return 2; }
    char line[128];
    int allowed = 0;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, " \t\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;
        int nr = seccomp_syscall_resolve_name(line);
        if (nr == __NR_SCMP_ERROR) {
            fprintf(stderr, "launcher: unknown syscall '%s' skipped\n", line);
            continue;
        }
        int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0);
        if (rc != 0) {
            fprintf(stderr, "launcher: cannot allow '%s' (%s)\n", line, strerror(-rc));
            continue;
        }
        allowed++;
    }
    fclose(f);

    int rc = seccomp_load(ctx);
    seccomp_release(ctx);
    if (rc != 0) { fprintf(stderr, "launcher: seccomp_load failed (%s)\n", strerror(-rc)); return 2; }

    execv(prog_argv[0], prog_argv);
    /* only reached if execve was allowed but failed, e.g. wrong path */
    perror("launcher: execv");
    return 127;
}
