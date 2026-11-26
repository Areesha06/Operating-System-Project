# Results summary

Policies: 310 (10 baseline, 300 LLM).

## Breakage rate (source: real seccomp enforcement (results/enforcement.csv))

Percentage of enforced policies under which the program failed (killed by seccomp, non-zero exit, or failed correctness check). Policies with malformed JSON are not enforced; see Invalid output.

| condition   |   policies_enforced |   broken_pct_training |   broken_pct_heldout |
|:------------|--------------------:|----------------------:|---------------------:|
| Baseline    |                  10 |                     0 |                  100 |
| 3B / a      |                  31 |                   100 |                  100 |
| 3B / b      |                  50 |                    90 |                  100 |
| 3B / c      |                  50 |                    48 |                  100 |
| 8B / a      |                  50 |                   100 |                  100 |
| 8B / b      |                  50 |                    74 |                  100 |
| 8B / c      |                  50 |                    80 |                  100 |

### Held-out breakage by program (%)

| program    |   3B |   8B |   Baseline |
|:-----------|-----:|-----:|-----------:|
| cp         |  100 |  100 |        100 |
| find       |  100 |  100 |        100 |
| grep       |  100 |  100 |        100 |
| gzip       |  100 |  100 |        100 |
| mini_httpd |  100 |  100 |        100 |
| sort       |  100 |  100 |        100 |
| sqlite3    |  100 |  100 |        100 |
| tar        |  100 |  100 |        100 |
| worker     |  100 |  100 |        100 |
| xz         |  100 |  100 |        100 |

### Syscalls whose blocking killed the program (most frequent per source and run)

| model    | run_tested   | blocked_syscall   |   times |
|:---------|:-------------|:------------------|--------:|
| 3B       | heldout      | brk               |      30 |
| 3B       | heldout      | access            |      20 |
| 3B       | heldout      | rt_sigaction      |      13 |
| 3B       | heldout      | mprotect          |      12 |
| 3B       | heldout      | mkdirat           |       8 |
| 3B       | heldout      | getdents64        |       7 |
| 3B       | training     | brk               |      30 |
| 3B       | training     | access            |      20 |
| 3B       | training     | mprotect          |      12 |
| 3B       | training     | exit_group        |       8 |
| 3B       | training     | rseq              |       6 |
| 3B       | training     | arch_prctl        |       4 |
| 8B       | heldout      | brk               |      48 |
| 8B       | heldout      | rseq              |      28 |
| 8B       | heldout      | read              |      18 |
| 8B       | heldout      | access            |      10 |
| 8B       | heldout      | rt_sigaction      |      10 |
| 8B       | heldout      | geteuid           |       7 |
| 8B       | training     | brk               |      48 |
| 8B       | training     | rseq              |      28 |
| 8B       | training     | read              |      18 |
| 8B       | training     | access            |      10 |
| 8B       | training     | ioctl             |       6 |
| 8B       | training     | arch_prctl        |       5 |
| Baseline | heldout      | rt_sigaction      |       3 |
| Baseline | heldout      | getcwd            |       1 |
| Baseline | heldout      | getdents64        |       1 |
| Baseline | heldout      | geteuid           |       1 |
| Baseline | heldout      | mkdirat           |       1 |
| Baseline | heldout      | mremap            |       1 |

## Attack surface

High-risk list: config/high_risk.txt (Docker default seccomp profile).

| condition   |   policies |   mean_allowed |   min_allowed |   max_allowed |   mean_high_risk |   pct_with_high_risk |
|:------------|-----------:|---------------:|--------------:|--------------:|-----------------:|---------------------:|
| Baseline    |         10 |          27    |            19 |            38 |             0    |                 0    |
| 3B / a      |         31 |          23.35 |             5 |            57 |             0.16 |                16.13 |
| 3B / b      |         50 |          22.04 |            10 |            35 |             0    |                 0    |
| 3B / c      |         50 |          25.7  |            16 |            38 |             0    |                 0    |
| 8B / a      |         50 |          12.1  |             4 |            47 |             0.1  |                 6    |
| 8B / b      |         50 |          24.1  |            12 |            35 |             0    |                 0    |
| 8B / c      |         50 |          23.92 |            13 |            37 |             0    |                 0    |

### High-risk syscalls that appeared in policies

| condition   | name              |   policies |
|:------------|:------------------|-----------:|
| 3B / a      | clock_settime     |          2 |
| 3B / a      | reboot            |          1 |
| 3B / a      | umount2           |          2 |
| 8B / a      | clock_settime     |          1 |
| 8B / a      | open_by_handle_at |          1 |
| 8B / a      | umount2           |          2 |
| 8B / a      | unshare           |          1 |

## Invalid output (LLM generations)

malformed = no JSON allow-list could be extracted; hallucinated = not a Linux syscall name on any checked ABI; wrong architecture = a real Linux syscall on i386 or the generic (arm64/riscv) table but not on x86_64.

| condition   |   generations |   malformed_json_pct |   hallucinated_pct |   wrong_arch_pct |   mean_hallucinated |   mean_wrong_arch |
|:------------|--------------:|---------------------:|-------------------:|-----------------:|--------------------:|------------------:|
| 3B / a      |            50 |                   38 |                 56 |               50 |                5.4  |              0.88 |
| 3B / b      |            50 |                    0 |                  4 |                0 |                0.04 |              0    |
| 3B / c      |            50 |                    0 |                  0 |                0 |                0    |              0    |
| 8B / a      |            50 |                    0 |                 30 |               10 |                0.82 |              0.24 |
| 8B / b      |            50 |                    0 |                  0 |                0 |                0    |              0    |
| 8B / c      |            50 |                    0 |                  0 |                0 |                0    |              0    |

### Hallucinated names (most frequent)

| hallucinated   |   policies |
|:---------------|-----------:|
| fstatat        |         25 |
| wait           |         20 |
| killpg         |         12 |
| execv          |          8 |
| usleep         |          7 |
| pread          |          7 |
| pwrite         |          7 |
| execle         |          7 |
| fsyncfs        |          6 |
| newfstatat64   |          6 |
| newfstat       |          5 |
| seteuid        |          5 |
| setegid        |          5 |
| send           |          5 |
| recv           |          5 |
| futimens       |          4 |
| statat         |          4 |
| getrlimit64    |          4 |
| setrlimit64    |          4 |
| openat64       |          4 |
| execvpe        |          4 |
| futimensat     |          3 |
| newstat        |          3 |
| epoll_add      |          3 |
| exec           |          3 |

### Wrong-architecture names (most frequent)

| wrong_arch   |   policies |
|:-------------|-----------:|
| waitpid      |         20 |
| fstatat64    |          8 |
| umount       |          6 |
| ftruncate64  |          5 |
| sigaction    |          3 |
| stat64       |          3 |
| statfs64     |          3 |
| sigprocmask  |          2 |
| lock         |          1 |
| getresuid32  |          1 |
| getresgid32  |          1 |
| fcntl64      |          1 |
| fstatfs64    |          1 |
| truncate64   |          1 |

## Containment

The probe attempted 10 dangerous syscalls under every enforceable policy. Observed outcome matched the allow-list in 2910/2910 attempts.

| condition   |   probe_attempts |   reached_kernel_pct |   policies_letting_any_through_pct |
|:------------|-----------------:|---------------------:|-----------------------------------:|
| Baseline    |              100 |                  0   |                                  0 |
| 3B / a      |              310 |                  0   |                                  0 |
| 3B / b      |              500 |                  0   |                                  0 |
| 3B / c      |              500 |                  0   |                                  0 |
| 8B / a      |              500 |                  0.2 |                                  2 |
| 8B / b      |              500 |                  0   |                                  0 |
| 8B / c      |              500 |                  0   |                                  0 |

### Policies that let each probe syscall reach the kernel (count)

| syscall           |   Baseline |   3B / a |   3B / b |   3B / c |   8B / a |   8B / b |   8B / c |
|:------------------|-----------:|---------:|---------:|---------:|---------:|---------:|---------:|
| bpf               |          0 |        0 |        0 |        0 |        0 |        0 |        0 |
| init_module       |          0 |        0 |        0 |        0 |        0 |        0 |        0 |
| keyctl            |          0 |        0 |        0 |        0 |        0 |        0 |        0 |
| mount             |          0 |        0 |        0 |        0 |        0 |        0 |        0 |
| perf_event_open   |          0 |        0 |        0 |        0 |        0 |        0 |        0 |
| process_vm_writev |          0 |        0 |        0 |        0 |        0 |        0 |        0 |
| ptrace            |          0 |        0 |        0 |        0 |        0 |        0 |        0 |
| setns             |          0 |        0 |        0 |        0 |        0 |        0 |        0 |
| unshare           |          0 |        0 |        0 |        0 |        1 |        0 |        0 |
| userfaultfd       |          0 |        0 |        0 |        0 |        0 |        0 |        0 |

## Prompt style vs model size (H3)

Rows: prompt style (a = name only, b = trace summary, c = trace summary + descriptions). Columns: model. Breakage counts enforced policies only.

### Held-out breakage (%)

| prompt   |   3B |   8B |
|:---------|-----:|-----:|
| a        |  100 |  100 |
| b        |  100 |  100 |
| c        |  100 |  100 |

### Training breakage (%)

| prompt   |   3B |   8B |
|:---------|-----:|-----:|
| a        |  100 |  100 |
| b        |   90 |   74 |
| c        |   48 |   80 |

### Policies with hallucinated names (%)

| prompt   |   3B |   8B |
|:---------|-----:|-----:|
| a        |   56 |   30 |
| b        |    4 |    0 |
| c        |    0 |    0 |

### Malformed JSON (%)

| prompt   |   3B |   8B |
|:---------|-----:|-----:|
| a        |   38 |    0 |
| b        |    0 |    0 |
| c        |    0 |    0 |
