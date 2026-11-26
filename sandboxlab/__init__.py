"""sandboxlab - shared library for the "Can Local LLMs Write Syscall Sandboxes?" project.

Modules (all pure Python, work on Windows and Linux unless noted):
    paths          where every folder lives (repo-relative, OS-independent)
    syscalls       x86_64 syscall table, other-architecture names, high-risk list,
                   descriptions, and classification of policy names
    strace_parser  turns `strace -f` output into events and summaries
    policy         load/save/validate allow-list policies, extract JSON from LLM text
    replay         replays a trace against a policy (the proposal's documented fallback
                   method for counting violations without running the program)
    workload       LINUX ONLY: runs a configured program under strace or the seccomp launcher
"""
