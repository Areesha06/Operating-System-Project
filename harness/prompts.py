"""The three prompt styles (proposal section 3, step 4):

  (a) program name only
  (b) trace summary                         - program name + the syscalls recorded in the training
                                              run with strace -f (syscall: number of calls)
  (c) trace summary plus syscall descriptions - (b) + a one-line description of each syscall,
                                              taken from the Linux man-pages (config/syscall_descriptions.json)

All three styles share the same SYSTEM message and ask for the same JSON format,
so the only thing that changes between styles is the information given.
Only the TRAINING trace is ever shown; the held-out run is never shown.

Preview a prompt:  python harness/prompts.py gzip c
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, syscalls  # noqa: E402

SYSTEM = """You are a Linux security engineer who writes seccomp allow-lists.
A seccomp allow-list is the set of system calls a program is permitted to make.
Every system call NOT on the list is blocked and the program is killed if it makes one.

Rules:
1. Use exact Linux x86_64 system call names as in <asm/unistd_64.h>, for example: openat, newfstatat, exit_group.
2. The program must keep working in ALL of its normal uses, not only the one described.
3. Do NOT include system calls the program does not need for normal operation. Every extra system call is attack surface.
4. Reply with JSON only, in exactly this form:
{"allow": ["syscall_1", "syscall_2"], "notes": "one short sentence"}"""

STYLES = {
    "a": "program name only",
    "b": "trace summary",
    "c": "trace summary plus syscall descriptions",
}


def load_programs():
    with open(paths.PROGRAMS_CONFIG, encoding="utf-8") as f:
        return json.load(f)["programs"]


def load_summary(program, data_dir=paths.DATA):
    f = Path(data_dir) / program / "summary_training.json"
    with open(f, encoding="utf-8") as fh:
        return json.load(fh)


def build(style, program, data_dir=paths.DATA):
    """Return the user message for one generation."""
    if style not in STYLES:
        raise ValueError(f"unknown prompt style {style!r}")
    head = f"Program: {program}\n"
    if style == "a":
        return head + "\nWrite the seccomp allow-list for this program."

    summ = load_summary(program, data_dir)
    lines = []
    for name, count in summ["counts"].items():
        if style == "c":
            calls = "call" if count == 1 else "calls"
            lines.append(f"- {name} ({count} {calls}): {syscalls.describe(name)}")
        else:
            lines.append(f"- {name}: {count}")
    intro = ("The following system calls were recorded with `strace -f` during one normal run of this program"
             + (" (syscall: number of calls)" if style == "b" else "") + ":\n")
    return (head + "\n" + intro + "\n".join(lines)
            + "\n\nThis recording may not cover every normal use of the program."
            "\nWrite the seccomp allow-list for this program.")


if __name__ == "__main__":
    prog = sys.argv[1] if len(sys.argv) > 1 else "gzip"
    style = sys.argv[2] if len(sys.argv) > 2 else "c"
    print("=== SYSTEM ===\n" + SYSTEM + "\n\n=== USER ===\n" + build(style, prog))
