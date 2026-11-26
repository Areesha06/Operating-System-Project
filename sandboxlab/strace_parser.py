"""Parse `strace -f -o FILE` output.

Handles the line shapes strace produces:
    12345 openat(AT_FDCWD, "x", O_RDONLY) = 3
    12345 futex(0x7f.., FUTEX_WAIT, ...) <unfinished ...>      (counted here)
    12345 <... futex resumed>) = 0                              (skipped: same call)
    12345 --- SIGCHLD {si_signo=SIGCHLD, ...} ---               (signal, not a syscall)
    12345 +++ exited with 0 +++                                 (process exit)
    openat(...) = 3                                             (no pid: strace without -f)

Each syscall becomes an Event(pid, name, ret, line_no). A summary is
{name: count} in order of first appearance - this is what the baseline and
the LLM prompts are built from.
"""
import json
import re
from collections import OrderedDict
from dataclasses import dataclass, asdict
from pathlib import Path

_LINE = re.compile(
    r"^(?:\[pid\s+)?(?P<pid>\d+)?\]?\s*"            # optional pid
    r"(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+)?"           # optional timestamp (-t/-tt)
    r"(?P<name>[a-z_][a-z0-9_]*)\("                  # syscall name followed by "("
)
_RET = re.compile(r"\)\s+=\s+(?P<ret>.+)$")
_SIGSYS = re.compile(r"si_syscall=__NR_(?P<name>[a-z0-9_]+)")


@dataclass
class Event:
    pid: int
    name: str
    ret: str          # e.g. "3", "-1 ENOENT (No such file or directory)", "?" if unfinished/killed
    line_no: int

    def to_dict(self):
        return asdict(self)


def parse_lines(lines):
    events = []
    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        stripped = re.sub(r"^\d+\s+", "", line)
        if stripped.startswith(("<...", "---", "+++")):
            continue                              # resumed call, signal or exit marker
        m = _LINE.match(line)
        if not m:
            continue
        name = m.group("name")                    # unknown syscalls appear as syscall_0x1b6
        r = _RET.search(line)
        ret = r.group("ret").strip() if r else "?"
        pid = int(m.group("pid")) if m.group("pid") else 0
        events.append(Event(pid=pid, name=name, ret=ret, line_no=i))
    return events


def parse_file(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return parse_lines(f)


def summarize(events) -> "OrderedDict[str, int]":
    """{syscall: count} in order of first appearance."""
    out = OrderedDict()
    for e in events:
        out[e.name] = out.get(e.name, 0) + 1
    return out


def process_count(events) -> int:
    return len({e.pid for e in events})


def sigsys_syscall(lines):
    """From a trace recorded with the launcher in --mode trap, return the name
    of the syscall that seccomp blocked (strace prints si_syscall=__NR_x)."""
    for line in lines:
        m = _SIGSYS.search(line)
        if m:
            return m.group("name")
    return None


def write_summary(trace_file, out_file, program=None, run=None):
    events = parse_file(trace_file)
    summ = summarize(events)
    doc = {
        "program": program,
        "run": run,
        "trace_file": str(Path(trace_file).as_posix()),
        "total_calls": len(events),
        "unique_syscalls": len(summ),
        "processes_or_threads": process_count(events),
        "counts": summ,
    }
    Path(out_file).parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    return doc
