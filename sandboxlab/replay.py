"""Replay a recorded trace against a policy without running the program.

This is the proposal's documented FALLBACK / SECONDARY method (section 8: "replaying
traces against the policy to count violations"). Real seccomp enforcement
(enforce/run_enforcement.py) is the primary method.

Approximation (state it in the report): replay assumes the program would make
the same syscalls in the same order under the filter. In kill mode the program
is considered dead at the first blocked call - real seccomp KILL_PROCESS kills
the whole thread group of the offending process. In errno mode real programs
may change behaviour after a failed call, which replay cannot predict, so
only kill-mode replay is used.
"""
from dataclasses import dataclass, field

from . import syscalls
from .policy import LAUNCH_SYSCALLS


@dataclass
class Decision:
    index: int
    pid: int
    name: str
    allowed: bool
    high_risk: bool


@dataclass
class ReplayResult:
    decisions: list = field(default_factory=list)
    first_block: int = -1             # index into decisions, -1 if nothing blocked
    survived: bool = True             # kill mode: no blocked call at all
    blocked_names: list = field(default_factory=list)       # unique, in order
    high_risk_admitted: list = field(default_factory=list)  # unique, in order

    @property
    def killed_by(self):
        return self.decisions[self.first_block].name if self.first_block >= 0 else None


def replay(events, allow, add_launch=True) -> ReplayResult:
    """events: list of strace_parser.Event; allow: iterable of valid syscall names."""
    allow = set(allow) | (set(LAUNCH_SYSCALLS) if add_launch else set())
    res = ReplayResult()
    seen_block, seen_risk = set(), set()
    for i, e in enumerate(events):
        ok = e.name in allow
        risky = syscalls.is_high_risk(e.name)
        res.decisions.append(Decision(i, e.pid, e.name, ok, risky))
        if not ok:
            if res.first_block < 0:
                res.first_block = i
                res.survived = False
            if e.name not in seen_block:
                seen_block.add(e.name)
                res.blocked_names.append(e.name)
        elif risky and e.name not in seen_risk:
            seen_risk.add(e.name)
            res.high_risk_admitted.append(e.name)
    return res
