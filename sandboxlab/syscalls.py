"""Syscall knowledge used by every step.

Data files (all in config/, all generated or sourced, see README):
    syscalls_x86_64.json      x86_64 name -> number, from <asm/unistd_64.h>
    syscalls_other_arch.json  names that exist on OTHER Linux ABIs (32-bit x86 from <asm/unistd_32.h>,
                              and the generic table used by arm64/riscv from <asm-generic/unistd.h>)
                              but NOT on x86_64
    high_risk.txt             syscalls blocked by Docker's default seccomp profile
    syscall_descriptions.json one-line description per syscall, from the Linux man-pages (section 2)

Every name in an LLM policy is classified as exactly one of:
    valid         a real x86_64 syscall
    wrong_arch    a real Linux syscall, but not on x86_64 (e.g. stat64, socketcall, waitpid)
    hallucinated  not a Linux syscall on any of these ABIs (e.g. open_file, readfile)
Names are compared after trivial clean-up only (spaces, quotes, case, a "sys_"/"__NR_" prefix, "()").
"""
import json
import re
from functools import lru_cache

from . import paths


@lru_cache(maxsize=1)
def table() -> dict:
    """{name: number} for x86_64."""
    with open(paths.SYSCALL_TABLE, encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def other_arch() -> dict:
    """{name: [abi, ...]} for syscall names that exist on other Linux ABIs but not on x86_64."""
    with open(paths.SYSCALL_TABLE_OTHER_ARCH, encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def high_risk() -> dict:
    """{name: reason} from config/high_risk.txt."""
    out = {}
    with open(paths.HIGH_RISK, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, _, reason = line.partition("#")
            out[name.strip()] = reason.strip()
    return out


@lru_cache(maxsize=1)
def descriptions() -> dict:
    with open(paths.DESCRIPTIONS, encoding="utf-8") as f:
        return json.load(f)


def describe(name: str) -> str:
    return descriptions().get(name, "no description in the Linux man-pages")


def is_valid(name: str) -> bool:
    return name in table()


def is_wrong_arch(name: str) -> bool:
    return name not in table() and name in other_arch()


def is_high_risk(name: str) -> bool:
    return name in high_risk()


_PREFIX = re.compile(r"^(sys_|__nr_|nr_)", re.IGNORECASE)


def normalize(raw) -> str:
    """Trivial clean-up only: 'SYS_Read ' -> 'read', 'read()' -> 'read'.
    Spelling mistakes are NOT corrected."""
    if not isinstance(raw, str):
        return str(raw)
    name = raw.strip().strip("'\"`").strip()
    name = name.split("(")[0].strip()
    name = _PREFIX.sub("", name)
    return name.lower()


def classify(names) -> dict:
    """Split the names of one policy into valid / wrong_arch / hallucinated (+ duplicates, high_risk)."""
    seen, valid, wrong, halluc, dups = set(), [], [], [], []
    for raw in names:
        n = normalize(raw)
        if n in seen:
            dups.append(n)
            continue
        seen.add(n)
        if is_valid(n):
            valid.append(n)
        elif is_wrong_arch(n):
            wrong.append(n)
        else:
            halluc.append(n)
    return {
        "valid": valid,
        "wrong_arch": wrong,
        "hallucinated": halluc,
        "duplicates": dups,
        "high_risk": [n for n in valid if is_high_risk(n)],
    }
