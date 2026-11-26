#!/usr/bin/env python3
"""Generate the syscall name tables from the Linux kernel headers of THIS machine.

Writes:
    config/syscalls_x86_64.json      {name: number} from <asm/unistd_64.h>
    config/syscalls_other_arch.json  {name: [abi, ...]} for names that are real Linux syscalls on
                                     another ABI but do NOT exist on x86_64:
                                       "i386"    from <asm/unistd_32.h>      (32-bit x86)
                                       "generic" from <asm-generic/unistd.h> (arm64, riscv, ...)
These two tables let the evaluation separate "wrong architecture" names from
"hallucinated" names (proposal section 4, Invalid output).

Needs: sudo apt install linux-libc-dev   (normally already installed)
Usage: python3 tracing/gen_syscall_table.py
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths  # noqa: E402

X86_64 = ["/usr/include/x86_64-linux-gnu/asm/unistd_64.h", "/usr/include/asm/unistd_64.h"]
I386 = ["/usr/include/x86_64-linux-gnu/asm/unistd_32.h", "/usr/include/asm/unistd_32.h"]
GENERIC = ["/usr/include/asm-generic/unistd.h"]
NOT_SYSCALLS = {"syscalls", "arch_specific_syscall"}   # counters/markers in the headers, not syscalls


def first_existing(candidates):
    return next((p for p in candidates if Path(p).exists()), None)


def parse(header):
    out = {}
    for line in open(header, encoding="utf-8", errors="replace"):
        m = re.match(r"#define __NR_(\w+)\s+(\d+)", line)
        if m and m.group(1) not in NOT_SYSCALLS:
            out[m.group(1)] = int(m.group(2))
    return out


def main():
    h64 = first_existing(X86_64)
    if not h64:
        sys.exit("asm/unistd_64.h not found - run: sudo apt install linux-libc-dev")
    x86_64 = dict(sorted(parse(h64).items(), key=lambda kv: kv[1]))
    paths.SYSCALL_TABLE.write_text(json.dumps(x86_64, indent=1), encoding="utf-8")
    print(f"{len(x86_64)} x86_64 syscalls from {h64}")

    other = {}
    for abi, candidates in (("i386", I386), ("generic", GENERIC)):
        h = first_existing(candidates)
        if not h:
            print(f"warning: no header for {abi}; wrong-architecture detection will miss those names")
            continue
        names = parse(h)
        for n in names:
            if n not in x86_64:
                other.setdefault(n, []).append(abi)
        print(f"{len(names)} {abi} syscalls from {h}")
    other = dict(sorted(other.items()))
    paths.SYSCALL_TABLE_OTHER_ARCH.write_text(json.dumps(other, indent=1), encoding="utf-8")
    print(f"{len(other)} names exist on other ABIs but not on x86_64 -> {paths.SYSCALL_TABLE_OTHER_ARCH.name}")


if __name__ == "__main__":
    main()
