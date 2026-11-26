#!/usr/bin/env python3
"""Containment (proposal section 4): do harmless probe programs that attempt
forbidden syscalls get blocked? In other words: if an attacker hijacked program X,
could they make dangerous syscalls through X's policy?

The harmless escape probe (programs/src/escape_probe.c) is run under each
policy with the launcher in errno:1234 mode, so every blocked call fails with
the marker errno 1234 instead of killing the process. The probe reports, per
dangerous syscall, BLOCKED or REACHED_KERNEL.

The probe needs a few syscalls of its own just to start and print (loader,
write, exit_group). These "reporting" syscalls are taken from the probe's own
trace (data/probe/traces/attack.strace) minus the dangerous targets, and are
always allowed. So for each dangerous syscall the only thing that decides the
outcome is whether the POLICY allows it.

Two things are recorded per (policy, dangerous syscall):
    outcome  BLOCKED or REACHED_KERNEL, as observed by the probe under real seccomp
    matches  whether that equals what the allow-list says should happen (checks the
             enforcement itself - every row should be True)

Output: results/containment.csv
Usage:  python3 enforce/run_containment.py [--programs gzip ...]
"""
import argparse
import csv
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, policy, strace_parser, workload  # noqa: E402
from run_enforcement import all_policy_files  # noqa: E402

TARGETS = ["ptrace", "mount", "unshare", "setns", "bpf", "perf_event_open",
           "init_module", "keyctl", "process_vm_writev", "userfaultfd"]
OUT = paths.RESULTS / "containment.csv"


def reporting_set():
    trace = paths.DATA / "probe" / "traces" / "attack.strace"
    if not trace.exists():
        sys.exit("record the probe trace first: python3 tracing/record_traces.py")
    names = set(strace_parser.summarize(strace_parser.parse_file(trace)))
    return names - set(TARGETS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--programs", nargs="*")
    ap.add_argument("--sources", nargs="*")
    args = ap.parse_args()

    base = reporting_set()
    rows = []
    for f, doc in all_policy_files(args.sources, args.programs):
        if not doc.get("json_valid", True):
            continue
        allow = policy.allowed_set(doc)
        with tempfile.NamedTemporaryFile("w", suffix=".policy", delete=False) as nf:
            names_file = nf.name
        policy.write_names_file((allow & set(TARGETS)) | base, names_file)
        res = workload.run_probe(prefix=[str(paths.LAUNCHER), "--mode", "errno:1234", names_file, "--"])
        Path(names_file).unlink(missing_ok=True)
        got = {a["syscall"]: a["outcome"] for a in res["attempts"]}
        for t in TARGETS:
            expected = "REACHED_KERNEL" if t in allow else "BLOCKED"
            outcome = got.get(t, "NO_REPORT")
            rows.append({"policy_file": f.relative_to(paths.ROOT).as_posix(), "program": doc["program"],
                         "source": doc.get("source"), "prompt": doc.get("prompt") or "",
                         "repeat": doc.get("repeat", 0), "syscall": t,
                         "policy_allows": t in allow, "outcome": outcome, "expected": expected,
                         "matches": outcome == expected})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["policy_file"])
        w.writeheader()
        w.writerows(rows)
    ok = sum(r["matches"] for r in rows)
    leaks = [r for r in rows if r["outcome"] == "REACHED_KERNEL"]
    print(f"{ok}/{len(rows)} probe results match the policy (should be all)")
    print(f"{len(leaks)} dangerous calls reached the kernel because a policy allowed them")
    for r in leaks[:15]:
        print(f"   {r['policy_file']}: {r['syscall']}")
    print(f"results -> {OUT.relative_to(paths.ROOT)}")


if __name__ == "__main__":
    main()
