#!/usr/bin/env python3
"""Enforce (proposal section 3, step 5): run every program under every policy with seccomp.

For each policy file in policies/baseline and policies/llm, and for each test
run (training, heldout), the program is executed in a fresh scratch directory
through enforce/bin/seccomp_launcher (libseccomp) with default action KILL_PROCESS (deny).

    passed = exit code 0, not killed, not timed out, and the run's `check` succeeded
    breakage = not passed

If the program dies with SIGSYS we re-run it once under strace with the launcher
in TRAP mode to find out WHICH syscall was blocked (strace prints
si_syscall=__NR_<name>). That name goes in the `blocked_syscall` column.

Policies whose LLM output could not be parsed (json_valid=false) are not run;
they get status "invalid_policy" and are reported under the Invalid output metric.

Results are appended to results/enforcement.csv. Re-running skips rows that
already exist, so an interrupted run can simply be restarted.

Usage:
    python3 enforce/run_enforcement.py                    # everything
    python3 enforce/run_enforcement.py --programs gzip --sources baseline
"""
import argparse
import csv
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, policy, strace_parser, workload  # noqa: E402

FIELDS = ["policy_file", "program", "source", "prompt", "repeat", "run_tested",
          "status", "passed", "exit_code", "signal", "blocked_syscall", "check_ok",
          "timed_out", "duration_s"]
OUT = paths.RESULTS / "enforcement.csv"


def all_policy_files(sources=None, programs=None):
    files = sorted(paths.POLICIES.glob("baseline/*/*.json")) + sorted(paths.POLICIES.glob("llm/*/*.json"))
    out = []
    for f in files:
        doc = policy.load_policy(f)
        if programs and doc.get("program") not in programs:
            continue
        if sources and doc.get("source") not in sources:
            continue
        out.append((f, doc))
    return out


def done_keys():
    if not OUT.exists():
        return set()
    with open(OUT, newline="") as fh:
        return {(r["policy_file"], r["run_tested"]) for r in csv.DictReader(fh)}


def diagnose(cfg, run_name, names_file):
    """Re-run under strace with TRAP mode and return the blocked syscall name."""
    with tempfile.NamedTemporaryFile(suffix=".strace", delete=False) as t:
        trace = t.name
    prefix = ["strace", "-f", "-o", trace, str(paths.LAUNCHER), "--mode", "trap", names_file, "--"]
    try:
        workload.run(cfg, run_name, prefix=prefix, timeout=60)
    except Exception:
        pass
    with open(trace, errors="replace") as fh:
        name = strace_parser.sigsys_syscall(fh)
    Path(trace).unlink(missing_ok=True)
    return name or "unknown"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--programs", nargs="*")
    ap.add_argument("--sources", nargs="*", help="e.g. baseline llama3.2:3b")
    ap.add_argument("--runs", nargs="*", default=["training", "heldout"])
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()

    if not paths.LAUNCHER.exists():
        sys.exit("launcher not built - run `make` in the repo root first")
    progs = workload.programs()
    done = done_keys()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    new_file = not OUT.exists()
    with open(OUT, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        if new_file:
            w.writeheader()
        for f, doc in all_policy_files(args.sources, args.programs):
            rel = f.relative_to(paths.ROOT).as_posix()
            prog = doc["program"]
            if prog not in progs:
                continue
            for run_name in args.runs:
                if (rel, run_name) in done:
                    continue
                row = {k: "" for k in FIELDS}
                row.update(policy_file=rel, program=prog, source=doc.get("source"), prompt=doc.get("prompt") or "",
                           repeat=doc.get("repeat", 0), run_tested=run_name)
                if not doc.get("json_valid", True):
                    row.update(status="invalid_policy")
                    w.writerow(row)
                    fh.flush()
                    continue
                with tempfile.NamedTemporaryFile("w", suffix=".policy", delete=False) as nf:
                    names_file = nf.name
                policy.write_names_file(policy.allowed_set(doc), names_file)
                prefix = [str(paths.LAUNCHER), "--mode", "kill", names_file, "--"]
                res = workload.run(progs[prog], run_name, prefix=prefix, timeout=args.timeout)
                blocked = diagnose(progs[prog], run_name, names_file) if res["signal"] == "SIGSYS" else ""
                Path(names_file).unlink(missing_ok=True)
                row.update(status="ran", passed=res["passed"], exit_code=res["exit_code"], signal=res["signal"],
                           blocked_syscall=blocked, check_ok=res["check_ok"], timed_out=res["timed_out"],
                           duration_s=res["duration_s"])
                w.writerow(row)
                fh.flush()
                mark = "PASS" if res["passed"] else f"BREAK ({res['signal'] or 'exit ' + str(res['exit_code'])}"
                mark += f" on {blocked})" if blocked else (")" if not res["passed"] else "")
                print(f"  {rel:<70} {run_name:<9} {mark}")
    print(f"results -> {OUT.relative_to(paths.ROOT)}")


if __name__ == "__main__":
    main()
