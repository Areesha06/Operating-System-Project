#!/usr/bin/env python3
"""Per-policy metrics from proposal section 4 (runs on Windows or Linux).

For every policy in policies/baseline and policies/llm:
  Invalid output   json_valid (malformed JSON = no allow-list could be extracted), extraction method,
                   n_hallucinated (+ names), n_wrong_arch (+ names), n_duplicates
  Attack surface   n_allowed (valid, unique x86_64 names), n_high_risk (+ names)
  Breakage (secondary method: replay of the recorded traces, proposal section 8 fallback)
                   replay_<run>_survives, replay_<run>_killed_by,
                   missing_<run> = syscalls the recorded run made that the policy does not allow
Real breakage from seccomp is in results/enforcement.csv (enforce/run_enforcement.py);
analysis/make_figures.py combines both.

Output: results/policy_metrics.csv
Usage:  python analysis/evaluate_policies.py
"""
import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, policy, replay, strace_parser, syscalls  # noqa: E402

OUT = paths.RESULTS / "policy_metrics.csv"
RUNS = ("training", "heldout")


def load_traces(data_dir):
    traces = {}
    for prog_dir in data_dir.iterdir():
        if not prog_dir.is_dir():
            continue
        for run in RUNS:
            f = prog_dir / "traces" / f"{run}.strace"
            if f.exists():
                traces[(prog_dir.name, run)] = strace_parser.parse_file(f)
    return traces


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=paths.DATA)
    args = ap.parse_args()

    traces = load_traces(args.data)
    files = sorted(paths.POLICIES.glob("baseline/*/*.json")) + sorted(paths.POLICIES.glob("llm/*/*.json"))
    if not files:
        sys.exit("no policies found - run tracing/make_baseline.py and harness/generate_policies.py first")
    rows = []
    for f in files:
        doc = policy.load_policy(f)
        prog = doc.get("program")
        cls = syscalls.classify(doc.get("allow", []))
        allow = set(cls["valid"])
        valid_json = bool(doc.get("json_valid", True))
        row = {
            "policy_file": f.relative_to(paths.ROOT).as_posix(), "program": prog, "source": doc.get("source", ""),
            "prompt": doc.get("prompt") or "", "repeat": doc.get("repeat", 0),
            "json_valid": valid_json, "extraction": doc.get("extraction", ""),
            "n_names": len(doc.get("allow", [])), "n_allowed": len(allow),
            "n_hallucinated": len(cls["hallucinated"]), "hallucinated": " | ".join(cls["hallucinated"]),
            "n_wrong_arch": len(cls["wrong_arch"]), "wrong_arch": " | ".join(cls["wrong_arch"]),
            "n_duplicates": len(cls["duplicates"]),
            "n_high_risk": len(cls["high_risk"]), "high_risk": " | ".join(cls["high_risk"]),
        }
        for run in RUNS:
            ev = traces.get((prog, run))
            if ev is None or not valid_json:
                row.update({f"replay_{run}_survives": "", f"replay_{run}_killed_by": "",
                            f"missing_{run}": "", f"missing_{run}_names": ""})
                continue
            res = replay.replay(ev, allow)
            needed = {e.name for e in ev} - allow - set(policy.LAUNCH_SYSCALLS)
            row.update({f"replay_{run}_survives": res.survived, f"replay_{run}_killed_by": res.killed_by or "",
                        f"missing_{run}": len(needed), f"missing_{run}_names": " | ".join(sorted(needed))})
        rows.append(row)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    n_llm = sum(r["source"] != "baseline" for r in rows)
    print(f"{len(rows)} policies evaluated ({len(rows) - n_llm} baseline, {n_llm} LLM) -> {OUT.relative_to(paths.ROOT).as_posix()}")


if __name__ == "__main__":
    main()
