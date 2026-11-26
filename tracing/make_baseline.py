#!/usr/bin/env python3
"""The deterministic trace-to-profile BASELINE (proposal section 3, step 3).

Rule: allow exactly the syscalls that appear in the training trace; everything else is denied.

Writes: policies/baseline/<program>/baseline.json

Runs on any OS (it only reads data/<program>/summary_training.json).
Usage:  python3 tracing/make_baseline.py [--data DIR]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, policy  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=paths.DATA)
    ap.add_argument("--out", type=Path, default=paths.POLICIES / "baseline")
    args = ap.parse_args()

    n = 0
    for prog_dir in sorted(p for p in args.data.iterdir() if p.is_dir() and p.name != "probe"):
        summ_file = prog_dir / "summary_training.json"
        if not summ_file.exists():
            continue
        summ = json.loads(summ_file.read_text(encoding="utf-8"))
        doc = {
            "program": prog_dir.name,
            "source": "baseline",
            "prompt": None,
            "repeat": 0,
            "allow": list(summ["counts"].keys()),
            "json_valid": True,
            "extraction": "n/a",
            "raw_output": "",
            "note": "allow exactly the syscalls seen in the training trace (default deny)",
        }
        out = args.out / prog_dir.name / "baseline.json"
        policy.save_policy(doc, out)
        print(f"  {prog_dir.name:<11} {len(doc['allow']):>3} syscalls -> {out.relative_to(paths.ROOT).as_posix()}")
        n += 1
    print(f"wrote {n} baseline policies")


if __name__ == "__main__":
    main()
