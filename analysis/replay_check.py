#!/usr/bin/env python3
"""Replay one recorded trace against one policy and print the violations.

This is the proposal's fallback/secondary method (section 8: "replaying traces against
the policy to count violations"). It needs no seccomp, so it also works on Windows.

Usage:
    python analysis/replay_check.py --trace data/gzip/traces/heldout.strace \
                                    --policy policies/baseline/gzip/baseline.json
    python analysis/replay_check.py --trace ... --policy ... --show-all
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import policy, replay, strace_parser, syscalls  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", required=True, type=Path)
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--show-all", action="store_true", help="print every syscall decision")
    args = ap.parse_args()

    doc = policy.load_policy(args.policy)
    cls = syscalls.classify(doc.get("allow", []))
    events = strace_parser.parse_file(args.trace)
    res = replay.replay(events, cls["valid"])

    print(f"policy : {args.policy}  ({doc.get('source')}, prompt={doc.get('prompt')}, json_valid={doc.get('json_valid')})")
    print(f"trace  : {args.trace}  ({len(events)} calls)")
    print(f"allowed: {len(cls['valid'])} valid names, high-risk: {cls['high_risk'] or 'none'}")
    if cls["hallucinated"]:
        print(f"hallucinated names (not Linux syscalls): {cls['hallucinated']}")
    if cls["wrong_arch"]:
        print(f"wrong-architecture names (exist on other ABIs, not x86_64): {cls['wrong_arch']}")
    if args.show_all:
        for d in res.decisions:
            print(f"   {'ALLOW' if d.allowed else 'BLOCK'}  {d.name}{'  [HIGH RISK]' if d.high_risk else ''}")
    if res.survived:
        print("RESULT : program SURVIVES (no syscall in the trace is blocked)")
    else:
        d = res.decisions[res.first_block]
        print(f"RESULT : program KILLED at call #{d.index + 1}: {d.name} (pid {d.pid}) -> SIGSYS")
        print(f"         all syscalls the policy would block in this trace: {res.blocked_names}")
    if res.high_risk_admitted:
        print(f"WARNING: high-risk syscalls in the trace that the policy LETS THROUGH: {res.high_risk_admitted}")


if __name__ == "__main__":
    main()
