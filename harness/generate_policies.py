#!/usr/bin/env python3
"""LLM policies (proposal section 3, step 4): generate allow-lists with local models via Ollama.

Grid (proposal scale): 10 programs x 3 prompt styles (a, b, c) x 2 models x 5 repeats = 300 generations.

Each generation is saved as
    policies/llm/<program>/<model>__p<style>__r<repeat>.json
and logged (timing, tokens, validity) in results/generation_log_<model>.csv
(one log per model, so two machines can run the two models without git conflicts).
containing the raw model output, the extracted allow-list, json_valid, the extraction
method and timing. Files that already exist are SKIPPED, so an interrupted run can be
restarted with the same command and continues where it stopped.

Sampling: temperature 0.7, seed = repeat number (0..4). At temperature 0 every repeat would
give the same answer and the 5 repeats would measure nothing; a fixed seed per repeat keeps
the whole grid reproducible.

Examples:
    python harness/generate_policies.py --dry-run                     # show the plan and one prompt
    python harness/generate_policies.py --models llama3.1:8b          # one model on this machine
    python harness/generate_policies.py --models llama3.2:3b          # the other model on another machine
"""
import argparse
import csv
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, policy  # noqa: E402
import prompts  # noqa: E402
import ollama_client  # noqa: E402

LOG_FIELDS = ["model", "program", "prompt", "repeat", "total_s", "load_s", "prompt_tokens",
              "output_tokens", "gen_s", "json_valid", "extraction", "n_names"]


def safe(model):
    return model.replace(":", "-").replace("/", "_")


def plan(args):
    jobs = []
    for model in args.models:
        for rep in range(args.repeats):
            for prog in args.programs:
                for style in args.prompts:
                    jobs.append((model, rep, prog, style))
    return jobs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models", nargs="+", default=["llama3.2:3b", "llama3.1:8b"])
    ap.add_argument("--prompts", nargs="+", default=["a", "b", "c"], choices=["a", "b", "c"])
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--programs", nargs="+", default=None, help="default: all in config/programs.json")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--host", default=ollama_client.DEFAULT_HOST)
    ap.add_argument("--out", type=Path, default=paths.POLICIES / "llm")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    args.programs = args.programs or list(prompts.load_programs())

    missing = [p for p in args.programs if not (paths.DATA / p / "summary_training.json").exists()]
    if missing and any(s in ("b", "c") for s in args.prompts):
        sys.exit(f"training summaries missing for {missing} - run tracing/record_traces.py first (and pull data/)")

    jobs = plan(args)
    todo = []
    for job in jobs:
        model, rep, prog, style = job
        out = args.out / prog / f"{safe(model)}__p{style}__r{rep}.json"
        if not out.exists():
            todo.append((job, out))
    print(f"{len(jobs)} generations in plan, {len(jobs) - len(todo)} already done, {len(todo)} to run")

    if args.dry_run:
        print("\n--- example prompt (style c) ---\n" + prompts.SYSTEM + "\n\n" + prompts.build("c", args.programs[0]))
        return
    try:
        have = ollama_client.list_models(args.host)
    except ollama_client.OllamaError as e:
        sys.exit(str(e))
    absent = [m for m in args.models if m not in have and m + ":latest" not in have]
    if absent:
        sys.exit(f"models not pulled: {absent}. Run: ollama pull {absent[0]}")

    paths.RESULTS.mkdir(parents=True, exist_ok=True)
    logs = {}
    for m in args.models:
        f = paths.RESULTS / f"generation_log_{safe(m)}.csv"
        new_log = not f.exists()
        fh = open(f, "a", newline="", encoding="utf-8")
        w = csv.DictWriter(fh, fieldnames=LOG_FIELDS)
        if new_log:
            w.writeheader()
        logs[m] = (fh, w)
    try:
        t_start = time.time()
        for i, ((model, rep, prog, style), out) in enumerate(todo, 1):
            user = prompts.build(style, prog)
            t0 = time.time()
            try:
                r = ollama_client.chat(model, prompts.SYSTEM, user, temperature=args.temperature, seed=rep,
                                       host=args.host)
            except ollama_client.OllamaError as e:
                sys.exit(str(e))
            wall = round(time.time() - t0, 2)
            names, how = policy.extract_allow_list(r["text"])
            doc = {
                "program": prog, "source": model, "prompt": style, "repeat": rep,
                "allow": names or [], "json_valid": names is not None, "extraction": how,
                "raw_output": r["text"], "temperature": args.temperature, "seed": rep, "wall_s": wall,
                **{k: r[k] for k in ("total_s", "load_s", "prompt_tokens", "output_tokens", "gen_s")},
                "system_prompt": prompts.SYSTEM, "user_prompt": user,
            }
            policy.save_policy(doc, out)
            fh, w = logs[model]
            w.writerow({"model": model, "program": prog, "prompt": style, "repeat": rep,
                        **{k: r[k] for k in ("total_s", "load_s", "prompt_tokens", "output_tokens", "gen_s")},
                        "json_valid": doc["json_valid"], "extraction": how, "n_names": len(doc["allow"])})
            fh.flush()
            eta = (time.time() - t_start) / i * (len(todo) - i)
            print(f"[{i}/{len(todo)}] {model:<12} {prog:<10} p{style} r{rep}  {wall:6.1f}s  "
                  f"valid={doc['json_valid']!s:<5} n={len(doc['allow']):<3} ETA {eta/60:5.1f} min")
    finally:
        for fh, _ in logs.values():
            fh.close()


if __name__ == "__main__":
    main()
