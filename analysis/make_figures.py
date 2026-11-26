#!/usr/bin/env python3
"""Figures and summary tables for the four metrics in proposal section 4 (runs on any OS).

Inputs : results/policy_metrics.csv  (analysis/evaluate_policies.py)
         results/enforcement.csv     (enforce/run_enforcement.py) - primary source for breakage.
                                     If it is missing, breakage falls back to replay predictions from
                                     policy_metrics.csv and every output says so (proposal section 8).
         results/containment.csv     (enforce/run_containment.py)
Outputs: results/figures/fig1_breakage.png         breakage on the training and held-out run
         results/figures/fig2_attack_surface.png   allowed syscalls, high-risk syscalls
         results/figures/fig3_invalid_output.png   malformed JSON, hallucinated names, wrong-architecture names
         results/figures/fig4_containment.png      dangerous probe syscalls that reached the kernel
         results/figures/fig5_prompt_vs_model.png  the same metrics split by prompt style and model (H3)
         results/summary.md                        every number behind the figures, as tables

A "condition" is either the baseline or one model + prompt style, e.g. "8B / c".
Breakage counts only policies that could be enforced; policies with malformed JSON are
reported under Invalid output instead.

Usage: python analysis/make_figures.py
"""
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths  # noqa: E402

C1, C2, C3 = "#2a78d6", "#eb6834", "#1baf7a"     # categorical colours, fixed order
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED,
    "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.grid.axis": "y", "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.axisbelow": True, "legend.frameon": False, "figure.dpi": 150,
})


def model_label(src):
    s = str(src).lower()
    if s == "baseline":
        return "Baseline"
    for tag in ("1b", "3b", "7b", "8b", "13b"):
        if tag in s:
            return tag.upper()
    return str(src)


def cond(row):
    m = model_label(row["source"])
    return m if m == "Baseline" else f"{m} / {row['prompt']}"


def ordered(conds):
    return sorted(set(conds), key=lambda c: (0, "", "") if c == "Baseline" else (1, c.split(" / ")[0], c.split(" / ")[-1]))


def truthy(series):
    return series.astype(str).str.lower().eq("true")


def bars(ax, labels, values, color, fmt="{:.0f}", offset=0.0, width=0.8, label=None):
    xs = [i + offset for i in range(len(labels))]
    ax.bar(xs, values, width=width, color=color, label=label, edgecolor="white", linewidth=1)
    for x, v in zip(xs, values):
        if pd.notna(v):
            ax.text(x, v, fmt.format(v), ha="center", va="bottom", fontsize=8, color=INK)


def save(fig, name):
    paths.FIGURES.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(paths.FIGURES / name, bbox_inches="tight")
    plt.close(fig)
    print(f"  figure  -> results/figures/{name}")


def md_table(df, index=True):
    return df.to_markdown(index=index)


def main():
    pm_file = paths.RESULTS / "policy_metrics.csv"
    if not pm_file.exists():
        sys.exit("results/policy_metrics.csv not found - run analysis/evaluate_policies.py first")
    pm = pd.read_csv(pm_file)
    for col in ("hallucinated", "wrong_arch", "high_risk", "prompt"):
        pm[col] = pm[col].fillna("").astype(str)        # empty name lists are read as NaN otherwise
    pm["condition"] = pm.apply(cond, axis=1)
    pm["model"] = pm["source"].map(model_label)
    pm["valid"] = truthy(pm["json_valid"])
    conds = ordered(pm["condition"])
    md = ["# Results summary", "",
          f"Policies: {len(pm)} ({int((pm['source'] == 'baseline').sum())} baseline, "
          f"{int((pm['source'] != 'baseline').sum())} LLM).", ""]

    # ------------------------------------------------------------ breakage
    enf_file = paths.RESULTS / "enforcement.csv"
    if enf_file.exists():
        enf = pd.read_csv(enf_file)
        enf = enf[enf["status"] == "ran"].merge(pm[["policy_file", "condition", "model"]], on="policy_file")
        enf["broken"] = ~truthy(enf["passed"])
        method = "real seccomp enforcement (results/enforcement.csv)"
    else:
        rows = []
        for _, r in pm[pm["valid"]].iterrows():
            for run in ("training", "heldout"):
                v = str(r.get(f"replay_{run}_survives", "")).lower()
                if v in ("true", "false"):
                    rows.append({"policy_file": r["policy_file"], "program": r["program"], "condition": r["condition"],
                                 "model": r["model"], "prompt": r["prompt"], "run_tested": run,
                                 "broken": v == "false", "blocked_syscall": r.get(f"replay_{run}_killed_by", "")})
        enf = pd.DataFrame(rows)
        method = "REPLAY of recorded traces (secondary method; results/enforcement.csv not found)"
    brk = (enf.pivot_table(index="condition", columns="run_tested", values="broken", aggfunc="mean") * 100
           ).reindex(index=conds, columns=[c for c in ("training", "heldout") if c in set(enf["run_tested"])])
    n_enf = enf.groupby("condition")["policy_file"].nunique().reindex(conds)

    fig, ax = plt.subplots(figsize=(max(6, 1.0 * len(conds) + 2), 3.8))
    bars(ax, conds, brk.get("training", pd.Series(index=conds, dtype=float)).values, C1, offset=-0.2, width=0.38, label="Training run")
    bars(ax, conds, brk.get("heldout", pd.Series(index=conds, dtype=float)).values, C2, offset=0.2, width=0.38, label="Held-out run")
    ax.set_xticks(range(len(conds)), conds)
    ax.set_ylabel("Runs broken (%)")
    ax.set_ylim(0, 112)
    ax.set_title(f"Fig. 1  Breakage rate ({'seccomp enforcement' if enf_file.exists() else 'REPLAY - secondary method'})",
                 fontsize=10, loc="left")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncols=2)
    save(fig, "fig1_breakage.png")

    t = pd.DataFrame({"policies_enforced": n_enf}).join(brk.round(1).add_prefix("broken_pct_"))
    md += [f"## Breakage rate (source: {method})", "",
           "Percentage of enforced policies under which the program failed (killed by seccomp, non-zero exit, "
           "or failed correctness check). Policies with malformed JSON are not enforced; see Invalid output.", "",
           md_table(t), ""]
    per_prog = (enf[enf["run_tested"] == "heldout"]
                .assign(group=lambda d: d["model"])
                .pivot_table(index="program", columns="group", values="broken", aggfunc="mean") * 100).round(1)
    md += ["### Held-out breakage by program (%)", "", md_table(per_prog), ""]
    killed = enf[enf["broken"] & enf["blocked_syscall"].notna() & (enf["blocked_syscall"].astype(str) != "")]
    if not killed.empty:
        top = (killed.groupby(["model", "run_tested", "blocked_syscall"]).size().rename("times").reset_index()
               .sort_values(["model", "run_tested", "times"], ascending=[True, True, False])
               .groupby(["model", "run_tested"]).head(6))
        md += ["### Syscalls whose blocking killed the program (most frequent per source and run)", "",
               md_table(top, index=False), ""]

    # ------------------------------------------------------------ attack surface
    v = pm[pm["valid"]]
    att = v.groupby("condition").agg(policies=("policy_file", "count"),
                                     mean_allowed=("n_allowed", "mean"), min_allowed=("n_allowed", "min"),
                                     max_allowed=("n_allowed", "max"), mean_high_risk=("n_high_risk", "mean"),
                                     pct_with_high_risk=("n_high_risk", lambda s: 100 * (s > 0).mean())
                                     ).reindex(ordered(v["condition"]))
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(max(8, 1.6 * len(att) + 2), 3.6))
    bars(a1, att.index, att["mean_allowed"].values, C1, "{:.1f}")
    a1.set_xticks(range(len(att)), att.index, rotation=30, ha="right")
    a1.set_title("Allowed syscalls per policy (mean)", fontsize=10, loc="left")
    bars(a2, att.index, att["mean_high_risk"].values, C1, "{:.2f}")
    a2.set_xticks(range(len(att)), att.index, rotation=30, ha="right")
    a2.set_title("High-risk syscalls allowed per policy (mean)", fontsize=10, loc="left")
    fig.suptitle("Fig. 2  Attack surface", fontsize=10, x=0.01, ha="left")
    save(fig, "fig2_attack_surface.png")
    hr_names = (v.loc[v["n_high_risk"] > 0, ["condition", "high_risk"]].assign(name=lambda d: d["high_risk"].str.split(" | ", regex=False))
                .explode("name").groupby(["condition", "name"]).size().rename("policies").reset_index())
    md += ["## Attack surface", "", "High-risk list: config/high_risk.txt (Docker default seccomp profile).", "",
           md_table(att.round(2)), ""]
    if not hr_names.empty:
        md += ["### High-risk syscalls that appeared in policies", "", md_table(hr_names, index=False), ""]

    # ------------------------------------------------------------ invalid output (LLM only)
    llm = pm[pm["source"] != "baseline"]
    if not llm.empty:
        inv = llm.groupby("condition").agg(
            generations=("policy_file", "count"),
            malformed_json_pct=("valid", lambda s: 100 * (1 - s.mean())),
            hallucinated_pct=("n_hallucinated", lambda s: 100 * (s > 0).mean()),
            wrong_arch_pct=("n_wrong_arch", lambda s: 100 * (s > 0).mean()),
            mean_hallucinated=("n_hallucinated", "mean"),
            mean_wrong_arch=("n_wrong_arch", "mean")).reindex(ordered(llm["condition"]))
        fig, axs = plt.subplots(1, 3, figsize=(max(10, 2.2 * len(inv) + 2), 3.6))
        for ax, col, title in zip(axs, ["malformed_json_pct", "hallucinated_pct", "wrong_arch_pct"],
                                  ["Malformed JSON (% of generations)", "Policies with >=1 hallucinated name (%)",
                                   "Policies with >=1 wrong-architecture name (%)"]):
            bars(ax, inv.index, inv[col].values, C3, "{:.0f}%")
            ax.set_xticks(range(len(inv)), inv.index, rotation=30, ha="right")
            ax.set_ylim(0, 108)
            ax.set_title(title, fontsize=9, loc="left")
        fig.suptitle("Fig. 3  Invalid output", fontsize=10, x=0.01, ha="left")
        save(fig, "fig3_invalid_output.png")
        md += ["## Invalid output (LLM generations)", "",
               "malformed = no JSON allow-list could be extracted; hallucinated = not a Linux syscall name on any "
               "checked ABI; wrong architecture = a real Linux syscall on i386 or the generic (arm64/riscv) table "
               "but not on x86_64.", "", md_table(inv.round(2)), ""]
        for col, label in (("hallucinated", "Hallucinated names"), ("wrong_arch", "Wrong-architecture names")):
            names = (llm[llm[f"n_{col}"] > 0][col].str.split(" | ", regex=False).explode().value_counts().head(25))
            if not names.empty:
                md += [f"### {label} (most frequent)", "", md_table(names.rename("policies").to_frame()), ""]

    # ------------------------------------------------------------ containment
    cont_file = paths.RESULTS / "containment.csv"
    if cont_file.exists():
        c = pd.read_csv(cont_file).merge(pm[["policy_file", "condition"]], on="policy_file")
        c["reached"] = c["outcome"].eq("REACHED_KERNEL")
        ct = c.groupby("condition").agg(probe_attempts=("syscall", "count"),
                                        reached_kernel_pct=("reached", lambda s: 100 * s.mean())
                                        ).reindex(ordered(c["condition"]))
        any_through = c.groupby(["condition", "policy_file"])["reached"].any().groupby("condition").mean() * 100
        ct["policies_letting_any_through_pct"] = any_through.reindex(ct.index)
        fig, ax = plt.subplots(figsize=(max(6, 1.0 * len(ct) + 2), 3.6))
        bars(ax, ct.index, ct["reached_kernel_pct"].values, C2, "{:.1f}%")
        ax.set_xticks(range(len(ct)), ct.index)
        ax.set_ylabel("Probe syscalls reaching the kernel (%)")
        ax.set_ylim(0, max(10, ct["reached_kernel_pct"].max() * 1.25))
        ax.set_title("Fig. 4  Containment: dangerous probe syscalls NOT blocked (lower is better)", fontsize=10, loc="left")
        save(fig, "fig4_containment.png")
        by_sys = c.pivot_table(index="syscall", columns="condition", values="reached", aggfunc="sum").reindex(
            columns=ordered(c["condition"]))
        md += ["## Containment", "",
               f"The probe attempted {c['syscall'].nunique()} dangerous syscalls under every enforceable policy. "
               f"Observed outcome matched the allow-list in {int(c['matches'].sum())}/{len(c)} attempts.", "",
               md_table(ct.round(1)), "", "### Policies that let each probe syscall reach the kernel (count)", "",
               md_table(by_sys.fillna(0).astype(int)), ""]

    # ------------------------------------------------------------ H3: prompt style vs model size
    if not llm.empty:
        held = enf[enf["run_tested"] == "heldout"][["policy_file", "broken"]].rename(columns={"broken": "heldout_broken"})
        train = enf[enf["run_tested"] == "training"][["policy_file", "broken"]].rename(columns={"broken": "training_broken"})
        h = llm.merge(held, on="policy_file", how="left").merge(train, on="policy_file", how="left")
        h["malformed"] = ~h["valid"]
        h["has_halluc"] = h["n_hallucinated"] > 0
        metrics = {"heldout_broken": "Held-out breakage (%)", "training_broken": "Training breakage (%)",
                   "has_halluc": "Policies with hallucinated names (%)", "malformed": "Malformed JSON (%)"}
        grid = {}
        for col in metrics:
            grid[col] = (h.pivot_table(index="prompt", columns="model", values=col,
                                       aggfunc=lambda s: 100 * pd.to_numeric(s, errors="coerce").mean()))
        fig, axs = plt.subplots(1, len(metrics), figsize=(3.4 * len(metrics), 3.6))
        for ax, (col, title) in zip(axs, metrics.items()):
            g = grid[col]
            models = list(g.columns)
            width = 0.8 / max(1, len(models))
            for i, (m, colr) in enumerate(zip(models, (C1, C2, C3))):
                bars(ax, list(g.index), g[m].values, colr, "{:.0f}", offset=(i - (len(models) - 1) / 2) * width,
                     width=width, label=m)
            ax.set_xticks(range(len(g.index)), list(g.index))
            ax.set_xlabel("prompt style")
            ax.set_ylim(0, 112)
            ax.set_title(title, fontsize=9, loc="left")
        handles, labels = axs[0].get_legend_handles_labels()
        fig.legend(handles, labels, loc="lower center", ncols=len(labels), bbox_to_anchor=(0.5, -0.06))
        fig.suptitle("Fig. 5  Prompt style vs model size (H3)", fontsize=10, x=0.01, ha="left")
        save(fig, "fig5_prompt_vs_model.png")
        md += ["## Prompt style vs model size (H3)", "",
               "Rows: prompt style (a = name only, b = trace summary, c = trace summary + descriptions). "
               "Columns: model. Breakage counts enforced policies only.", ""]
        for col, title in metrics.items():
            md += [f"### {title}", "", md_table(grid[col].round(1)), ""]

    (paths.RESULTS / "summary.md").write_text("\n".join(md), encoding="utf-8")
    print("  summary -> results/summary.md")


if __name__ == "__main__":
    main()
