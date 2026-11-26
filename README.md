# Can Local LLMs Write Syscall Sandboxes?

Operating Systems L4 term project. Instructor: Zafar Iqbal.
Group: Areesha Kashif, Alishbah Saleem Kath, Noor E Hira.

## Research question

Can local LLMs synthesize seccomp/AppArmor-style syscall policies from strace traces of normal program
runs, and how does the result compare with a deterministic trace-to-profile baseline in attack surface
removed versus legitimate behaviour broken?

Every program reaches the kernel through system calls. A seccomp filter is an allow-list: any syscall not
on the list is denied. This project builds such lists in two ways, from strace recordings of 10 programs:
- a deterministic **baseline** that allows exactly what the training run used;
- **local LLMs** (Llama 3.2 3B and Llama 3.1 8B via Ollama).

Every list is then enforced with real seccomp. We measure four things:
- **breakage**: does the program still work?
- **attack surface**: how many syscalls, and how many dangerous ones, are allowed?
- **invalid output**: malformed JSON, hallucinated names, wrong-architecture names.
- **containment**: does a harmless probe's dangerous syscall get blocked?

OS elements covered:
- **Security**: least-privilege hardening, privilege-escalation prevention (`PR_SET_NO_NEW_PRIVS`, syscall filtering).
- **I/O**: system-call interception with seccomp and strace.
- **Concurrency**: multithreaded test runs (`worker`, `xz -T4`, `sort --parallel=4`), child processes (`find -exec`), and `strace -f` tracing of threads and processes.

---

## 1. Requirements

| Step | Needs |
|---|---|
| Building, tracing, baseline, enforcement, containment | Ubuntu 22.04/24.04 (or Ubuntu on WSL2): gcc, strace, libseccomp-dev, sqlite3, xz-utils |
| LLM policy generation | [Ollama](https://ollama.com/download) on Windows or Linux, with `llama3.2:3b` and `llama3.1:8b` pulled; 16 GB RAM for the 8B model |
| Analysis and figures | Python 3.10+ on any OS, `pip install -r requirements.txt` |

seccomp and strace are Linux kernel features, so those steps must run on Linux. All traces and all
enforcement runs must come from the **same** Linux machine.

## 2. Reproducing the results

This repository contains our complete run: traces, 310 policies, enforcement results and figures.
The scripts never overwrite finished work, so re-running a step on this clone reports
"already done". There are two ways to check our results.

### Option A: Recompute the analysis from our data (about 2 minutes, any OS)

```bash
pip install -r requirements.txt
python analysis/evaluate_policies.py
python analysis/make_figures.py
```

This rebuilds `results/policy_metrics.csv`, `results/summary.md` and `results/figures/` from the
committed traces, policies and enforcement results. The new `results/summary.md` should be
identical to the committed one.

### Option B: Run the whole experiment again from scratch (Linux + Ollama)

Do this in a fresh clone: it deletes our results and replaces them with yours.

```bash
bash scripts/setup_ubuntu.sh
source .venv/bin/activate
rm -rf data/* policies/baseline/* policies/llm/* results/*
ollama pull llama3.2:3b
ollama pull llama3.1:8b
python3 tracing/record_traces.py
python3 tracing/make_baseline.py
python3 harness/generate_policies.py
python3 enforce/run_enforcement.py
python3 enforce/run_containment.py
python3 analysis/evaluate_policies.py
python3 analysis/make_figures.py
```

The model step uses a fixed seed for each repeat, but a run on
different hardware or with a different Ollama version may still give slightly different numbers.
Our committed results are the ones reported.

## 3. Setup

**Ubuntu (tracing and enforcement machine)**
```bash
git clone https://github.com/Areesha06/Operating-System-Project.git && cd OS-Project
bash scripts/setup_ubuntu.sh     # apt packages, Python venv, build, syscall tables, man-page descriptions
source .venv/bin/activate        # in every new terminal
```

**Windows (LLM generation or analysis only)**, in PowerShell:
```powershell
git clone https://github.com/Areesha06/Operating-System-Project.git; cd OS-Project
py -m venv .venv; .venv\Scripts\activate
pip install -r requirements.txt
ollama pull llama3.2:3b; ollama pull llama3.1:8b     # only on the machine that generates policies
```

## 4. Running the experiment

Run the steps in this order. On Windows use `python` instead of `python3`.

| # | Command | Where | Produces |
|---|---|---|---|
| 1 | `make` | Linux | `programs/bin/*`, `enforce/bin/seccomp_launcher` (done by setup) |
| 2 | `python3 tracing/record_traces.py` | Linux | `data/<program>/traces/{training,heldout}.strace`, summaries, `data/probe/` |
| 3 | `python3 tracing/make_baseline.py` | any | `policies/baseline/<program>/baseline.json` |
| 4a | `python harness/timing_test.py` | Ollama machine | time per generation (optional check) |
| 4b | `python harness/generate_policies.py` | Ollama machine | `policies/llm/<program>/*.json` (300 files), `results/generation_log_<model>.csv` |
| 5 | `python3 enforce/run_enforcement.py` | Linux | `results/enforcement.csv` |
| 6 | `python3 enforce/run_containment.py` | Linux | `results/containment.csv` |
| 7 | `python analysis/evaluate_policies.py` | any | `results/policy_metrics.csv` |
| 8 | `python analysis/make_figures.py` | any | `results/figures/fig1..fig5.png`, `results/summary.md` |

Notes:
- **Two models on two machines.** Step 4b accepts `--models`: run `--models llama3.2:3b` on one machine and `--models llama3.1:8b` on the other. Each machine needs `data/` (from step 2) pulled first.
- **Restarting.** Steps 4b and 5 skip work that is already finished, so an interrupted run can be restarted with the same command.
- **Linux steps in one go.** After `policies/llm/` is complete, `bash scripts/run_pipeline.sh --no-trace` runs steps 3 and 5–8.
- **Preview a prompt.** `python harness/prompts.py gzip c` shows exactly what the model receives.
- **Inspect one policy against one trace.** `python analysis/replay_check.py --trace data/gzip/traces/heldout.strace --policy policies/baseline/gzip/baseline.json`

## 5. Repository layout

```
config/       experiment configuration and reference data
sandboxlab/   shared Python library used by every step
programs/     the two test programs written for this project, the probe, and workloads
tracing/      strace recording and the baseline generator
harness/      LLM prompts and policy generation with Ollama
enforce/      libseccomp launcher, enforcement runner, containment runner
analysis/     metrics, figures, summary tables
scripts/      Ubuntu setup and full pipeline
data/         recorded traces            (generated by step 2)
policies/     baseline and LLM policies  (generated by steps 3 and 4)
results/      CSV results and figures    (generated by steps 5-8)
```

### config/
| File | What it is | Why it is needed |
|---|---|---|
| `programs.json` | The 10 test programs: setup commands, training run, held-out run, correctness check | Single definition of every run used by tracing and enforcement |
| `syscalls_x86_64.json` | x86_64 syscall name → number (generated from `<asm/unistd_64.h>`) | Decides which names are valid |
| `syscalls_other_arch.json` | Names that exist on i386 / generic Linux ABIs but not on x86_64 (generated from kernel headers) | Detects wrong-architecture names (Invalid output) |
| `syscall_descriptions.json` | One-line description per syscall from the Linux man-pages (generated) | Descriptions for prompt style (c) |
| `high_risk.txt` | Syscalls blocked by Docker's default seccomp profile, with reasons and source | High-risk part of the Attack surface metric |

### sandboxlab/ (shared library)
| File | What it does | Why it is needed |
|---|---|---|
| `__init__.py` | Package description | Makes `sandboxlab` importable |
| `paths.py` | All folder/file locations relative to the repo | Same code works on Windows and Linux |
| `strace_parser.py` | Parses `strace -f` output (pids, unfinished/resumed calls, signals) into events and `{syscall: count}` summaries; finds the blocked syscall in TRAP-mode traces | Traces → summaries, baselines, prompts, replay |
| `workload.py` | Linux only. Runs one program run in a fresh temp directory: plainly, under strace, or under the launcher; runs the HTTP client for `mini_httpd`; runs the correctness check | Identical execution for tracing and enforcement |
| `syscalls.py` | Loads the tables, high-risk list and descriptions; classifies names as valid / wrong-architecture / hallucinated | Invalid output and Attack surface metrics |
| `policy.py` | Policy JSON format, extraction of the allow-list from model text, writes the names file for the launcher | Shared by generation, enforcement and analysis |
| `replay.py` | Checks a recorded trace against a policy without running it | Secondary method (proposal section 8) |

### programs/
| File | What it does | Why it is needed |
|---|---|---|
| `src/worker.c` | `worker N`: N POSIX threads sum an array under a mutex (N = 0: no threads) | Multithreaded C worker named in the proposal (concurrency) |
| `src/mini_httpd.c` | Serves one HTTP request on 127.0.0.1: a file (training) or a directory listing (held-out) | Simple HTTP server named in the proposal |
| `src/escape_probe.c` | Attempts 10 dangerous syscalls with invalid arguments and reports BLOCKED / REACHED_KERNEL for each | Harmless probe program for the Containment metric |
| `workloads/sqlite_insert.sql`, `sqlite_query.sql` | sqlite3 training and held-out workloads | Different code paths for sqlite3 |
| `Makefile` | Builds the three C programs into `programs/bin/` | Build |

### tracing/
| File | What it does | Why it is needed |
|---|---|---|
| `record_traces.py` | Checks each run works, then records it with `strace -f`; writes summaries and version metadata; records the probe | Proposal step 2 |
| `make_baseline.py` | Allow-list = exactly the syscalls of the training trace | Proposal step 3 |
| `gen_syscall_table.py` | Generates both syscall tables from this machine's kernel headers | Valid / wrong-architecture classification |

### harness/
| File | What it does | Why it is needed |
|---|---|---|
| `prompts.py` | System message and prompt styles (a) name only, (b) trace summary, (c) trace summary + descriptions | Proposal step 4 |
| `ollama_client.py` | Standard-library client for Ollama's `/api/chat` (temperature, seed, context size, timing) | Talks to the local model |
| `generate_policies.py` | Runs the 300-generation grid; saves each reply, the extracted list and timing; resumable | Proposal step 4 |
| `timing_test.py` | Times one generation per model and estimates the grid duration | Planning the run |
| `gen_syscall_descriptions.py` | Extracts syscall descriptions from the man-pages | Builds `config/syscall_descriptions.json` |

### enforce/
| File | What it does | Why it is needed |
|---|---|---|
| `src/seccomp_launcher.c` | libseccomp launcher: builds the filter from a names file, sets NO_NEW_PRIVS, loads it, `exec`s the program. Modes: kill / trap / errno:N | Proposal step 5 |
| `run_enforcement.py` | Runs every program under every policy on the training and held-out run; on SIGSYS finds the blocked syscall | Breakage metric |
| `run_containment.py` | Runs the probe under every policy; records outcome and whether it matches the allow-list | Containment metric |

### analysis/
| File | What it does | Why it is needed |
|---|---|---|
| `evaluate_policies.py` | Per-policy metrics: malformed JSON, hallucinated / wrong-architecture names, allowed and high-risk counts, replay results | Invalid output, Attack surface |
| `make_figures.py` | Figures 1–5 and `results/summary.md` | Comparison (proposal step 6) and hypotheses H1–H3 |
| `replay_check.py` | Prints the replay verdict for one trace and one policy | Inspecting individual cases (secondary method) |

### scripts/ and other files
| File | What it does |
|---|---|
| `scripts/setup_ubuntu.sh` | Installs packages, creates the venv, builds, generates the syscall tables and descriptions |
| `scripts/run_pipeline.sh` | Runs the Linux steps in order |
| `Makefile` | Builds the test programs and the launcher |
| `requirements.txt` | Python packages for analysis |

## 6. Output files

| File | Content |
|---|---|
| `data/<program>/summary_<run>.json` | total calls, unique syscalls, processes/threads, `{syscall: count}` |
| `data/<program>/traces/<run>.meta.json` | pass/fail, command, kernel, glibc and strace versions, timestamp |
| `policies/baseline/<program>/baseline.json` | baseline allow-list |
| `policies/llm/<program>/<model>__p<style>__r<repeat>.json` | raw model reply, extracted allow-list, `json_valid`, extraction method, prompts, timing |
| `results/generation_log_<model>.csv` | one row per generation: time, tokens, validity |
| `results/enforcement.csv` | one row per (policy, run): `passed`, `signal` (SIGSYS = killed by seccomp), `blocked_syscall` |
| `results/containment.csv` | one row per (policy, probe syscall): `policy_allows`, `outcome`, `matches` |
| `results/policy_metrics.csv` | one row per policy: invalid-output, attack-surface and replay columns |
| `results/summary.md` | all tables behind the figures |
| `results/figures/fig1_breakage.png` | breakage on training and held-out runs per condition |
| `results/figures/fig2_attack_surface.png` | allowed and high-risk syscalls per condition |
| `results/figures/fig3_invalid_output.png` | malformed JSON, hallucinated names, wrong-architecture names |
| `results/figures/fig4_containment.png` | probe syscalls that reached the kernel per condition |
| `results/figures/fig5_prompt_vs_model.png` | metrics split by prompt style and model (H3) |

## 7. Safety

- The probe only makes syscalls with invalid arguments. Even when a call is not blocked, it fails in the kernel and changes nothing.
- Every run uses a temporary directory, which is deleted afterwards.
- `mini_httpd` listens on 127.0.0.1 only and exits after one request.
- A syscall filter is one defence layer, not complete security.
