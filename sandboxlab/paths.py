"""Central place for folder locations. Everything is relative to the repo root,
so the same scripts work on Windows and on Ubuntu."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CONFIG = ROOT / "config"
PROGRAMS_CONFIG = CONFIG / "programs.json"
SYSCALL_TABLE = CONFIG / "syscalls_x86_64.json"
SYSCALL_TABLE_OTHER_ARCH = CONFIG / "syscalls_other_arch.json"
HIGH_RISK = CONFIG / "high_risk.txt"
DESCRIPTIONS = CONFIG / "syscall_descriptions.json"

PROGRAMS_DIR = ROOT / "programs"
PROGRAMS_BIN = PROGRAMS_DIR / "bin"
WORKLOADS = PROGRAMS_DIR / "workloads"
LAUNCHER = ROOT / "enforce" / "bin" / "seccomp_launcher"

DATA = ROOT / "data"                 # data/<program>/traces/<run>.strace and summaries
POLICIES = ROOT / "policies"         # policies/baseline/... and policies/llm/...
RESULTS = ROOT / "results"           # csv results and figures
FIGURES = RESULTS / "figures"


def trace_path(program: str, run: str, data_dir: Path = DATA) -> Path:
    return data_dir / program / "traces" / f"{run}.strace"


def summary_path(program: str, run: str, data_dir: Path = DATA) -> Path:
    return data_dir / program / f"summary_{run}.json"
