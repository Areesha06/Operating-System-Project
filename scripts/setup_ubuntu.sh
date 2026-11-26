#!/usr/bin/env bash
# One-time setup on the Ubuntu machine that records traces and runs enforcement.
# (Ubuntu 22.04 / 24.04, or Ubuntu under WSL2.)
set -euo pipefail
cd "$(dirname "$0")/.."
sudo apt update
sudo apt install -y build-essential strace libseccomp-dev linux-libc-dev manpages-dev \
                    sqlite3 xz-utils python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make                                        # programs/bin/* and enforce/bin/seccomp_launcher
python3 tracing/gen_syscall_table.py        # config/syscalls_x86_64.json, config/syscalls_other_arch.json
python3 harness/gen_syscall_descriptions.py # config/syscall_descriptions.json (from man-pages)
grep -q '^Seccomp:' /proc/self/status && echo "seccomp available: OK"
echo "Setup done. In every new terminal run:  source .venv/bin/activate"
