"""LINUX ONLY. Runs one configured program run in a fresh scratch directory,
either plainly, under strace (to record a trace) or under the seccomp launcher
(to enforce a policy). Used by tracing/record_traces.py,
enforce/run_enforcement.py and enforce/run_containment.py.
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from . import paths


def load_config() -> dict:
    with open(paths.PROGRAMS_CONFIG, encoding="utf-8") as f:
        return json.load(f)


def programs() -> dict:
    return load_config()["programs"]


def _expand(s: str) -> str:
    return s.replace("{BIN}", str(paths.PROGRAMS_BIN)).replace("{WORKLOADS}", str(paths.WORKLOADS))


def resolve_argv(argv):
    argv = [_expand(a) for a in argv]
    exe = argv[0] if os.path.isabs(argv[0]) else shutil.which(argv[0])
    if not exe or not os.path.exists(exe):
        raise FileNotFoundError(f"program not found: {argv[0]} (did you run `make` / install it?)")
    return [exe] + argv[1:]


def _bash(cmd: str, cwd: Path, timeout=60):
    return subprocess.run(["bash", "-c", _expand(cmd)], cwd=cwd, capture_output=True, text=True, timeout=timeout)


def _http_client(port: int, path: str, proc=None, timeout=8.0):
    """Connect (retrying while the server starts), send GET, return status line.
    Stops early if the server process has already died (e.g. killed by seccomp)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            return ""
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                s.sendall(f"GET {path} HTTP/1.0\r\n\r\n".encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                return data.split(b"\r\n", 1)[0].decode(errors="replace")
        except (ConnectionRefusedError, ConnectionResetError, socket.timeout, OSError):
            time.sleep(0.1)
    return ""


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return ""
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"SIG{-returncode}"


def run(program_cfg: dict, run_name: str, prefix=None, env_extra=None, timeout=60, keep=False) -> dict:
    """Execute program_cfg['runs'][run_name].

    prefix: list placed before the program argv, e.g.
            ["strace", "-f", "-o", "/abs/out.strace"]                       (record)
            [LAUNCHER, "--mode", "kill", "/abs/policy_names.txt", "--"]     (enforce)
    Returns a dict with exit code, signal, check result and passed flag.
    """
    spec = program_cfg["runs"][run_name]
    scratch = Path(tempfile.mkdtemp(prefix=f"sandbox_{run_name}_"))
    env = dict(os.environ)
    env["LC_ALL"] = "C"          # same locale for recording and enforcement (fewer locale-file opens)
    env.update({k: _expand(v) for k, v in (env_extra or {}).items()})
    result = {"run": run_name, "exit_code": None, "signal": "", "timed_out": False,
              "check_ok": None, "client_status": "", "passed": False, "stderr_tail": "",
              "duration_s": None, "scratch": str(scratch)}
    try:
        for cmd in program_cfg.get("setup", []) + spec.get("setup", []):
            r = _bash(cmd, scratch)
            if r.returncode != 0:
                raise RuntimeError(f"setup failed: {cmd}\n{r.stderr}")

        argv = (prefix or []) + resolve_argv(spec["argv"])
        stdin = open(scratch / spec["stdin"], "rb") if spec.get("stdin") else subprocess.DEVNULL
        stdout = open(scratch / spec["stdout"], "wb") if spec.get("stdout") else subprocess.DEVNULL
        t0 = time.time()
        proc = subprocess.Popen(argv, cwd=scratch, stdin=stdin, stdout=stdout,
                                stderr=subprocess.PIPE, env=env)
        if spec.get("client"):
            c = spec["client"]
            status = _http_client(c["port"], c["path"], proc)
            result["client_status"] = status
        try:
            _, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate()
            result["timed_out"] = True
        result["duration_s"] = round(time.time() - t0, 3)
        for fh in (stdin, stdout):
            if hasattr(fh, "close"):
                fh.close()

        result["exit_code"] = proc.returncode
        result["signal"] = signal_name(proc.returncode)
        result["stderr_tail"] = err.decode(errors="replace")[-300:]

        ok = proc.returncode == 0 and not result["timed_out"]
        if spec.get("client"):
            ok = ok and spec["client"]["expect"] in result["client_status"]
        if spec.get("check"):
            result["check_ok"] = _bash(spec["check"], scratch).returncode == 0
            ok = ok and result["check_ok"]
        result["passed"] = bool(ok)
        return result
    finally:
        if not keep:
            shutil.rmtree(scratch, ignore_errors=True)


def run_probe(prefix=None, timeout=30) -> dict:
    """Run the escape probe (no scratch setup needed). Returns exit info + parsed JSON lines."""
    argv = (prefix or []) + resolve_argv(load_config()["probe"]["argv"])
    env = dict(os.environ, LC_ALL="C")
    p = subprocess.run(argv, capture_output=True, timeout=timeout, env=env)
    attempts = []
    for line in p.stdout.decode(errors="replace").splitlines():
        try:
            attempts.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return {"exit_code": p.returncode, "signal": signal_name(p.returncode), "attempts": attempts}
