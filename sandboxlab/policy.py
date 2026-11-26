"""Policies = allow-lists of syscall names, stored as JSON.

Standard policy file (written by tracing/make_baseline.py and harness/generate_policies.py):
{
  "program": "gzip",
  "source": "baseline" | "llama3.2:3b" | "llama3.1:8b",
  "prompt": null | "a" | "b" | "c",
  "repeat": 0,
  "allow": ["read", "write", ...],            # names exactly as produced (after JSON extraction)
  "json_valid": true,                          # could we get a list of names out of the output?
  "extraction": "direct" | "embedded" | "list-fallback" | "failed" | "n/a",
  "raw_output": "...",                         # full LLM text, kept even when broken
  ... timing fields for LLM policies ...
}

load_policy() also accepts a bare JSON list or a Docker seccomp profile.
"""
import json
import re
from pathlib import Path

from . import syscalls

# The launcher needs execve to start the program at all (the filter is installed
# before exec). It is added to every policy at ENFORCEMENT time only and is never
# counted in attack-surface metrics.
LAUNCH_SYSCALLS = ["execve"]


def load_policy(path) -> dict:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if isinstance(doc, list):
        return {"program": None, "source": Path(path).stem, "allow": doc, "json_valid": True}
    if "syscalls" in doc and "defaultAction" in doc:         # Docker profile format
        names = []
        for rule in doc["syscalls"]:
            if rule.get("action") == "SCMP_ACT_ALLOW":
                names += rule.get("names", [])
        return {"program": None, "source": Path(path).stem, "allow": names, "json_valid": True}
    doc.setdefault("allow", [])
    doc.setdefault("json_valid", True)
    return doc


def save_policy(doc: dict, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)


def allowed_set(doc: dict) -> set:
    """Valid x86_64 names the policy allows. Wrong-architecture and hallucinated
    names are dropped: they have no x86_64 syscall number, so they cannot be enforced."""
    return set(syscalls.classify(doc.get("allow", []))["valid"])


def write_names_file(names, path, add_launch=True):
    """Write the allow-list for enforce/bin/seccomp_launcher: one syscall name per line."""
    names = sorted(set(names) | (set(LAUNCH_SYSCALLS) if add_launch else set()))
    with open(path, "w", encoding="utf-8") as f:
        f.write("# syscalls allowed by the policy (x86_64 names)\n")
        f.write("\n".join(names) + "\n")
    return names


# ---------------------------------------------------------------- LLM output
def _first_json_object(text: str):
    """Find the first balanced {...} block in text and parse it."""
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


def _names_from_obj(obj):
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, str)]
    if isinstance(obj, dict):
        for key in ("allow", "allowed", "syscalls", "allowlist", "allow_list", "names"):
            if key in obj and isinstance(obj[key], list):
                return [x for x in obj[key] if isinstance(x, str)]
    return None


def extract_allow_list(text: str):
    """Return (names or None, extraction_method).

    direct        the whole output is valid JSON with an allow list (ideal)
    embedded      valid JSON object found inside extra text (e.g. ```json fences)
    list-fallback no valid object, but a JSON array of strings was found
    failed        nothing usable -> counted as INVALID OUTPUT
    """
    text = text.strip()
    try:
        names = _names_from_obj(json.loads(text))
        if names is not None:
            return names, "direct"
    except json.JSONDecodeError:
        pass
    obj = _first_json_object(text)
    names = _names_from_obj(obj) if obj is not None else None
    if names is not None:
        return names, "embedded"
    m = re.search(r"\[[^\[\]]*\]", text, re.S)
    if m:
        try:
            names = _names_from_obj(json.loads(m.group(0)))
            if names:
                return names, "list-fallback"
        except json.JSONDecodeError:
            pass
    return None, "failed"
