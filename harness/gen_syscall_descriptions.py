#!/usr/bin/env python3
"""Build config/syscall_descriptions.json from the Linux man-pages (section 2).

Prompt style (c) gives the model "trace summary plus syscall descriptions" (proposal
section 3, step 4). The descriptions are taken from the NAME line of each syscall's
man page, e.g.  openat.2: "open, openat, creat - open and possibly create a file"
gives  openat -> "open and possibly create a file".
Pages that only redirect (".so man2/stat.2", as for newfstatat) are followed.

Run on Linux. Needs: sudo apt install manpages-dev   (installs /usr/share/man/man2)
Usage: python3 harness/gen_syscall_descriptions.py [--man-dir /usr/share/man/man2]
"""
import argparse
import gzip
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, syscalls  # noqa: E402


def read_page(man_dir: Path, name: str, depth=0):
    for cand in (man_dir / f"{name}.2.gz", man_dir / f"{name}.2"):
        if cand.exists():
            raw = gzip.open(cand, "rt", errors="replace").read() if cand.suffix == ".gz" else cand.read_text(errors="replace")
            m = re.match(r"\s*\.so\s+man2/([\w.]+)\.2", raw)
            if m and depth < 3:
                return read_page(man_dir, m.group(1), depth + 1)
            return raw
    return None


def name_line(page: str):
    """Text of the line after '.SH NAME', without troff markup."""
    m = re.search(r"^\.SH\s+\"?NAME\"?\s*\n(.+?)\n\.(SH|SS|PP|LP)", page, re.M | re.S)
    if not m:
        return None
    text = " ".join(l for l in m.group(1).splitlines() if not l.startswith(".\\\""))
    text = re.sub(r"\\f[BIRP]", "", text)
    text = text.replace("\\-", "-").replace("\\(em", "-").replace("\\ ", " ").replace("\\%", "")
    text = re.sub(r"\\[(][a-z]{2}", "", text)
    text = re.sub(r"^\.\w+\s*", "", text).strip()
    if " - " not in text:
        return None
    return text.split(" - ", 1)[1].strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--man-dir", type=Path, default=Path("/usr/share/man/man2"))
    args = ap.parse_args()
    if not args.man_dir.is_dir():
        sys.exit(f"{args.man_dir} not found - run: sudo apt install manpages-dev")

    out, missing = {}, []
    for name in syscalls.table():
        page = read_page(args.man_dir, name)
        desc = name_line(page) if page else None
        if desc:
            out[name] = desc
        else:
            missing.append(name)
    paths.DESCRIPTIONS.write_text(json.dumps(dict(sorted(out.items())), indent=1), encoding="utf-8")
    print(f"{len(out)} descriptions written to {paths.DESCRIPTIONS.relative_to(paths.ROOT)}")
    print(f"{len(missing)} x86_64 syscalls have no man page entry (prompt shows 'no description in the Linux man-pages')")


if __name__ == "__main__":
    main()
