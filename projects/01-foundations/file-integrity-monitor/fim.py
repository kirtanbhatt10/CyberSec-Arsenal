#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
============================

A tiny Tripwire/AIDE: snapshot a directory's SHA-256 hashes and metadata,
then detect anything that was added, deleted, modified or had its
permissions changed.

The baseline is signed with HMAC-SHA256 so an attacker who edits files
*and* the baseline JSON gets caught - unless they also have your key.

Usage
-----
    export FIM_KEY="long-random-secret"
    python fim.py baseline /etc  -o etc.baseline.json
    python fim.py check    /etc  -b etc.baseline.json
    python fim.py watch    /etc  -b etc.baseline.json --interval 30
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

CHUNK = 64 * 1024


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def snapshot(root: Path, exclude: tuple[str, ...] = ()) -> dict[str, dict]:
    """Walk ``root`` and record hash, size, mode, uid and mtime for each regular file."""
    entries: dict[str, dict] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in exclude]
        for name in filenames:
            if name in exclude:
                continue
            path = Path(dirpath) / name
            try:
                st = path.lstat()
                if not stat.S_ISREG(st.st_mode):
                    continue
                entries[str(path.relative_to(root))] = {
                    "sha256": sha256_file(path),
                    "size": st.st_size,
                    "mode": oct(stat.S_IMODE(st.st_mode)),
                    "uid": st.st_uid,
                    "mtime": int(st.st_mtime),
                }
            except (PermissionError, FileNotFoundError):
                continue
    return entries


def _canonical(files: dict) -> bytes:
    return json.dumps(files, sort_keys=True, separators=(",", ":")).encode()


def sign(files: dict, key: bytes) -> str:
    return hmac.new(key, _canonical(files), hashlib.sha256).hexdigest()


def save_baseline(files: dict, out: Path, key: bytes | None) -> None:
    doc = {"created": int(time.time()), "files": files}
    if key:
        doc["hmac"] = sign(files, key)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True))


def load_baseline(path: Path, key: bytes | None) -> dict:
    doc = json.loads(path.read_text())
    if key:
        expected = sign(doc["files"], key)
        if not hmac.compare_digest(expected, doc.get("hmac", "")):
            raise ValueError("baseline HMAC mismatch - the baseline itself was tampered with")
    return doc["files"]


@dataclass
class Diff:
    added: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    metadata: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.added or self.deleted or self.modified or self.metadata)


def compare(old: dict, new: dict) -> Diff:
    d = Diff()
    d.added = sorted(set(new) - set(old))
    d.deleted = sorted(set(old) - set(new))
    for path in sorted(set(old) & set(new)):
        if old[path]["sha256"] != new[path]["sha256"]:
            d.modified.append(path)
        elif old[path]["mode"] != new[path]["mode"] or old[path]["uid"] != new[path]["uid"]:
            d.metadata.append(f"{path} ({old[path]['mode']}->{new[path]['mode']}, uid {old[path]['uid']}->{new[path]['uid']})")
    return d


def print_diff(d: Diff) -> None:
    if d.clean:
        print("[OK] no changes detected")
        return
    for label, items, sym in (("ADDED", d.added, "+"), ("DELETED", d.deleted, "-"),
                              ("MODIFIED", d.modified, "~"), ("PERMS/OWNER", d.metadata, "!")):
        for item in items:
            print(f"[{sym}] {label:<11} {item}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Detect file tampering with signed hash baselines.")
    p.add_argument("command", choices=["baseline", "check", "watch"])
    p.add_argument("root", type=Path)
    p.add_argument("-o", "--output", type=Path, default=Path("fim.baseline.json"))
    p.add_argument("-b", "--baseline", type=Path, default=Path("fim.baseline.json"))
    p.add_argument("--exclude", nargs="*", default=[".git", "__pycache__"])
    p.add_argument("--interval", type=int, default=60)
    a = p.parse_args(argv)

    key = os.environ.get("FIM_KEY", "").encode() or None
    if key is None:
        print("[!] FIM_KEY not set - baseline will not be tamper-evident", file=sys.stderr)

    if a.command == "baseline":
        files = snapshot(a.root, tuple(a.exclude))
        save_baseline(files, a.output, key)
        print(f"[+] baselined {len(files)} files -> {a.output}")
        return 0

    try:
        old = load_baseline(a.baseline, key)
    except ValueError as exc:
        print(f"[!!] {exc}", file=sys.stderr)
        return 2

    while True:
        diff = compare(old, snapshot(a.root, tuple(a.exclude)))
        print_diff(diff)
        if a.command == "check":
            return 0 if diff.clean else 1
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
