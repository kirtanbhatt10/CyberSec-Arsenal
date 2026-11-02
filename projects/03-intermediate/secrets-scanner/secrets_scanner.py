#!/usr/bin/env python3
"""
Secrets Scanner
===============

Find leaked credentials in a codebase *and its git history* - because
deleting a key in a later commit doesn't remove it from the repo.

Detection
---------
1. Provider-specific regexes (AWS, GitHub, Slack, Stripe, Google, private keys, ...)
2. Generic ``secret = "..."`` assignments filtered by Shannon entropy
3. Allowlist via inline ``# secrets-scanner: ignore`` comments

Output as a table, JSON, or SARIF 2.1.0 (GitHub code scanning understands it).

Usage
-----
    python secrets_scanner.py path/to/repo
    python secrets_scanner.py . --git-history --format sarif > results.sarif
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass

RULES: dict[str, tuple[str, str]] = {
    # id: (description, regex)
    "aws-access-key-id": ("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github-token": ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "github-fine-grained": ("GitHub fine-grained PAT", r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    "slack-token": ("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,72}\b"),
    "slack-webhook": ("Slack webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    "stripe-secret": ("Stripe secret key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,99}\b"),
    "google-api-key": ("Google API key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "private-key": ("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    "jwt": ("JSON Web Token", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "db-url-with-password": ("Database URL with password",
                             r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]{3,}@[^\s/]+"),
    "openai-key": ("OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
}
COMPILED = {rid: (desc, re.compile(rx)) for rid, (desc, rx) in RULES.items()}

GENERIC = re.compile(
    r"""(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|auth|credential)s?\b\s*[:=]\s*["']([^"'\s]{12,})["']"""
)
PLACEHOLDER = re.compile(r"(?i)(example|changeme|your[_-]|xxxx|\*\*\*|<|\$\{|placeholder|dummy|test|sample)")
IGNORE_MARK = "secrets-scanner: ignore"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}
MAX_FILE = 2 * 1024 * 1024


@dataclass
class Finding:
    rule: str
    description: str
    file: str
    line: int
    secret: str  # redacted
    commit: str = ""

    @property
    def key(self):
        return (self.rule, self.secret, self.file)


def shannon(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


def redact(s: str) -> str:
    return s[:4] + "*" * max(4, len(s) - 8) + s[-4:] if len(s) > 10 else "*" * len(s)


def scan_text(text: str, path: str, min_entropy: float = 3.5, commit: str = "") -> list[Finding]:
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARK in line:
            continue
        hit_spans = []
        for rid, (desc, rx) in COMPILED.items():
            for m in rx.finditer(line):
                hit_spans.append(m.span())
                out.append(Finding(rid, desc, path, lineno, redact(m.group(0)), commit))
        for m in GENERIC.finditer(line):
            value = m.group(1)
            if any(a <= m.start(1) < b for a, b in hit_spans) or PLACEHOLDER.search(value):
                continue
            if shannon(value) >= min_entropy:
                out.append(Finding("generic-high-entropy", f"High-entropy secret (H={shannon(value):.2f})",
                                   path, lineno, redact(value), commit))
    return out


def iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > MAX_FILE:
                    continue
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            if b"\x00" in data[:4096]:  # binary
                continue
            yield os.path.relpath(path, root), data.decode("utf-8", "replace")


def scan_tree(root: str, min_entropy: float = 3.5) -> list[Finding]:
    return [f for rel, text in iter_files(root) for f in scan_text(text, rel, min_entropy)]


def scan_git_history(root: str, min_entropy: float = 3.5) -> list[Finding]:
    """Scan every added line in every commit (``git log -p``)."""
    try:
        log = subprocess.run(
            ["git", "-C", root, "log", "--all", "-p", "--no-color", "--unified=0", "--format=COMMIT %H"],
            capture_output=True, text=True, errors="replace", check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    findings, commit, path, buf = [], "", "", []

    def flush():
        if buf:
            findings.extend(scan_text("\n".join(buf), path, min_entropy, commit[:10]))
            buf.clear()

    for line in log.splitlines():
        if line.startswith("COMMIT "):
            flush()
            commit = line.split()[1]
        elif line.startswith("+++ b/"):
            flush()
            path = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            buf.append(line[1:])
    flush()
    return findings


def to_sarif(findings: list[Finding]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "cybersec-arsenal-secrets-scanner",
                "rules": [{"id": rid, "shortDescription": {"text": desc}} for rid, (desc, _) in RULES.items()]
                + [{"id": "generic-high-entropy", "shortDescription": {"text": "High-entropy secret"}}],
            }},
            "results": [{
                "ruleId": f.rule,
                "level": "error",
                "message": {"text": f"{f.description}: {f.secret}" + (f" (commit {f.commit})" if f.commit else "")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                                    "region": {"startLine": f.line}}}],
            } for f in findings],
        }],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Find leaked secrets in files and git history.")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--git-history", action="store_true", help="also scan every commit")
    ap.add_argument("--min-entropy", type=float, default=3.5)
    ap.add_argument("--format", choices=["table", "json", "sarif"], default="table")
    a = ap.parse_args(argv)

    findings = scan_tree(a.path, a.min_entropy)
    if a.git_history:
        seen = {f.key for f in findings}
        findings += [f for f in scan_git_history(a.path, a.min_entropy) if f.key not in seen]

    if a.format == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    elif a.format == "sarif":
        print(json.dumps(to_sarif(findings), indent=2))
    else:
        for f in findings:
            where = f"{f.file}:{f.line}" + (f" @{f.commit}" if f.commit else "")
            print(f"[{f.rule}] {where}\n    {f.description}: {f.secret}")
        print(f"\n{len(findings)} potential secret(s) found", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
