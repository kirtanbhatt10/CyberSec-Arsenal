#!/usr/bin/env python3
"""
Web Attack Detector
===================

Hunts for attacks in nginx / Apache *combined* access logs - a lightweight,
rule-based WAF-in-hindsight that a blue teamer can read in one sitting.

Detects
-------
* SQL injection, XSS, path traversal / LFI, command injection, SSRF probes
* Log4Shell (``${jndi:``) and other template-injection payloads
* Known scanner user-agents (sqlmap, nikto, nuclei, ...)
* Sensitive-file probing (``/.env``, ``/.git/config``, ``wp-config.php``)
* Forced browsing: IPs generating bursts of 404s

Payloads are URL-decoded (twice, to beat double encoding) before matching.

Usage
-----
    python web_attack_detector.py /var/log/nginx/access.log
    python web_attack_detector.py access.log --format json --min-severity high
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from urllib.parse import unquote_plus

COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

RULES: list[tuple[str, str, re.Pattern]] = [
    ("log4shell", "critical", re.compile(r"\$\{(?:jndi|lower|upper|env|sys)[:$]", re.I)),
    ("sqli", "high", re.compile(
        r"(?:'|\")\s*(?:or|and)\s+['\"\d]+\s*=\s*['\"\d]+|union(?:\s|/\*.*?\*/)+(?:all\s+)?select|"
        r"\b(?:sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay|information_schema|"
        r";\s*(?:drop|insert|update|delete)\s|\bor\s+1\s*=\s*1|'--|\bxp_cmdshell\b", re.I)),
    ("xss", "high", re.compile(
        r"<\s*script|javascript:|on(?:error|load|mouseover|focus)\s*=|<\s*(?:img|svg|iframe)[^>]*\bsrc|"
        r"document\.(?:cookie|domain)|alert\s*\(", re.I)),
    ("path-traversal", "high", re.compile(r"(?:\.\./|\.\.\\){2,}|/etc/passwd|/proc/self/environ|c:\\windows", re.I)),
    ("cmd-injection", "critical", re.compile(
        r"(?:;|\||`|\$\()\s*(?:cat|id|whoami|uname|wget|curl|nc|bash|sh|powershell)\b", re.I)),
    ("ssrf", "high", re.compile(
        r"(?:url|uri|dest|redirect|next|target)=\s*(?:https?|gopher|file|dict)://"
        r"(?:127\.|localhost|169\.254\.169\.254|0\.0\.0\.0|\[::1\]|metadata\.google)", re.I)),
    ("sensitive-file", "medium", re.compile(
        r"/(?:\.env|\.git/(?:config|HEAD)|\.aws/credentials|wp-config\.php|\.htpasswd|"
        r"server-status|phpinfo\.php|id_rsa|\.DS_Store|backup\.(?:zip|sql|tar\.gz))\b", re.I)),
]
SCANNER_UA = re.compile(r"sqlmap|nikto|nuclei|nmap|masscan|zgrab|dirbuster|gobuster|ffuf|wpscan|acunetix|"
                        r"nessus|openvas|hydra|python-requests/|go-http-client", re.I)


@dataclass
class Hit:
    line: int
    ip: str
    rule: str
    severity: str
    method: str
    path: str
    status: int
    user_agent: str


def decode(s: str) -> str:
    """URL-decode twice to catch double-encoded payloads like %252e%252e%252f."""
    return unquote_plus(unquote_plus(s))


def parse(line: str) -> dict | None:
    m = COMBINED.match(line)
    return m.groupdict() if m else None


def detect(lines, notfound_threshold: int = 20) -> tuple[list[Hit], dict[str, int]]:
    hits: list[Hit] = []
    notfound: Counter[str] = Counter()
    for n, raw in enumerate(lines, 1):
        rec = parse(raw)
        if not rec:
            continue
        status = int(rec["status"])
        ua = rec.get("ua") or ""
        target = decode(rec["path"]) + " " + decode(ua)
        if status == 404:
            notfound[rec["ip"]] += 1
        for name, sev, rx in RULES:
            if rx.search(target):
                hits.append(Hit(n, rec["ip"], name, sev, rec["method"], rec["path"][:200], status, ua[:80]))
        if SCANNER_UA.search(ua):
            hits.append(Hit(n, rec["ip"], "scanner-ua", "low", rec["method"], rec["path"][:200], status, ua[:80]))
    brute = {ip: c for ip, c in notfound.items() if c >= notfound_threshold}
    return hits, brute


def summarize(hits: list[Hit]) -> dict[str, dict]:
    by_ip: dict[str, dict] = defaultdict(lambda: {"hits": 0, "rules": Counter(), "succeeded": 0, "worst": "low"})
    for h in hits:
        s = by_ip[h.ip]
        s["hits"] += 1
        s["rules"][h.rule] += 1
        if 200 <= h.status < 300 and h.rule != "scanner-ua":
            s["succeeded"] += 1
        if SEVERITY_ORDER[h.severity] < SEVERITY_ORDER[s["worst"]]:
            s["worst"] = h.severity
    return by_ip


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Detect web attacks in combined-format access logs.")
    ap.add_argument("logfile", help="access log path or - for stdin")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low")
    ap.add_argument("--404-threshold", dest="nf", type=int, default=20)
    a = ap.parse_args(argv)

    fh = sys.stdin if a.logfile == "-" else open(a.logfile, encoding="utf-8", errors="replace")
    with fh:
        hits, brute = detect(fh, a.nf)
    hits = [h for h in hits if SEVERITY_ORDER[h.severity] <= SEVERITY_ORDER[a.min_severity]]

    if a.format == "json":
        print(json.dumps({"hits": [asdict(h) for h in hits], "forced_browsing": brute}, indent=2))
    else:
        for ip, s in sorted(summarize(hits).items(), key=lambda kv: (SEVERITY_ORDER[kv[1]["worst"]], -kv[1]["hits"])):
            rules = ", ".join(f"{r}({c})" for r, c in s["rules"].most_common())
            flag = f"  <-- {s['succeeded']} got 2xx!" if s["succeeded"] else ""
            print(f"[{s['worst'].upper():<8}] {ip:<16} {s['hits']:>4} hits  {rules}{flag}")
        for ip, c in brute.items():
            print(f"[MEDIUM  ] {ip:<16} {c:>4} 404s  forced-browsing / directory brute force")
        print(f"\n{len(hits)} malicious requests from {len({h.ip for h in hits})} IPs", file=sys.stderr)
    return 1 if any(h.severity in ("critical", "high") for h in hits) else 0


if __name__ == "__main__":
    sys.exit(main())
