#!/usr/bin/env python3
"""
IOC Extractor
=============

Pull Indicators of Compromise out of threat reports, emails, logs or
paste-bin dumps - and handle the *defanged* notation analysts use so links
aren't clickable (``hxxp://evil[.]com``, ``1.2.3[.]4``).

Extracts
--------
IPv4 / IPv6, domains, URLs, email addresses, MD5 / SHA-1 / SHA-256 hashes,
CVE IDs, MITRE ATT&CK technique IDs, Bitcoin addresses.

Private/reserved IPs and common benign domains are filtered by default.

Usage
-----
    python ioc_extractor.py report.txt
    cat email.eml | python ioc_extractor.py - --format csv
    python ioc_extractor.py report.txt --defang        # safe to paste into tickets
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sys

REFANG = [
    (re.compile(r"(?i)\bhxxp(s?)://"), r"http\1://"),
    (re.compile(r"(?i)\bh\*\*p(s?)://"), r"http\1://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\[://\]"), "://"),
]

TLDS = ("com|net|org|io|ru|cn|info|biz|xyz|top|online|site|club|co|me|tk|ml|ga|cf|gq|uk|de|in|us|"
        "app|dev|cc|pw|su|onion|shop|live|link|click|zip|mov|ir|kp|br|fr|nl|eu|gov|edu|mil")
PATTERNS = {
    "url": re.compile(r"\bhttps?://[^\s<>\"'`)\]]+", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "ipv6": re.compile(r"(?<![:\w])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![:\w])"),
    "domain": re.compile(rf"\b(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{TLDS})\b", re.I),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "mitre_attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "bitcoin": re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
}
BENIGN_DOMAINS = {"microsoft.com", "google.com", "github.com", "mitre.org", "attack.mitre.org", "nvd.nist.gov",
                  "virustotal.com", "twitter.com", "x.com", "linkedin.com", "w3.org", "schema.org", "example.com"}


def refang(text: str) -> str:
    for rx, repl in REFANG:
        text = rx.sub(repl, text)
    return text


def defang(ioc: str) -> str:
    ioc = re.sub(r"(?i)^http", "hxxp", ioc)
    return re.sub(r"\.(?=[^.]*$)", "[.]", ioc) if "://" not in ioc else ioc.replace(".", "[.]")


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def _is_benign_url(url: str) -> bool:
    return any(re.match(rf"https?://(?:[^/]*\.)?{re.escape(b)}(?:[/:]|$)", url, re.I) for b in BENIGN_DOMAINS)


def _is_benign_domain(domain: str) -> bool:
    return domain in BENIGN_DOMAINS or any(domain.endswith("." + b) for b in BENIGN_DOMAINS)


def extract(text: str, include_private: bool = False, include_benign: bool = False) -> dict[str, list[str]]:
    text = refang(text)
    found: dict[str, set[str]] = {k: set() for k in PATTERNS}

    urls = {m.group(0).rstrip(".,;:") for m in PATTERNS["url"].finditer(text)}
    if not include_benign:
        # Drop reference links (MITRE, NVD, ...) *and* their contents, so a path like
        # /techniques/T1566/ doesn't produce a spurious indicator.
        for url in {u for u in urls if _is_benign_url(u)}:
            text = text.replace(url, " ")
            urls.discard(url)
    found["url"] = urls

    for kind in ("email", "sha256", "sha1", "md5", "cve", "mitre_attack", "bitcoin"):
        for m in PATTERNS[kind].finditer(text):
            val = m.group(0).rstrip(".,;:")
            found[kind].add(val.upper() if kind == "cve" else val.lower() if kind in ("sha256", "sha1", "md5") else val)

    for ip in PATTERNS["ipv4"].findall(text):
        if include_private or is_public_ip(ip):
            found["ipv4"].add(ip)
    for ip in PATTERNS["ipv6"].findall(text):
        if include_private or is_public_ip(ip):
            found["ipv6"].add(ip.lower())

    for d in PATTERNS["domain"].findall(text):
        d = d.lower()
        if include_benign or not _is_benign_domain(d):
            found["domain"].add(d)
    return {k: sorted(v) for k, v in found.items() if v}


def render(iocs: dict[str, list[str]], fmt: str, defanged: bool) -> str:
    fix = defang if defanged else (lambda s: s)
    if fmt == "json":
        return json.dumps({k: [fix(v) if k in ("url", "domain", "ipv4", "email") else v for v in vs]
                           for k, vs in iocs.items()}, indent=2)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value"])
        for k, vs in iocs.items():
            for v in vs:
                w.writerow([k, fix(v) if k in ("url", "domain", "ipv4", "email") else v])
        return buf.getvalue()
    lines = []
    for k, vs in iocs.items():
        lines.append(f"## {k} ({len(vs)})")
        lines += [f"  {fix(v) if k in ('url', 'domain', 'ipv4', 'email') else v}" for v in vs]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Extract (and refang/defang) IOCs from text.")
    ap.add_argument("input", help="file path or - for stdin")
    ap.add_argument("--format", choices=["text", "json", "csv"], default="text")
    ap.add_argument("--defang", action="store_true", help="defang network IOCs in output")
    ap.add_argument("--include-private", action="store_true")
    ap.add_argument("--include-benign", action="store_true")
    a = ap.parse_args(argv)

    text = sys.stdin.read() if a.input == "-" else open(a.input, encoding="utf-8", errors="replace").read()
    iocs = extract(text, a.include_private, a.include_benign)
    print(render(iocs, a.format, a.defang))
    return 0 if iocs else 1


if __name__ == "__main__":
    sys.exit(main())
