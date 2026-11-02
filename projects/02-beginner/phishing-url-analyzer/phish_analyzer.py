#!/usr/bin/env python3
"""
Phishing URL Analyzer
=====================

Explainable, offline heuristic scoring of URLs. No ML black box - every
point of risk comes with a human-readable reason, which is exactly what a
SOC analyst needs when triaging a reported email.

Checks
------
* Raw IP address as host, non-standard ports
* Punycode / IDN homographs (``xn--pple-43d.com`` -> ``аpple.com``)
* Lookalike brands via edit distance (``paypa1``, ``micros0ft``)
* Brand name buried in a subdomain (``paypal.com.account-verify.ru``)
* ``@`` userinfo tricks, excessive subdomains, very long URLs
* Suspicious TLDs, URL shorteners, credential-themed keywords
* High-entropy (randomly generated) hostnames

Usage
-----
    python phish_analyzer.py "http://paypal.com.secure-login.xyz/verify"
    python phish_analyzer.py -f urls.txt --json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "linkedin", "github", "dropbox", "outlook", "office365", "chase",
    "wellsfargo", "bankofamerica", "coinbase", "binance", "whatsapp", "adobe",
    "sbi", "hdfcbank", "icicibank", "paytm",
]
SUSPICIOUS_TLDS = {"xyz", "top", "zip", "mov", "tk", "ml", "ga", "cf", "gq", "click", "country",
                   "work", "support", "rest", "fit", "cam", "icu", "buzz", "monster"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy", "shorturl.at"}
KEYWORDS = ["login", "signin", "verify", "account", "update", "secure", "banking", "confirm",
            "password", "wallet", "suspend", "unlock", "billing", "invoice", "webscr"]
# Common two-label public suffixes, so "evil.co.uk" registers as "evil", not "co".
MULTI_SUFFIXES = {"co.uk", "co.in", "com.au", "co.jp", "com.br", "org.uk", "gov.in", "ac.in", "net.in"}


@dataclass
class Verdict:
    url: str
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return "PHISHING" if self.score >= 60 else "SUSPICIOUS" if self.score >= 30 else "LIKELY SAFE"

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.reasons.append(f"+{points:<3}{reason}")


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def split_host(host: str) -> tuple[list[str], str, str]:
    """Return (subdomain_labels, registrable_name, suffix)."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return labels[:-3], labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[:-2], labels[-2], labels[-1]
    return [], host, ""


# Characters that render (almost) identically to ASCII letters.
CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "8": "b",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u04cf": "l",
    "\u03bf": "o", "\u03b1": "a", "\u03c1": "p",
})


def skeleton(s: str) -> str:
    """Map lookalike characters to the ASCII letter a victim would read."""
    return s.translate(CONFUSABLES)


def analyze(url: str) -> Verdict:
    v = Verdict(url)
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower().rstrip(".")

    if parts.scheme == "http":
        v.add(10, "plain HTTP (no TLS)")
    if parts.username or "@" in parts.netloc:
        v.add(30, "'@' in authority - browser ignores everything before it")
    try:
        ipaddress.ip_address(host)
        v.add(35, f"raw IP address as host ({host})")
        return v
    except ValueError:
        pass
    if parts.port and parts.port not in (80, 443):
        v.add(10, f"non-standard port {parts.port}")
    if host in SHORTENERS:
        v.add(20, "URL shortener hides the real destination")
        return v

    subs, name, tld = split_host(host)
    if "xn--" in host:
        try:
            decoded = host.encode().decode("idna")
            v.add(35, f"punycode/IDN host - renders as '{decoded}'")
            name = split_host(decoded)[1]
        except UnicodeError:
            v.add(35, "malformed punycode host")

    if tld in SUSPICIOUS_TLDS:
        v.add(15, f"high-abuse TLD .{tld}")
    if len(subs) >= 3:
        v.add(10, f"{len(subs)} subdomain levels")

    if name not in BRANDS:
        for brand in BRANDS:
            if brand in (".".join(subs)).replace("-", ".").split(".") or brand in "-".join(subs):
                v.add(35, f"brand '{brand}' used in subdomain of unrelated domain '{name}.{tld}'")
                break
            if brand in name.split("-") or (len(brand) >= 5 and brand in name):
                v.add(30, f"brand '{brand}' embedded in domain '{name}'")
                break
            if skeleton(name) == brand != name:
                v.add(40, f"'{name}' uses lookalike characters to impersonate '{brand}'")
                break
            dist = levenshtein(name, brand)
            if len(brand) >= 5 and 0 < dist <= 2:
                v.add(40, f"'{name}' is a typosquat of '{brand}' (edit distance {dist})")
                break

    ent = shannon_entropy(name)
    if len(name) >= 12 and ent > 3.5:
        v.add(15, f"random-looking domain (entropy {ent:.2f})")
    if name.count("-") >= 2 and "xn--" not in host:
        v.add(10, "multiple hyphens in domain")

    path_q = (parts.path + "?" + parts.query).lower()
    hits = [k for k in KEYWORDS if k in path_q or k in ".".join(subs)]
    if hits:
        v.add(min(25, 8 * len(hits)), f"credential-themed keywords: {', '.join(hits[:4])}")
    if len(url) > 100:
        v.add(10, f"very long URL ({len(url)} chars)")
    return v


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Explainable phishing URL scoring.")
    ap.add_argument("urls", nargs="*")
    ap.add_argument("-f", "--file", help="newline-separated URLs")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    urls = list(a.urls)
    if a.file:
        with open(a.file, encoding="utf-8") as fh:
            urls += [u.strip() for u in fh if u.strip() and not u.startswith("#")]
    if not urls:
        ap.error("give at least one URL or --file")

    verdicts = [analyze(u) for u in urls]
    if a.json:
        print(json.dumps([{**asdict(v), "label": v.label} for v in verdicts], indent=2))
    else:
        for v in verdicts:
            print(f"\n[{v.label}] score={v.score}  {v.url}")
            for r in v.reasons:
                print(f"    {r}")
    return 1 if any(v.label == "PHISHING" for v in verdicts) else 0


if __name__ == "__main__":
    sys.exit(main())
