#!/usr/bin/env python3
"""
Password Auditor
================

Scores a password the way an attacker would think about it, not the way a
"must contain one symbol" form does.

What it checks
--------------
* Character-pool entropy (a rough upper bound on brute-force cost)
* Known-weak passwords (a small built-in list, or your own wordlist)
* Keyboard walks  (``qwerty``, ``asdf``, ``1qaz``)
* Sequences       (``abcd``, ``1234``, ``9876``)
* Repeats         (``aaaa``, ``abcabc``)
* Leetspeak       (``p@ssw0rd`` is still ``password``)
* Dates / years   (``1999``, ``2024``)
* Optional breach check against Have I Been Pwned using *k-anonymity*:
  only the first 5 hex chars of the SHA-1 ever leave your machine.

Usage
-----
    python password_auditor.py                 # prompts securely (no echo)
    python password_auditor.py --hibp          # also query the breach API
    python password_auditor.py --wordlist rockyou.txt
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import math
import re
import string
import sys
import urllib.request
from dataclasses import dataclass, field

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "111111", "123123", "letmein", "welcome", "monkey", "dragon",
    "football", "iloveyou", "admin", "login", "princess", "sunshine",
    "master", "shadow", "baseball", "superman", "trustno1", "passw0rd",
    "starwars", "whatever", "hello", "freedom", "charlie", "secret",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
KEYBOARD_COLUMNS = ["1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik", "9ol", "0p"]

LEET_MAP = str.maketrans({
    "@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o",
    "$": "s", "5": "s", "7": "t", "+": "t", "8": "b", "9": "g",
})


@dataclass
class Report:
    password_length: int
    entropy_bits: float
    score: int  # 0 (terrible) .. 4 (strong)
    findings: list[str] = field(default_factory=list)
    breached_count: int | None = None

    @property
    def verdict(self) -> str:
        return ["Very weak", "Weak", "Fair", "Good", "Strong"][self.score]


def charset_size(password: str) -> int:
    """Size of the character pool an attacker must search."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(ord(c) > 127 for c in password):
        pool += 100  # conservative guess for unicode
    if any(c == " " for c in password):
        pool += 1
    return pool


def entropy_bits(password: str) -> float:
    pool = charset_size(password)
    return 0.0 if pool == 0 or not password else len(password) * math.log2(pool)


def _runs(password: str, sources: list[str], min_len: int = 4) -> list[str]:
    """Find substrings of ``password`` that appear (forwards or backwards) in any source."""
    low = password.lower()
    hits = []
    for src in sources:
        for seq in (src, src[::-1]):
            for size in range(len(seq), min_len - 1, -1):
                for i in range(len(seq) - size + 1):
                    chunk = seq[i:i + size]
                    if chunk in low and not any(chunk in h for h in hits):
                        hits.append(chunk)
    return hits


def find_keyboard_walks(password: str) -> list[str]:
    return _runs(password, KEYBOARD_ROWS + KEYBOARD_COLUMNS)


def find_sequences(password: str) -> list[str]:
    return _runs(password, [string.ascii_lowercase, string.digits])


def find_repeats(password: str) -> list[str]:
    hits = [m.group(0) for m in re.finditer(r"(.)\1{2,}", password)]
    hits += [m.group(0) for m in re.finditer(r"(.{2,})\1+", password) if m.group(0) not in hits]
    return hits


def find_years(password: str) -> list[str]:
    return re.findall(r"(?:19|20)\d{2}", password)


def deleet(password: str) -> str:
    return password.lower().translate(LEET_MAP)


def hibp_breach_count(password: str, timeout: float = 5.0) -> int:
    """Return how many times ``password`` appears in HIBP using k-anonymity."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "cybersec-arsenal-password-auditor", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URL)
        body = resp.read().decode()
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate == suffix:
            return int(count)
    return 0


def audit(password: str, wordlist: set[str] | None = None, check_hibp: bool = False) -> Report:
    weak = COMMON_PASSWORDS | (wordlist or set())
    bits = entropy_bits(password)
    report = Report(password_length=len(password), entropy_bits=round(bits, 1), score=0)
    penalty = 0

    if len(password) < 8:
        report.findings.append("Shorter than 8 characters - trivially brute-forced.")
        penalty += 2
    elif len(password) < 12:
        report.findings.append("Under 12 characters - consider a longer passphrase.")
        penalty += 1

    if password.lower() in weak:
        report.findings.append("Appears in a common-password list.")
        penalty += 4
    elif deleet(password) in weak or deleet(re.sub(r"[\d!@#$%^&*]+$", "", password)) in weak:
        report.findings.append("Common password hidden behind leetspeak or trailing digits.")
        penalty += 3

    for label, hits, cost in (
        ("Keyboard walk", find_keyboard_walks(password), 1),
        ("Sequential run", find_sequences(password), 1),
        ("Repeated pattern", find_repeats(password), 1),
        ("Looks like a year", find_years(password), 1),
    ):
        if hits:
            report.findings.append(f"{label}: {', '.join(sorted(set(hits)))}")
            penalty += cost

    if charset_size(password) <= 26:
        report.findings.append("Uses a single character class.")
        penalty += 1

    base = 0 if bits < 28 else 1 if bits < 36 else 2 if bits < 60 else 3 if bits < 80 else 4
    report.score = max(0, min(4, base - penalty // 2))

    if check_hibp:
        try:
            report.breached_count = hibp_breach_count(password)
            if report.breached_count:
                report.findings.append(f"Seen {report.breached_count:,} times in public breaches!")
                report.score = 0
        except OSError as exc:
            report.findings.append(f"HIBP lookup failed: {exc}")

    if not report.findings:
        report.findings.append("No obvious weaknesses found.")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit password strength like an attacker would.")
    parser.add_argument("--hibp", action="store_true", help="check Have I Been Pwned (k-anonymity)")
    parser.add_argument("--wordlist", help="extra newline-separated weak password list")
    args = parser.parse_args(argv)

    words: set[str] = set()
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8", errors="ignore") as fh:
            words = {line.strip().lower() for line in fh if line.strip()}

    password = getpass.getpass("Password to audit (input hidden): ")
    report = audit(password, words, args.hibp)

    print(f"\nLength      : {report.password_length}")
    print(f"Entropy     : ~{report.entropy_bits} bits")
    print(f"Verdict     : {report.verdict} ({report.score}/4)")
    print("Findings    :")
    for item in report.findings:
        print(f"  - {item}")
    return 0 if report.score >= 3 else 1


if __name__ == "__main__":
    sys.exit(main())
