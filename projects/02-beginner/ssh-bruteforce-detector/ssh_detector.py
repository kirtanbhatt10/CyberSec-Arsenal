#!/usr/bin/env python3
"""
SSH Brute-Force Detector
========================

Parses OpenSSH auth logs, finds brute-force and password-spraying behaviour
with a sliding time window, flags successful logins *after* a burst of
failures (the scary one), and can emit firewall rules to block offenders.

Usage
-----
    python ssh_detector.py /var/log/auth.log
    python ssh_detector.py auth.log --threshold 5 --window 60 --emit iptables
    journalctl -u ssh --no-pager | python ssh_detector.py -
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)")
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+")
SYSLOG_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})")
ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")


@dataclass
class Event:
    ts: datetime
    kind: str  # "fail" | "success"
    ip: str
    user: str


@dataclass
class Offender:
    ip: str
    failures: int = 0
    users: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    peak_burst: int = 0
    compromised_users: set[str] = field(default_factory=set)

    @property
    def technique(self) -> str:
        if len(self.users) >= 5:
            return "password spraying / user enumeration"
        return "brute force"


def parse_timestamp(line: str, year: int) -> datetime | None:
    if m := ISO_TS.match(line):
        return datetime.fromisoformat(m.group("ts"))
    if m := SYSLOG_TS.match(line):
        return datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
    return None


def parse_events(lines, year: int | None = None) -> list[Event]:
    year = year or datetime.now().year
    events = []
    for line in lines:
        ts = parse_timestamp(line, year)
        if ts is None:
            continue
        if m := FAILED.search(line) or INVALID.search(line):
            events.append(Event(ts, "fail", m.group("ip"), m.group("user")))
        elif m := ACCEPTED.search(line):
            events.append(Event(ts, "success", m.group("ip"), m.group("user")))
    return events


def analyze(events: list[Event], threshold: int = 5, window: int = 60) -> dict[str, Offender]:
    """Flag IPs with >= ``threshold`` failures inside any ``window``-second span."""
    span = timedelta(seconds=window)
    recent: dict[str, deque] = defaultdict(deque)
    stats: dict[str, Offender] = {}

    for ev in sorted(events, key=lambda e: e.ts):
        off = stats.setdefault(ev.ip, Offender(ev.ip))
        off.first_seen = off.first_seen or ev.ts
        off.last_seen = ev.ts
        q = recent[ev.ip]
        if ev.kind == "fail":
            off.failures += 1
            off.users.add(ev.user)
            q.append(ev.ts)
            while q and ev.ts - q[0] > span:
                q.popleft()
            off.peak_burst = max(off.peak_burst, len(q))
        elif ev.kind == "success" and off.peak_burst >= threshold:
            off.compromised_users.add(ev.user)

    return {ip: o for ip, o in stats.items() if o.peak_burst >= threshold}


def firewall_rules(ips, kind: str) -> list[str]:
    rules = []
    for ip in sorted(ips):
        v6 = isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        if kind == "iptables":
            rules.append(f"{'ip6tables' if v6 else 'iptables'} -A INPUT -s {ip} -p tcp --dport 22 -j DROP")
        elif kind == "nft":
            rules.append(f"nft add element inet filter blocklist{'6' if v6 else ''} {{ {ip} }}")
        elif kind == "ufw":
            rules.append(f"ufw deny from {ip} to any port 22")
    return rules


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Detect SSH brute force from auth logs.")
    ap.add_argument("logfile", help="path to auth.log/secure, or - for stdin")
    ap.add_argument("--threshold", type=int, default=5)
    ap.add_argument("--window", type=int, default=60, help="seconds")
    ap.add_argument("--year", type=int, help="year for syslog timestamps (default: current)")
    ap.add_argument("--emit", choices=["iptables", "nft", "ufw"])
    a = ap.parse_args(argv)

    fh = sys.stdin if a.logfile == "-" else open(a.logfile, encoding="utf-8", errors="replace")
    with fh:
        events = parse_events(fh, a.year)
    offenders = analyze(events, a.threshold, a.window)

    print(f"[*] parsed {len(events)} auth events, {len(offenders)} offending IPs\n")
    for o in sorted(offenders.values(), key=lambda x: -x.failures):
        print(f"{o.ip:<40} fails={o.failures:<5} peak={o.peak_burst}/{a.window}s users={len(o.users):<3} {o.technique}")
        if o.compromised_users:
            print(f"   [!!] SUCCESSFUL LOGIN after brute force as: {', '.join(sorted(o.compromised_users))}")

    if a.emit and offenders:
        print("\n# firewall rules")
        print("\n".join(firewall_rules(offenders, a.emit)))
    return 1 if any(o.compromised_users for o in offenders.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
