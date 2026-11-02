#!/usr/bin/env python3
"""
Async Port Scanner
==================

TCP connect scanner built on asyncio - scans thousands of ports in seconds
without threads, grabs service banners, and exports JSON.

Only scan hosts you own or have written permission to test.

Usage
-----
    python port_scanner.py scanme.nmap.org -p 1-1024
    python port_scanner.py 192.168.1.10 -p 22,80,443,8000-8100 --banners --json out.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys
import time
from dataclasses import asdict, dataclass

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

# Ports where the server speaks first. Others need a nudge.
HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    banner: str = ""


def parse_ports(spec: str) -> list[int]:
    """'22,80,8000-8005' -> [22, 80, 8000, ..., 8005]"""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"invalid port(s): {bad[:5]}")
    return sorted(ports)


async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int, timeout: float) -> str:
    try:
        data = await asyncio.wait_for(reader.read(256), timeout)
        if not data and port not in (22, 21, 25):
            writer.write(HTTP_PROBE)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        try:
            writer.write(HTTP_PROBE)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return ""
    return data.decode("utf-8", "replace").split("\r\n")[0].strip()[:120]


async def probe(host: str, port: int, timeout: float, sem: asyncio.Semaphore, banners: bool) -> PortResult:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except asyncio.TimeoutError:
            return PortResult(port, "filtered", COMMON_SERVICES.get(port, ""))
        except (ConnectionRefusedError, OSError):
            return PortResult(port, "closed", COMMON_SERVICES.get(port, ""))
        banner = await grab_banner(reader, writer, port, timeout) if banners else ""
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return PortResult(port, "open", COMMON_SERVICES.get(port, "unknown"), banner)


async def scan(host: str, ports: list[int], timeout: float = 1.0, concurrency: int = 500,
               banners: bool = False) -> list[PortResult]:
    sem = asyncio.Semaphore(concurrency)
    return await asyncio.gather(*(probe(host, p, timeout, sem, banners) for p in ports))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Fast asyncio TCP connect scanner (authorized use only).")
    ap.add_argument("host")
    ap.add_argument("-p", "--ports", default="1-1024")
    ap.add_argument("-t", "--timeout", type=float, default=1.0)
    ap.add_argument("-c", "--concurrency", type=int, default=500)
    ap.add_argument("--banners", action="store_true", help="try to read service banners")
    ap.add_argument("--show-closed", action="store_true")
    ap.add_argument("--json", help="write results to a JSON file")
    a = ap.parse_args(argv)

    try:
        ip = socket.gethostbyname(a.host)
        ports = parse_ports(a.ports)
    except (socket.gaierror, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    print(f"[*] scanning {a.host} ({ip}) - {len(ports)} ports")
    start = time.perf_counter()
    results = asyncio.run(scan(ip, ports, a.timeout, a.concurrency, a.banners))
    elapsed = time.perf_counter() - start

    shown = [r for r in results if r.state == "open" or a.show_closed]
    print(f"\n{'PORT':<8}{'STATE':<10}{'SERVICE':<16}BANNER")
    for r in shown:
        print(f"{r.port:<8}{r.state:<10}{r.service:<16}{r.banner}")
    print(f"\n[*] {sum(r.state == 'open' for r in results)} open - done in {elapsed:.2f}s")

    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"host": a.host, "ip": ip, "results": [asdict(r) for r in results]}, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
