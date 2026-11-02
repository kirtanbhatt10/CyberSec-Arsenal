# Async Port Scanner

A TCP connect scanner built on `asyncio`: 1,000 ports in about a second, service banners, JSON export - zero dependencies.

> Only scan systems you own or have explicit written permission to test. `scanme.nmap.org` is provided by the Nmap project for exactly this purpose.

```text
$ python port_scanner.py scanme.nmap.org -p 1-1024 --banners
[*] scanning scanme.nmap.org (45.33.32.156) - 1024 ports

PORT    STATE     SERVICE         BANNER
22      open      ssh             SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80      open      http            HTTP/1.1 200 OK

[*] 2 open - done in 1.84s
```

## How it works

| Step | Code |
|---|---|
| Parse `22,80,8000-8100` into a port list | `parse_ports()` |
| Bound concurrency with a semaphore so we don't exhaust file descriptors | `scan()` |
| Full TCP handshake via `asyncio.open_connection` | `probe()` |
| Refused -> **closed**, timeout -> **filtered**, success -> **open** | `probe()` |
| Read what the server says first (SSH/FTP/SMTP), otherwise send an HTTP `HEAD` | `grab_banner()` |

## Connect scan vs SYN scan

A connect scan completes the 3-way handshake, so it needs no root but it **shows up in application logs**. Nmap's `-sS` sends only a SYN and resets on SYN/ACK - stealthier, faster, but requires raw sockets. Building a SYN scanner with `scapy` is a great follow-up project.

## Run

```bash
python port_scanner.py 127.0.0.1 -p 1-65535 -c 1000
pytest -q
```

## Ideas to extend

- CIDR range support (`10.0.0.0/24`) with host discovery
- UDP scanning with protocol-specific probes
- Service/version fingerprinting from banners
