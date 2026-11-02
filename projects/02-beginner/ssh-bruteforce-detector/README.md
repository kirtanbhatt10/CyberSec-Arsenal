# SSH Brute-Force Detector

Reads OpenSSH auth logs and answers the three questions a SOC analyst actually cares about:

1. **Who is hammering us?** (sliding-window failure bursts)
2. **Is it brute force or password spraying?** (one user vs many users)
3. **Did any of them get in?** (a successful login *after* a burst = probable compromise)

```text
$ python ssh_detector.py sample_auth.log --emit iptables
[*] parsed 15 auth events, 2 offending IPs

198.51.100.77    fails=6     peak=6/60s users=6   password spraying / user enumeration
203.0.113.9      fails=6     peak=6/60s users=1   brute force
   [!!] SUCCESSFUL LOGIN after brute force as: root

# firewall rules
iptables -A INPUT -s 198.51.100.77 -p tcp --dport 22 -j DROP
iptables -A INPUT -s 203.0.113.9 -p tcp --dport 22 -j DROP
```

Exit code `1` means a probable compromise - wire it into an alert.

## What you'll learn

- Log parsing with regular expressions (syslog *and* ISO-8601 / journald timestamps)
- Sliding-window detection with `collections.deque`
- Distinguishing MITRE ATT&CK **T1110.001** (guessing) from **T1110.003** (spraying)
- Turning detections into response: iptables / nftables / ufw rules, IPv4 and IPv6

## Run

```bash
python ssh_detector.py /var/log/auth.log          # Debian/Ubuntu
python ssh_detector.py /var/log/secure            # RHEL/Fedora
journalctl -u ssh --no-pager -o short-iso | python ssh_detector.py -
pytest -q
```

## Ideas to extend

- Tail mode (`follow`) that blocks in real time - a mini fail2ban
- GeoIP / ASN enrichment for offenders
- Detect "impossible travel" between successful logins
