# Web Attack Detector

A rule-based "WAF in hindsight" for nginx/Apache access logs. Point it at a log and see who attacked you, with what, and - most importantly - **which attacks got a 2xx back**.

```text
$ python web_attack_detector.py sample_access.log
[CRITICAL] 198.18.0.9          2 hits  log4shell(1), cmd-injection(1)  <-- 1 got 2xx!
[HIGH    ] 203.0.113.66        4 hits  sqli(2), scanner-ua(2)  <-- 2 got 2xx!
[HIGH    ] 192.0.2.14          2 hits  xss(1), path-traversal(1)  <-- 1 got 2xx!
[HIGH    ] 198.18.0.10         1 hits  ssrf(1)  <-- 1 got 2xx!
[MEDIUM  ] 198.18.0.11         4 hits  sensitive-file(2), scanner-ua(2)

13 malicious requests from 5 IPs
```

## Detections

| Rule | Severity | Example |
|---|---|---|
| `log4shell` | critical | `${jndi:ldap://...}` in any header we log |
| `cmd-injection` | critical | `?host=127.0.0.1;cat /etc/shadow` |
| `sqli` | high | `UNION SELECT`, `' OR 1=1`, `SLEEP(5)` |
| `xss` | high | `<script>`, `onerror=`, `javascript:` |
| `path-traversal` | high | `../../../etc/passwd`, even double-encoded `%252e%252e%252f` |
| `ssrf` | high | `?url=http://169.254.169.254/` (cloud metadata) |
| `sensitive-file` | medium | `/.env`, `/.git/config`, `wp-config.php` |
| `scanner-ua` | low | sqlmap, nikto, nuclei, ffuf, gobuster |
| forced browsing | medium | IPs with >= 20 404s |

## What you'll learn

- The nginx/Apache *combined* log format
- Why decoding (and double-decoding) before matching matters - and how attackers abuse it
- OWASP Top 10 attack signatures: A03 Injection, A10 SSRF, A05 Misconfiguration
- Limits of signature detection (obfuscation, POST bodies aren't logged) and why real WAFs inspect the full request

## Run

```bash
python web_attack_detector.py /var/log/nginx/access.log --min-severity high
python web_attack_detector.py access.log --format json | jq '.hits[] | select(.status < 300)'
pytest -q
```

## Ideas to extend

- Export Sigma rules for each detection
- Tail mode that pushes alerts to Slack/Discord
- GeoIP + ASN enrichment and a timeline view
