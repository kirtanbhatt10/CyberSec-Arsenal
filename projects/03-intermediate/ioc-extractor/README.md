# IOC Extractor

Turn a messy threat report, phishing email or incident chat log into a clean list of Indicators of Compromise - ready for a blocklist, a SIEM search, or a ticket.

```text
$ python ioc_extractor.py sample_report.txt --format csv
type,value
url,https://invoice-portal.xyz/download/inv_2291.zip
email,billing@invoice-portal.xyz
ipv4,45.137.21.9
domain,cdn-updates.top
domain,invoice-portal.xyz
sha256,3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea
md5,44d88612fea8a8f36de82e1278abb02f
cve,CVE-2024-3400
mitre_attack,T1059.001
mitre_attack,T1566.002
bitcoin,bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
```

## Features

- **Refangs** analyst notation: `hxxps://`, `[.]`, `(dot)`, `[at]`, `[:]`
- **Defangs** output with `--defang` so links in tickets aren't clickable
- Extracts IPv4/IPv6, domains, URLs, emails, MD5/SHA-1/SHA-256, CVEs, ATT&CK technique IDs, Bitcoin addresses
- Drops **private/reserved IPs** (RFC 1918, loopback, link-local) unless `--include-private`
- Drops **reference links** (MITRE, NVD, VirusTotal, ...) and anything inside them, so citations don't pollute the IOC list
- Text, JSON or CSV output

## What you'll learn

- Writing regexes that are strict enough to avoid noise (IPv4 octet bounds, hash word boundaries)
- The `ipaddress` module for classifying address space
- Why defanging exists and how threat-intel sharing (STIX/MISP) structures indicators
- The Pyramid of Pain - why hashes and IPs are the *easiest* IOCs for attackers to change

## Run

```bash
python ioc_extractor.py report.pdf.txt --defang
pbpaste | python ioc_extractor.py - --format json
pytest -q
```

## Ideas to extend

- Export STIX 2.1 bundles
- Enrich IPs/domains via AbuseIPDB or VirusTotal APIs
- Pipe the URLs into [`phishing-url-analyzer`](../../02-beginner/phishing-url-analyzer)
