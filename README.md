<div align="center">

# 🛡️ CyberSec Arsenal

**Hands-on cybersecurity projects you can read in one sitting, run in one command, and extend in a weekend.**

Offensive concepts, defensive tooling, real detection logic - written in clean, dependency-free Python with tests.

[![CI](https://github.com/kirtanbhatt10/CyberSec-Arsenal/actions/workflows/ci.yml/badge.svg)](https://github.com/kirtanbhatt10/CyberSec-Arsenal/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)
![Projects](https://img.shields.io/badge/projects-10-orange)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg)](CONTRIBUTING.md)
![Stars](https://img.shields.io/github/stars/kirtanbhatt10/CyberSec-Arsenal?style=social)

[Projects](#-projects) · [Quick start](#-quick-start) · [Learning path](ROADMAP.md) · [Resources](RESOURCES.md) · [Contributing](CONTRIBUTING.md)

</div>

---

## Why this repo?

Most "cybersecurity projects" lists are just links. This one ships **working tools** where every project:

- 📄 is a **single readable Python file** - no framework, no dependency hell
- ✅ has **pytest tests** that run in CI on every push
- 🎯 maps to **real-world attacks** (MITRE ATT&CK, OWASP Top 10, real CVEs)
- 🧠 has a README explaining **how the attack/defense actually works**, not just how to run it
- 🔧 ends with **"Ideas to extend"** so you can level it up into your own portfolio piece

> [!WARNING]
> These tools are for **education and authorized testing only**. Only scan, test or analyze systems you own or have explicit written permission to assess.

---

## 🧰 Projects

### 🟢 Foundations - *start here*

| Project | What it does | You'll learn |
|---|---|---|
| [**Password Auditor**](projects/01-foundations/password-auditor) | Scores passwords like a cracker would + private breach check | Entropy vs. patterns · leetspeak mangling · HIBP k-anonymity |
| [**Cipher Breaker**](projects/01-foundations/cipher-breaker) | Breaks Caesar & Vigenère **without the key** | Frequency analysis · chi-squared · Index of Coincidence |
| [**File Integrity Monitor**](projects/01-foundations/file-integrity-monitor) | Tripwire-style tamper detection with HMAC-signed baselines | SHA-256 streaming · HMAC · web-shell detection |

### 🟡 Beginner

| Project | What it does | You'll learn |
|---|---|---|
| [**Async Port Scanner**](projects/02-beginner/async-port-scanner) | 1,000 ports in ~1s with banner grabbing | asyncio · TCP handshake · open/closed/filtered |
| [**SSH Brute-Force Detector**](projects/02-beginner/ssh-bruteforce-detector) | Finds brute force, spraying & **logins after attacks** | Sliding windows · T1110 · firewall automation |
| [**Phishing URL Analyzer**](projects/02-beginner/phishing-url-analyzer) | Explainable scoring of suspicious links | IDN homographs · typosquatting · Levenshtein |
| [**JWT Inspector**](projects/02-beginner/jwt-inspector) | Decodes JWTs, cracks weak HMAC secrets, flags `alg:none` | JWS internals · offline secret cracking · API auth bugs |

### 🔴 Intermediate

| Project | What it does | You'll learn |
|---|---|---|
| [**Secrets Scanner**](projects/03-intermediate/secrets-scanner) | Finds leaked keys in code **and git history**, outputs SARIF | Regex + entropy detection · git internals · code scanning |
| [**IOC Extractor**](projects/03-intermediate/ioc-extractor) | Pulls IPs, domains, hashes, CVEs, ATT&CK IDs from reports | Refang/defang · threat intel · Pyramid of Pain |
| [**Web Attack Detector**](projects/03-intermediate/web-attack-detector) | Hunts SQLi, XSS, Log4Shell, SSRF in access logs | OWASP Top 10 signatures · double-encoding evasion |

### 🗺️ Coming next

Want to build one of these? [Open an issue](../../issues/new/choose) and claim it.

| Tier | Project idea |
|---|---|
| 🟡 | DNS Recon Tool (records, zone-transfer check, subdomain brute force) |
| 🟡 | HTTP Security Headers Grader |
| 🔴 | Packet Sniffer & Protocol Analyzer (scapy) |
| 🔴 | TLS Certificate & Cipher Auditor |
| 🔴 | YARA Rule Scanner for suspicious files |
| ⚫ | Honeypot with attacker session replay |
| ⚫ | Mini SIEM with correlation rules + dashboard |
| ⚫ | Container image vulnerability scanner (SBOM + CVE matching) |

---

## 🚀 Quick start

```bash
git clone https://github.com/kirtanbhatt10/CyberSec-Arsenal.git
cd CyberSec-Arsenal

# every tool is standalone - just run it
python projects/02-beginner/phishing-url-analyzer/phish_analyzer.py "http://paypa1.com/login"
python projects/03-intermediate/web-attack-detector/web_attack_detector.py \
       projects/03-intermediate/web-attack-detector/sample_access.log

# run the whole test suite
pip install pytest
pytest
```

No `pip install -r requirements.txt`. Every tool uses only the Python standard library.

---

## 🧭 How to use this repo to learn

1. **Read the project README first** - understand the attack or defense before the code.
2. **Run it against the sample data** in the folder.
3. **Read the source top to bottom** - each file is under ~250 lines.
4. **Break the tests** - change a rule and see what fails.
5. **Pick an "Ideas to extend"** item and ship it as a PR. 🎉

Then follow the [**learning roadmap**](ROADMAP.md) for where to go next (certs, labs, CTFs).

---

## 🗂️ Repository layout

```
CyberSec-Arsenal/
├── projects/
│   ├── 01-foundations/     # single concept, heavily explained
│   ├── 02-beginner/        # real tools, one protocol or log source
│   └── 03-intermediate/    # multi-technique detection & analysis
├── ROADMAP.md              # learning path + certification tracks
├── RESOURCES.md            # labs, CTFs, books, channels
└── .github/                # CI, issue & PR templates
```

---

## 🤝 Contributing

New projects, bug fixes, better detections and docs are all welcome - see [CONTRIBUTING.md](CONTRIBUTING.md).
Found a security issue in one of the tools? See [SECURITY.md](SECURITY.md).

## ⭐ Support

If this helped you learn something, **star the repo** - it helps other students find it.

## 📜 License

[MIT](LICENSE) © Kirtan Bhatt
