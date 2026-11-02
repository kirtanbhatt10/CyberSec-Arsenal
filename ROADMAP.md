# 🧭 Learning Roadmap

A practical path from "I just installed Python" to job-ready, mapped to the projects in this repo.

## Stage 0 - Fundamentals (4-8 weeks)

- **Networking:** OSI/TCP-IP, TCP handshake, DNS, HTTP, TLS, subnetting
- **Linux:** filesystem, permissions, processes, `systemd`, logs in `/var/log`, bash
- **Python:** files, regex, `argparse`, sockets, `asyncio` basics
- **Practice:** OverTheWire *Bandit*, TryHackMe *Pre-Security*

➡️ Build: [Password Auditor](projects/01-foundations/password-auditor), [Cipher Breaker](projects/01-foundations/cipher-breaker), [File Integrity Monitor](projects/01-foundations/file-integrity-monitor)

## Stage 1 - Core security concepts (6-10 weeks)

- CIA triad, authentication vs authorization, hashing vs encryption vs encoding
- OWASP Top 10, MITRE ATT&CK, the cyber kill chain
- Recon and scanning (nmap), log analysis, basic incident response

➡️ Build: [Async Port Scanner](projects/02-beginner/async-port-scanner), [SSH Brute-Force Detector](projects/02-beginner/ssh-bruteforce-detector), [Phishing URL Analyzer](projects/02-beginner/phishing-url-analyzer), [JWT Inspector](projects/02-beginner/jwt-inspector)

## Stage 2 - Pick a track (3-6 months)

### 🔵 Blue team / SOC Analyst
- SIEM (Splunk / Elastic / Wazuh), detection engineering, Sigma rules, threat intel
- Labs: TryHackMe SOC Level 1, Blue Team Labs Online, LetsDefend
- Certs: **CompTIA Security+** -> **CySA+** or **BTL1**
- ➡️ Build: [IOC Extractor](projects/03-intermediate/ioc-extractor), [Web Attack Detector](projects/03-intermediate/web-attack-detector)

### 🔴 Red team / Penetration Tester
- Web app testing (Burp Suite), Active Directory, privilege escalation, report writing
- Labs: PortSwigger Web Security Academy, Hack The Box, TryHackMe Jr Penetration Tester
- Certs: **eJPT** -> **PNPT** / **CPTS** -> **OSCP**
- ➡️ Build: [JWT Inspector](projects/02-beginner/jwt-inspector), extend the port scanner into a SYN scanner

### 🟢 Security Engineer / DevSecOps
- Secure SDLC, SAST/DAST, secrets management, IaC & container security, cloud IAM
- Certs: **Security+**, **AWS Security Specialty** / **AZ-500**, **CKS**
- ➡️ Build: [Secrets Scanner](projects/03-intermediate/secrets-scanner) as a pre-commit hook + GitHub Action

### 🟣 GRC / Security Analyst
- Risk assessment, ISO 27001, NIST CSF, SOC 2, DPDP Act (India) / GDPR
- Certs: **Security+**, **ISC2 CC**, then **CISA** / **CRISC** with experience

## Stage 3 - Prove it

- Push every project here with a good README (you're doing it!)
- Write up 5+ CTF / lab walkthroughs on a blog
- Contribute detection rules or fixes to an open-source security tool
- Responsible disclosure / bug bounty on in-scope programs

---

Certification names and syllabi change - always check the vendor's official page before you book an exam.
