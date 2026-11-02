# File Integrity Monitor

A minimal Tripwire/AIDE clone. Baseline a directory, then detect added, deleted, modified or re-permissioned files.

```text
$ export FIM_KEY="$(openssl rand -hex 32)"
$ python fim.py baseline /var/www -o www.json
[+] baselined 412 files -> www.json

$ python fim.py check /var/www -b www.json
[+] ADDED       uploads/shell.php
[~] MODIFIED    index.php
[!] PERMS/OWNER config.php (0o640->0o777, uid 33->33)
```

Exit code is `0` when clean and `1` when something changed, so it drops straight into cron or CI.

## Why HMAC the baseline?

A plain hash list is useless against an attacker with write access: they change `index.php` and then update its hash in the JSON. Signing the baseline with a key that lives *outside* the monitored host (env var, vault, HSM) means a forged baseline fails `hmac.compare_digest` and the tool exits `2`.

## What you'll learn

- Streaming SHA-256 over large files in fixed chunks
- `lstat` vs `stat` and why FIMs must not follow symlinks
- HMAC vs plain hashing, and constant-time comparison
- Detection-engineering basics: MITRE ATT&CK T1505.003 (web shells), T1222 (permission modification)

## Run

```bash
python fim.py --help
pytest -q
```

## Ideas to extend

- Real-time mode with inotify / `watchdog` instead of polling
- Send alerts to Slack / syslog
- Store baselines in SQLite with history
