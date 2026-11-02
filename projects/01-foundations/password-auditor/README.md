# Password Auditor

Scores a password the way a cracker thinks about it - pattern first, entropy second.

```text
$ python password_auditor.py --hibp
Password to audit (input hidden):

Length      : 11
Entropy     : ~72.1 bits
Verdict     : Very weak (0/4)
Findings    :
  - Under 12 characters - consider a longer passphrase.
  - Common password hidden behind leetspeak or trailing digits.
  - Sequential run: 123
  - Seen 128,442 times in public breaches!
```

## What you'll learn

| Concept | Where |
|---|---|
| Why "entropy" from character pools overestimates strength | `entropy_bits()` |
| How crackers apply mangling rules (leet, suffix digits) | `deleet()`, `audit()` |
| Keyboard-walk and sequence detection | `_runs()` |
| k-anonymity: checking a breach DB without sending your password | `hibp_breach_count()` |
| Reading secrets from a terminal safely | `getpass` in `main()` |

## How the HIBP check stays private

1. SHA-1 the password locally -> `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
2. Send only the first 5 chars (`5BAA6`) to the API.
3. The API returns ~800 suffixes that share that prefix (padded to hide the real count).
4. Match the remaining 35 chars locally.

The server never learns which of the hundreds of candidates was yours.

## Run

```bash
python password_auditor.py
python password_auditor.py --hibp --wordlist /usr/share/wordlists/rockyou.txt
pytest -q
```

## Ideas to extend

- Port zxcvbn's graph-based matching for non-QWERTY layouts
- Estimate crack time for online vs offline (bcrypt vs MD5) attacks
- Add a `--batch` mode for auditing exported password-manager CSVs
