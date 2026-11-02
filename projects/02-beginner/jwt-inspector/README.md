# JWT Inspector

Decode JSON Web Tokens and audit them for the bugs that keep paying out in bug bounties.

```text
$ python jwt_inspector.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Findings:
  [HIGH  ] HMAC secret cracked: 'your-256-bit-secret' - tokens can be forged
  [MEDIUM] no 'exp' claim - token never expires
```

## Checks

| Severity | Issue |
|---|---|
| HIGH | `alg: none` / empty signature |
| HIGH | Weak HMAC secret (offline dictionary attack - no requests sent) |
| HIGH | Secrets/PII in the payload (it's only base64!) |
| MEDIUM | `jku` / `x5u` / `jwk` / `kid` headers - classic key-injection points |
| MEDIUM | No `exp` |
| LOW | RS/ES/PS algs -> test for RS256 -> HS256 algorithm confusion |
| LOW | Lifetimes over 7 days, missing `iat` |

## What you'll learn

- JWS structure: `base64url(header).base64url(payload).signature`
- Why HMAC secrets must be long and random (they can be brute-forced offline from a single token)
- Constant-time comparison with `hmac.compare_digest`
- The OWASP API Security Top 10 "Broken Authentication" category in practice

## Run

```bash
python jwt_inspector.py <token> --wordlist jwt-secrets.txt
python jwt_inspector.py --sign '{"sub":"42","role":"user"}' --secret devsecret   # craft lab tokens
pytest -q
```

> Only test tokens from applications you own or are authorized to assess.

## Ideas to extend

- Verify RS256/ES256 tokens against a JWKS URL
- Generate the algorithm-confusion payload for a lab target
- Parallel cracking with `multiprocessing` for large wordlists
