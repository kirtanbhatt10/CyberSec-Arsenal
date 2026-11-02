#!/usr/bin/env python3
"""
JWT Inspector
=============

Decode a JSON Web Token and audit it for the mistakes that show up again
and again in real-world bug bounty reports.

Checks
------
* ``alg: none`` / missing signature
* Weak HMAC secret (dictionary test against a wordlist you supply)
* Algorithm-confusion risk (``kid``/``jku``/``x5u``/``jwk`` header injection points)
* Missing or excessive ``exp``, missing ``iat``/``nbf``, already-expired tokens
* Sensitive-looking claims stored in the (only base64-encoded!) payload

Use on tokens from applications you are authorized to test.

Usage
-----
    python jwt_inspector.py <token>
    python jwt_inspector.py <token> --wordlist secrets.txt
    python jwt_inspector.py --sign '{"sub":"1"}' --secret dev-secret   # make test tokens
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
from dataclasses import dataclass, field

HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "ssn", "credit_card", "card", "cvv",
                  "api_key", "apikey", "private_key", "aadhaar", "pan"}
DEFAULT_SECRETS = ["secret", "password", "123456", "changeme", "jwt", "key", "your-256-bit-secret",
                   "supersecret", "test", "dev", "admin", "qwerty", "secretkey", "jwtsecret"]


def b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass
class Finding:
    severity: str  # HIGH / MEDIUM / LOW / INFO
    message: str


@dataclass
class Inspection:
    header: dict
    payload: dict
    signature: str
    findings: list[Finding] = field(default_factory=list)
    cracked_secret: str | None = None


def decode(token: str) -> tuple[dict, dict, str, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("a JWS must have exactly 3 dot-separated parts")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"not valid base64url JSON: {exc}") from exc
    return header, payload, parts[2], f"{parts[0]}.{parts[1]}"


def sign_hs(signing_input: str, secret: str, alg: str = "HS256") -> str:
    mac = hmac.new(secret.encode(), signing_input.encode(), HMAC_ALGS[alg]).digest()
    return b64url_encode(mac)


def make_token(payload: dict, secret: str, alg: str = "HS256") -> str:
    header = b64url_encode(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header}.{body}.{sign_hs(f'{header}.{body}', secret, alg)}"


def crack_hmac(signing_input: str, signature: str, alg: str, candidates) -> str | None:
    for candidate in candidates:
        candidate = candidate.rstrip("\r\n")
        if hmac.compare_digest(sign_hs(signing_input, candidate, alg), signature):
            return candidate
    return None


def inspect(token: str, candidates=None, now: float | None = None) -> Inspection:
    header, payload, sig, signing_input = decode(token)
    r = Inspection(header, payload, sig)
    now = now or time.time()
    alg = str(header.get("alg", "")).upper()

    if alg in ("", "NONE") or not sig:
        r.findings.append(Finding("HIGH", "unsigned token (alg=none / empty signature) - anyone can forge it"))
    elif alg in HMAC_ALGS:
        secret = crack_hmac(signing_input, sig, alg, candidates or DEFAULT_SECRETS)
        if secret is not None:
            r.cracked_secret = secret
            r.findings.append(Finding("HIGH", f"HMAC secret cracked: '{secret}' - tokens can be forged"))
        else:
            r.findings.append(Finding("INFO", "HMAC secret not in wordlist"))

    for hdr in ("jku", "x5u", "jwk", "kid"):
        if hdr in header:
            r.findings.append(Finding("MEDIUM", f"'{hdr}' header present - verify the server doesn't trust it blindly "
                                                 "(key injection / path traversal / SQLi via kid)"))
    if alg.startswith(("RS", "ES", "PS")):
        r.findings.append(Finding("LOW", "asymmetric alg - test for RS256->HS256 algorithm confusion"))

    exp = payload.get("exp")
    if exp is None:
        r.findings.append(Finding("MEDIUM", "no 'exp' claim - token never expires"))
    elif isinstance(exp, (int, float)):
        if exp < now:
            r.findings.append(Finding("INFO", f"expired {int(now - exp)}s ago"))
        elif exp - now > 7 * 86400:
            r.findings.append(Finding("LOW", f"long lifetime: expires in {int((exp - now) / 86400)} days"))
    if "iat" not in payload:
        r.findings.append(Finding("LOW", "no 'iat' claim"))

    leaked = sorted(k for k in payload if k.lower() in SENSITIVE_KEYS)
    if leaked:
        r.findings.append(Finding("HIGH", f"sensitive data in payload (base64 is not encryption): {', '.join(leaked)}"))
    return r


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Decode and audit JSON Web Tokens.")
    ap.add_argument("token", nargs="?")
    ap.add_argument("--wordlist", help="candidate HMAC secrets, one per line")
    ap.add_argument("--sign", metavar="JSON", help="create a test token from this payload")
    ap.add_argument("--secret", default="secret")
    ap.add_argument("--alg", default="HS256", choices=sorted(HMAC_ALGS))
    a = ap.parse_args(argv)

    if a.sign:
        print(make_token(json.loads(a.sign), a.secret, a.alg))
        return 0
    if not a.token:
        ap.error("token required")

    try:
        if a.wordlist:
            with open(a.wordlist, encoding="utf-8", errors="ignore") as fh:
                result = inspect(a.token, fh)
        else:
            result = inspect(a.token)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    print("Header :", json.dumps(result.header, indent=2))
    print("Payload:", json.dumps(result.payload, indent=2))
    print("\nFindings:")
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    for f in sorted(result.findings, key=lambda f: order[f.severity]):
        print(f"  [{f.severity:<6}] {f.message}")
    return 1 if any(f.severity == "HIGH" for f in result.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
