import time

import pytest

from jwt_inspector import b64url_encode, decode, inspect, make_token

# The well-known jwt.io example token (secret: "your-256-bit-secret").
JWT_IO = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
          "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")


def severities(r):
    return {f.severity for f in r.findings}


def test_cracks_jwt_io_example():
    r = inspect(JWT_IO)
    assert r.cracked_secret == "your-256-bit-secret"
    assert r.payload["name"] == "John Doe"


def test_strong_secret_not_cracked_and_round_trip():
    tok = make_token({"sub": "1", "iat": int(time.time()), "exp": int(time.time()) + 600}, "x" * 48)
    r = inspect(tok)
    assert r.cracked_secret is None
    assert "HIGH" not in severities(r)


def test_alg_none_is_high():
    h = b64url_encode(b'{"alg":"none"}')
    p = b64url_encode(b'{"sub":"admin"}')
    assert "HIGH" in severities(inspect(f"{h}.{p}."))


def test_sensitive_claim_flagged():
    tok = make_token({"user": "a", "password": "hunter2", "exp": int(time.time()) + 60, "iat": 1}, "y" * 40)
    assert any("sensitive" in f.message for f in inspect(tok).findings)


def test_garbage_rejected():
    with pytest.raises(ValueError):
        decode("not.a.jwt")
