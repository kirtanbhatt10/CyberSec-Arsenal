#!/usr/bin/env python3
"""
Classical Cipher Breaker
========================

Encrypt, decrypt and *break* Caesar and Vigenere ciphers without the key,
using the same statistics cryptanalysts used for 400 years.

Techniques
----------
* Chi-squared test against English letter frequencies (Caesar break)
* Index of Coincidence to estimate the Vigenere key length
* Splitting ciphertext into columns -> each column is just a Caesar cipher

Usage
-----
    python cipher_breaker.py caesar  encrypt --shift 3 "attack at dawn"
    python cipher_breaker.py caesar  crack  "DWWDFN DW GDZQ"
    python cipher_breaker.py vigenere encrypt --key LEMON "attack at dawn"
    python cipher_breaker.py vigenere crack  "$(cat ciphertext.txt)"
"""

from __future__ import annotations

import argparse
import string
import sys
from collections import Counter

ALPHABET = string.ascii_uppercase

# Relative frequency of letters in English text (percent).
ENGLISH_FREQ = {
    "A": 8.167, "B": 1.492, "C": 2.782, "D": 4.253, "E": 12.702, "F": 2.228,
    "G": 2.015, "H": 6.094, "I": 6.966, "J": 0.153, "K": 0.772, "L": 4.025,
    "M": 2.406, "N": 6.749, "O": 7.507, "P": 1.929, "Q": 0.095, "R": 5.987,
    "S": 6.327, "T": 9.056, "U": 2.758, "V": 0.978, "W": 2.360, "X": 0.150,
    "Y": 1.974, "Z": 0.074,
}
ENGLISH_IOC = 0.0667


def _shift_char(ch: str, shift: int) -> str:
    if ch.isupper():
        return ALPHABET[(ALPHABET.index(ch) + shift) % 26]
    if ch.islower():
        return ALPHABET[(ALPHABET.index(ch.upper()) + shift) % 26].lower()
    return ch


def caesar(text: str, shift: int) -> str:
    return "".join(_shift_char(c, shift) for c in text)


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    key = "".join(k for k in key.upper() if k in ALPHABET)
    if not key:
        raise ValueError("key must contain at least one letter")
    out, i = [], 0
    for ch in text:
        if ch.upper() in ALPHABET:
            shift = ALPHABET.index(key[i % len(key)])
            out.append(_shift_char(ch, -shift if decrypt else shift))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def letters_only(text: str) -> str:
    return "".join(c for c in text.upper() if c in ALPHABET)


def chi_squared(text: str) -> float:
    """Lower = more English-like."""
    letters = letters_only(text)
    if not letters:
        return float("inf")
    counts = Counter(letters)
    n = len(letters)
    return sum(
        (counts.get(ch, 0) - n * ENGLISH_FREQ[ch] / 100) ** 2 / (n * ENGLISH_FREQ[ch] / 100)
        for ch in ALPHABET
    )


def crack_caesar(ciphertext: str) -> tuple[int, str]:
    """Return (shift, plaintext) with the lowest chi-squared score."""
    best = min(range(26), key=lambda s: chi_squared(caesar(ciphertext, -s)))
    return best, caesar(ciphertext, -best)


def index_of_coincidence(text: str) -> float:
    letters = letters_only(text)
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def guess_key_length(ciphertext: str, max_len: int = 16) -> int:
    """Pick the period whose columns look most like English (highest average IoC)."""
    letters = letters_only(ciphertext)
    scores = {}
    for period in range(1, min(max_len, max(1, len(letters) // 2)) + 1):
        columns = [letters[i::period] for i in range(period)]
        scores[period] = sum(index_of_coincidence(c) for c in columns) / period
    # Prefer the smallest period that is close to English IoC (avoids picking multiples).
    best = max(scores.values())
    for period in sorted(scores):
        if scores[period] >= best * 0.95:
            return period
    return max(scores, key=scores.get)


def crack_vigenere(ciphertext: str, max_len: int = 16) -> tuple[str, str]:
    letters = letters_only(ciphertext)
    period = guess_key_length(ciphertext, max_len)
    key = "".join(ALPHABET[crack_caesar(letters[i::period])[0]] for i in range(period))
    return key, vigenere(ciphertext, key, decrypt=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Encrypt, decrypt and break classical ciphers.")
    p.add_argument("cipher", choices=["caesar", "vigenere"])
    p.add_argument("mode", choices=["encrypt", "decrypt", "crack"])
    p.add_argument("text")
    p.add_argument("--shift", type=int, default=3)
    p.add_argument("--key")
    a = p.parse_args(argv)

    if a.cipher == "caesar":
        if a.mode == "crack":
            shift, plain = crack_caesar(a.text)
            print(f"[+] shift = {shift}\n{plain}")
        else:
            print(caesar(a.text, a.shift if a.mode == "encrypt" else -a.shift))
    else:
        if a.mode == "crack":
            key, plain = crack_vigenere(a.text)
            print(f"[+] key = {key}\n{plain}")
        else:
            if not a.key:
                p.error("--key is required for vigenere encrypt/decrypt")
            print(vigenere(a.text, a.key, decrypt=a.mode == "decrypt"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
