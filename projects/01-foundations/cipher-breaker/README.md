# Classical Cipher Breaker

Encrypt, decrypt and **break** Caesar and Vigenere ciphers with no key - using nothing but letter statistics.

```bash
$ python cipher_breaker.py caesar crack "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"
[+] shift = 3
The quick brown fox jumps over the lazy dog

$ python cipher_breaker.py vigenere crack "$(cat secret.txt)"
[+] key = ORWELL
It was a bright cold day in April...
```

## How the attack works

**Caesar** - try all 26 shifts and score each candidate with the chi-squared statistic against English letter frequencies. The lowest score wins.

**Vigenere** - a polyalphabetic cipher, but still breakable:

1. **Find the key length.** For each candidate period `p`, split the ciphertext into `p` columns. If `p` is right, every column was encrypted with one letter, so it keeps English's *Index of Coincidence* (~0.067). Wrong periods look random (~0.038).
2. **Solve each column** as an independent Caesar cipher with chi-squared.
3. Join the shifts -> the key.

## What you'll learn

- Frequency analysis and why monoalphabetic ciphers fall instantly
- Index of Coincidence (Friedman, 1922)
- Why "more key" (one-time pad) is the only fix - and why modern crypto moved to block ciphers

## Run

```bash
python cipher_breaker.py --help
pytest -q
```

## Ideas to extend

- Kasiski examination as a second key-length estimator
- Break substitution ciphers with hill-climbing on quadgram scores
- Add Playfair and rail-fence
