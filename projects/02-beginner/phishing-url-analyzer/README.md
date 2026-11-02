# Phishing URL Analyzer

Explainable, offline phishing triage. Every point of risk comes with a reason, so you can defend the verdict in a ticket.

```text
$ python phish_analyzer.py "http://paypa1.com/webscr?cmd=login" "https://xn--pple-43d.com/"

[PHISHING] score=66  http://paypa1.com/webscr?cmd=login
    +10 plain HTTP (no TLS)
    +40 'paypa1' uses lookalike characters to impersonate 'paypal'
    +16 credential-themed keywords: login, webscr

[PHISHING] score=75  https://xn--pple-43d.com/
    +35 punycode/IDN host - renders as 'аpple.com'
    +40 'аpple' uses lookalike characters to impersonate 'apple'
```

The second one uses a **Cyrillic `а`** (U+0430). It looks identical to `apple.com` in many fonts.

## Signals

| Signal | Why attackers use it |
|---|---|
| IDN homographs (`xn--`) | Unicode lookalikes defeat a visual check |
| Typosquats (edit distance <= 2) | `paypa1`, `amazom`, `micros0ft` |
| Brand in subdomain | `paypal.com.account-verify.xyz` - the real domain is `account-verify.xyz` |
| `@` in authority | `https://google.com@evil.tk` goes to `evil.tk` |
| Raw IP / odd port | Throwaway infra without DNS |
| High-abuse TLDs, shorteners | Cheap, disposable, hide destination |
| High-entropy hostnames | DGA / auto-generated domains |

## What you'll learn

- URL anatomy with `urllib.parse.urlsplit` (scheme, userinfo, host, port, path)
- Punycode / IDNA and Unicode confusables
- Levenshtein distance from scratch
- Shannon entropy for detecting generated strings
- Why explainable scoring beats a black-box model for analyst workflows

## Run

```bash
python phish_analyzer.py -f urls.txt --json
pytest -q
```

## Ideas to extend

- Check domain age via RDAP (new domains are high-risk)
- Pull the live page and compare its favicon/title against the brand
- Feed in URLs extracted by [`ioc-extractor`](../../03-intermediate/ioc-extractor)
