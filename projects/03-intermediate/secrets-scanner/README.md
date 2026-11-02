# Secrets Scanner

Finds leaked credentials in your working tree **and every commit in git history** - a key you "deleted" last week is still one `git log -p` away for anyone who clones the repo.

```text
$ python secrets_scanner.py ../vulnerable-app --git-history
[aws-access-key-id] settings.py:3 @9f1c2ab4e0
    AWS access key ID: AKIA************6RTV
[generic-high-entropy] app/config.js:12
    High-entropy secret (H=4.12): q8Zr************pYc

2 potential secret(s) found
```

Secrets are **always redacted** in output so the report itself doesn't become a leak.

## Detection layers

1. **Provider rules** - AWS, GitHub (classic + fine-grained), Slack, Stripe, Google, OpenAI, JWTs, DB connection strings, PEM private keys.
2. **Generic assignments** - `password = "..."`, `api_key: '...'` - kept only if the value's Shannon entropy is >= 3.5 bits/char and it isn't an obvious placeholder.
3. **Suppression** - add `# secrets-scanner: ignore` to a line that is a known false positive, or list path globs (one per line) in a `.secrets-scanner-ignore` file at the scan root. Path ignores apply to git history too.

```text
# .secrets-scanner-ignore
tests/fixtures/*
docs/examples/*.md
```

## Use it in CI (GitHub code scanning)

```yaml
- run: python secrets_scanner.py . --format sarif > secrets.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: secrets.sarif }
```

## What you'll learn

- Why git history is the real attack surface (`git log -p --all`)
- Shannon entropy as a false-positive filter
- SARIF, the standard format for static-analysis results
- Incident response: **rotate first**, then rewrite history with `git filter-repo`

## Run

```bash
python secrets_scanner.py . --format json
pytest -q
```

## Ideas to extend

- Verify AWS/GitHub keys are live with a read-only API call (with permission!)
- pre-commit hook mode that only scans staged changes
- Baseline file so existing accepted findings don't fail CI
