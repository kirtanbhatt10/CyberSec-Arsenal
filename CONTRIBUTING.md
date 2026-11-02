# Contributing to CyberSec Arsenal

Thanks for helping! Students and first-time contributors are especially welcome.

## Ways to contribute

- 🐛 Fix a bug or false positive/negative in a detection
- ✨ Implement an item from a project's **"Ideas to extend"** list
- 🆕 Build a project from the [roadmap table](README.md#%EF%B8%8F-coming-next)
- 📝 Improve explanations, diagrams or examples

## Project standards

Every project lives in `projects/<tier>/<kebab-case-name>/` and must have:

1. **One main script** (`snake_case.py`) runnable with `python script.py --help`
2. **Standard library only** - if you truly need a dependency, add a `requirements.txt` in the project folder and explain why
3. **`test_<name>.py`** with pytest tests that run offline (no live targets)
4. **`README.md`** with: example output, how it works, what you'll learn, how to run, ideas to extend
5. A row added to the main README table
6. **Safe defaults** - no destructive actions, no live exploitation of third parties, clear "authorized use only" notes where relevant

Malware, credential stealers, or tools whose primary purpose is harm will not be accepted.

## Workflow

```bash
git checkout -b feat/dns-recon-tool
# ...build...
pytest            # all tests must pass
ruff check .      # lint must pass
git commit -m "feat(dns-recon): add zone transfer check"
```

We use [Conventional Commits](https://www.conventionalcommits.org): `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`.

Open a PR using the template and link the issue it closes.

## Code of conduct

Be kind, assume good faith, and help newcomers. Harassment of any kind isn't tolerated. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
