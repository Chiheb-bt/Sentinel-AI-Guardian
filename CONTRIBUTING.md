# Contributing to SENTINEL Guardian

## Development workflow

```bash
git clone <repository-url>
cd sentinel_guardian
git switch -c <short-description>
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r app/requirements.txt
python tests/test_core.py
python tests/test_contract.py
```

Make focused changes, preserve the separation between `engine.py` and
`app/core.py`, and run the tests again before committing:

```bash
git add .
git commit -m "Describe the change"
git push -u origin <short-description>
```

Open a pull request with a concise summary, test output, and any changes to
evaluation results. Never commit credentials, environment files, virtual
environments, caches, or generated local artifacts.
