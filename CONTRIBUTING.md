# Contributing to SENTINEL Guardian

Repository: https://github.com/Chiheb-bt/sentinel-ai-guardian

SENTINEL Guardian is an AI agent security and runtime-defense project. Contributions should preserve the security boundary and keep changes focused and testable.

## Development workflow

### 1. Fork or clone

Clone the repository:

~~~bash
git clone https://github.com/Chiheb-bt/sentinel-ai-guardian.git
cd sentinel-ai-guardian
~~~

If you fork the repository, use your fork as the `origin` remote and the main repository as `upstream` when appropriate.

### 2. Create a branch

Use a focused branch name:

~~~bash
git switch -c feature/short-description
~~~

### 3. Install dependencies

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r app/requirements.txt
~~~

On Windows PowerShell:

~~~powershell
.\.venv\Scripts\Activate.ps1
~~~

### 4. Run the tests

Run the regression checks before changing security logic:

~~~bash
python tests/test_core.py
python tests/test_contract.py
python tests/test_engine.py
~~~

If pytest is installed:

~~~bash
python -m pytest -q tests
~~~

### 5. Make a focused change

Keep security changes narrow and explain their effect.

Changes affecting any of the following should include regression coverage:

- provenance
- trust / taint
- authority
- capabilities
- confirmation
- memory
- secret detection
- data flow
- decision policies
- rewrite / escalation behavior

Where relevant, tests should cover both the intended defense and a legitimate hard-negative case.

### 6. Run the tests again

Run the full test suite after the change. Do not modify tests merely to hide a regression.

Include the relevant test output in the pull request description.

### 7. Commit

Use a concise commit message:

~~~bash
git add .
git commit -m "Describe the change"
~~~

### 8. Push

Push the focused branch:

~~~bash
git push -u origin feature/short-description
~~~

### 9. Open a Pull Request

Use the repository's pull-request workflow and include:

- what changed;
- why it changed;
- security implications;
- tests run;
- evaluation impact, if applicable;
- known limitations.

## Architecture boundary

The repository currently contains two related implementations:

- `sentinel_guardian/` — standalone/reference security engine;
- `app/core.py` — decision path used by the HTTP-defense service.

Do not silently change their relationship. Security-semantic changes should include regression tests and clearly describe which path is affected.

## Repository hygiene

Never commit:

- API keys
- passwords
- access tokens
- private keys
- credentials
- `.env` files
- virtual environments
- caches
- local generated artifacts

If you discover a security-sensitive issue, avoid publishing exploitable details in a public issue before the maintainer has reviewed it.

## Pull-request standard

A good contribution should be:

- focused;
- reproducible;
- tested;
- explicit about security impact;
- honest about limitations.
