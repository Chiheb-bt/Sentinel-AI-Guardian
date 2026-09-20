# Contributing to SENTINEL Guardian

Thank you for contributing to **SENTINEL Guardian**, an AI agent security and runtime-defense project.

Repository: https://github.com/Chiheb-bt/sentinel-ai-guardian

## Development workflow

### 1. Clone

~~~bash
git clone https://github.com/Chiheb-bt/sentinel-ai-guardian.git
cd sentinel-ai-guardian
~~~

### 2. Create a branch

Use a focused branch name:

~~~bash
git switch -c feature/short-description
~~~

### 3. Install dependencies

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r app/requirements.txt
~~~

On Windows PowerShell:

~~~powershell
.\.venv\Scripts\Activate.ps1
~~~

### 4. Run the tests before changing security logic

~~~bash
python tests/test_core.py
python tests/test_contract.py
python tests/test_engine.py
~~~

### 5. Make a focused change

Security-sensitive changes should be accompanied by regression tests.

In particular, changes affecting:

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

should include tests demonstrating both the intended defense and relevant hard-negative behavior.

### 6. Run the tests again

Do not modify tests merely to hide a regression.

Record the relevant test output in the pull request description.

### 7. Commit

Use a concise commit message:

~~~bash
git add .
git commit -m "Describe the change"
~~~

### 8. Push

~~~bash
git push -u origin feature/short-description
~~~

### 9. Open a Pull Request

Include:

- what changed;
- why it changed;
- security implications;
- tests run;
- evaluation impact, if applicable;
- known limitations.

## Security and repository hygiene

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

## Architecture note

The repository currently contains both:

- `engine.py` — standalone/reference engine;
- `app/core.py` — production-style decision path used by the HTTP-defense adapter.

Do not silently change the relationship between these implementations. Changes that affect their security semantics should include regression coverage and explain the impact in the pull request.
