# SENTINEL Guardian

SENTINEL Guardian is a security and guardrail layer for tool-using AI agents.
It evaluates proposed actions before execution and makes decisions that are
observable through structured reason codes, risk scores, and JSONL traces.

## 1. Problem

An agent may encounter hostile or misleading instructions in email, documents,
logs, tool results, or memory. Guardian is designed to reduce prompt
injection, memory poisoning, data exfiltration, and unauthorized consequential
actions without treating every untrusted string as an attack.

## 2. Core idea

Untrusted content can be evidence, but it cannot grant authority. Guardian
separates provenance and trust from the user's goal, checks tool capability and
policy authorization, detects suspicious data flow, and requires real
confirmation for consequential actions.

There are two decision-related implementations:

- `engine.py` is the standalone/reference engine used by the local engine tests.
- `app/core.py` is the production-style decision path used by the official
  HTTP-defense adapter and public evaluation.

They are intentionally not merged automatically.

## 3. Architecture

```text
Agent
  -> Candidate Action
  -> Provenance / Trust Analysis
  -> Authority / Capability Check
  -> Data-flow / Exfiltration Check
  -> Risk Analysis
  -> Decision
  -> Tool Execution
  -> Trace
```

The deployable HTTP service is in `app/`; `app/models.py` defines the wire
contract and `app/main.py` exposes `/healthz` and `/v1/decision`.

## 4. Decisions

- **ALLOW**: the action is authorized and may proceed.
- **BLOCK**: the action is disallowed or shows a strong injection, policy, or
  data-flow violation.
- **ESCALATE**: a human decision is required, typically for an unconfirmed
  consequential action.
- **REWRITE**: a safer non-final action is substituted, such as drafting
  instead of sending.

## 5. Attack classes

The implementation addresses direct and indirect prompt injection, memory
poisoning, hostile tool output, sensitive-data exfiltration, unauthorized
consequential actions, and multi-step/compositional attacks. It also includes
hard-negative handling for legitimate content that mentions security terms.

## 6. Testing and verified evaluation

Local validation currently passes:

- `tests/test_core.py`: 11/11 fixtures and 6/6 property tests.
- `tests/test_contract.py`: output-shape checks.
- `tests/test_engine.py`: standalone engine coverage.

Against the official public HTTP-defense evaluator using the documented
offline mock reference model, the latest run covered 19/19 scenarios:

| Metric | Result |
|---|---:|
| BTU | 1.0000 |
| ASR | 0.0000 |
| CVR | 0.0000 |
| FBR | 0.0230 |
| UER | 0.0345 |
| Official score | 0.989787 |

The latest measured average decision latency was approximately 3.8 ms. These
results are evidence from one local public evaluation, not a guarantee of
perfect security or hackathon success. Qwen3-8B was not used for these
measurements because its weights were unavailable in the offline environment.

## 7. Project structure

```text
app/                    Deployable FastAPI defense and decision logic
  core.py               Production-style decision path for official adapter
  decision.py           HTTP adapter entry point
  main.py               FastAPI application
  models.py             Request/response schema
engine.py               Separate standalone/reference engine
tests/                  Core, contract, and engine tests
dev/                    Fixtures, baseline comparison, training, demo tooling
dashboard/              Self-contained observability dashboard
traces/                 JSONL event traces used by the dashboard
TECHNICAL_REPORT_TEMPLATE.md
SAFETY_STATEMENT.md
STRATEGY.md
CONTRIBUTING.md
```

## 8. Running locally

From this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r app/requirements.txt
python tests/test_core.py
python tests/test_contract.py
python tests/test_engine.py
```

Start the HTTP defense:

```bash
uvicorn app.main:app --port 8080
```

The official starter kit is required for the real evaluator. From its
repository root, install it in its own environment, run the defense service,
and then use:

```bash
sentinel eval public --defense-url http://127.0.0.1:8080 --json
```

The local tools can rebuild the dashboard from traces:

```bash
python dashboard/build_dashboard.py
```

## 9. Collaboration

Clone the repository, create a branch, install the dependencies, run the
tests, make a focused change, run the tests again, and open a pull request.
See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the short workflow. Do not commit
`.env` files, credentials, virtual environments, caches, or generated local
artifacts.
