# SENTINEL Guardian

**AI Agent Security & Runtime Defense**

SENTINEL Guardian is a runtime security layer for tool-using AI agents that evaluates proposed actions before execution and prevents untrusted content from becoming unauthorized authority.

Built for the **IndabaX Tunisia — SENTINEL Challenge**.

**Author:** Chiheb Ben Taghaline · [GitHub: Chiheb-bt](https://github.com/Chiheb-bt)

---

## Why SENTINEL?

Tool-using AI agents consume content from sources such as documents, email, search results, logs, and persistent memory. Those sources can contain instructions that attempt to influence the agent's next action.

SENTINEL treats provenance and trust as part of the security boundary. It separates **evidence** from **authority**, evaluates candidate actions before execution, checks capabilities and confirmation, and monitors sensitive-data flow.

The defense is designed for threats including prompt injection, indirect prompt injection, memory poisoning, hostile tool output, data exfiltration, and unauthorized consequential actions. It also preserves legitimate security analysis of suspicious content instead of blocking solely on alarming text.

## Core Security Principle

> **Untrusted content can be evidence, but it cannot grant authority.**

A document, email, log, search result, or memory item may provide useful evidence. Its instructions do not automatically become trusted commands, authorization, confirmation, or elevated capability.

SENTINEL evaluates the relationship between:

- **Provenance** — where relevant information originated.
- **Trust / taint** — how that information may affect downstream decisions.
- **Authority** — who or what is actually authorized to request the action.
- **Capability** — whether the requested operation is permitted.
- **Data flow** — whether sensitive information is moving toward an unsafe destination.
- **Consequence** — whether the candidate action creates an external side effect.

---

## Architecture

~~~mermaid
flowchart TD
    A[AI Agent] --> B[Candidate Action]
    B --> C[Provenance / Trust]
    C --> D[Authority / Capability]
    D --> E[Data-flow / Exfiltration]
    E --> F[Risk Analysis]
    F --> G{Decision}
    G -->|ALLOW| H[Tool Execution]
    G -->|BLOCK| I[Prevent Side Effect]
    G -->|ESCALATE| J[Human Review]
    G -->|REWRITE| K[Safer Action]
    H --> L[Trace / Observability]
    I --> L
    J --> L
    K --> L
~~~

The deployable HTTP defense is under `app/`. The request/response contract is defined in `app/models.py`, and `app/main.py` exposes `/healthz` and `/v1/decision`.

### Decision outcomes

| Decision | Meaning |
|---|---|
| **ALLOW** | The action passes the applicable security and authorization checks. |
| **BLOCK** | The action is prevented because a security, policy, authorization, or data-flow check fails. |
| **ESCALATE** | The system requires a human decision because sufficient authority or safety cannot be established. |
| **REWRITE** | A safer non-final action is substituted, such as drafting instead of sending. |

---

## Threat Model

| Attack / risk | Entry point | Defense | Decision |
|---|---|---|---|
| Direct prompt injection | User or agent-visible instructions | Policy, provenance, authorization | BLOCK / ESCALATE / REWRITE |
| Indirect prompt injection | Documents, email, search, external content | Provenance / trust and instruction detection | BLOCK / ESCALATE / REWRITE |
| Memory poisoning | Persistent agent memory | Memory provenance and trust inheritance | BLOCK when authority would be derived from untrusted memory |
| Hostile tool output | Search or tool results | Source trust and candidate-action checks | BLOCK unsafe follow-on action; allow legitimate read-only analysis |
| Data exfiltration | External communication and tool arguments | Sensitive-data flow detection | BLOCK |
| Unauthorized consequential action | Email, payment, or other external side effect | Capability and confirmation checks | BLOCK / ESCALATE / REWRITE |
| Multi-step attack | Chained observations and actions | Provenance, authorization, history, and risk checks | BLOCK / ESCALATE / REWRITE |
| Security-analysis hard negative | Legitimate analysis containing hostile text | Context-sensitive checks | ALLOW when the requested operation is legitimate and read-only |

---

## Security Controls

### Provenance and trust

SENTINEL records where relevant information originated and propagates trust through the provenance graph. Untrusted sources cannot silently become trusted authority downstream.

### Authority vs. evidence

Information can inform an agent's reasoning without authorizing the resulting action. Authority is evaluated separately from the content being analyzed.

### Capabilities and confirmation

Consequential actions require the applicable authorization. Confirmation is bound to the candidate action rather than treated as a generic approval signal.

### Secret-flow detection

Sensitive values are checked as they move toward external destinations. The implementation also checks common transformed representations including spaced, reversed, Base64, and hexadecimal forms.

### Memory provenance

Memory remains inside the trust boundary. Storing or recalling content does not by itself upgrade its authority.

### Rewrite and escalation

When a final side effect is not sufficiently authorized, SENTINEL can substitute a safer intermediate action or escalate for human review.

### Observability

Decisions expose structured reason codes, risk information, and JSONL traces so the security decision can be inspected after execution.

---

## Evaluation

The latest verified public HTTP-defense evaluation covered **19/19 scenarios**.

| Metric | Result |
|---|---:|
| Public scenarios | **19/19** |
| BTU | **1.0000** |
| ASR | **0.0000** |
| CVR | **0.0000** |
| FBR | **0.0230** |
| UER | **0.0345** |
| Official score | **0.989787** |
| Average decision latency | **≈ 3.8 ms** |

These results come from **one local public evaluation using the documented offline mock reference model**. They are evidence for that evaluation run, not a guarantee of perfect security or hackathon success.

The local regression suite currently contains **15 pytest-discovered tests** across the core and standalone engine test files. The contract check is a separate executable validation because it can run without the optional Pydantic test dependency.

---

## Hard Negatives

A security defense must distinguish between:

> **a malicious instruction attempting to control the agent**

and

> **legitimate security analysis containing suspicious text as evidence**.

A SOC analyst may need to inspect a malicious email, hostile log, or incident report containing phrases such as `ignore previous instructions`. Blocking the analysis merely because the text contains an alarming phrase would reduce utility without proving that the proposed action is unsafe.

SENTINEL therefore evaluates the **source, authority, requested action, and consequences**, not just the presence of suspicious strings.

---

## Demo

The demonstration flow is:

**Attack → Detection → Decision → Outcome → Trace**

Run the standalone scenario and mutation demo:

~~~bash
python run_demo.py
~~~

Generate HTTP-style decision traces for the dashboard:

~~~bash
python dev/run_demo.py
python dashboard/build_dashboard.py
~~~

The generated JSONL traces are stored under `traces/`.

---

## Repository Structure

~~~text
app/                    Deployable FastAPI defense
  core.py               HTTP decision engine
  decision.py           HTTP adapter
  main.py               FastAPI entry point
  models.py             Request/response models
  requirements.txt      HTTP-service dependencies

sentinel_guardian/      Standalone/reference security engine
tests/                  Core, contract, and engine tests
dev/                    Fixtures, evaluation, and demo tooling
scenarios/              Standalone scenario definitions
dashboard/              Trace observability dashboard
traces/                 JSONL decision traces

STRATEGY.md             Project strategy
SAFETY_STATEMENT.md     Safety statement
TECHNICAL_REPORT_TEMPLATE.md
CONTRIBUTING.md
~~~

The repository contains both a standalone/reference engine and the HTTP-defense path under `app/`. They are documented separately rather than silently presented as the same implementation.

---

## Installation

From the repository root:

~~~bash
python3 -m venv .venv
source .venv/bin/activate

# Core / standalone engine dependencies
python -m pip install -r requirements.txt

# HTTP defense dependencies
python -m pip install -r app/requirements.txt
~~~

On Windows PowerShell:

~~~powershell
.\.venv\Scripts\Activate.ps1
~~~

The root requirements file contains the standalone engine dependency; `app/requirements.txt` contains the FastAPI, Uvicorn, and Pydantic dependencies for the HTTP service.

---

## Running Tests

Run the executable regression checks:

~~~bash
python tests/test_core.py
python tests/test_contract.py
python tests/test_engine.py
~~~

If pytest is installed, the same test suite can be run with:

~~~bash
python -m pytest -q tests
~~~

The verified baseline is **15 passing pytest tests**.

---

## Running the HTTP Defense

Start the FastAPI service:

~~~bash
uvicorn app.main:app --port 8080
~~~

The service exposes:

- `GET /healthz`
- `POST /v1/decision`

---

## Public Evaluation

The official public evaluator is provided by the SENTINEL starter kit. From the starter-kit environment, the verified command is:

~~~bash
sentinel eval public --defense-url http://127.0.0.1:8080 --json
~~~

The starter kit itself is not part of this repository. Use its official documentation for the exact environment setup.

---

## Collaboration

1. Fork or clone the repository.
2. Create a focused branch.
3. Install the dependencies.
4. Run the tests.
5. Make a focused change.
6. Add regression tests for security-sensitive behavior.
7. Run the tests again.
8. Commit and push the branch.
9. Open a pull request with a concise summary, tests, security implications, and known limitations.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full workflow.

---

## Author

**Chiheb Ben Taghaline**

AI / Robotics / Security Engineering

[GitHub — Chiheb-bt](https://github.com/Chiheb-bt)

---

## Scope

SENTINEL Guardian is a defensive AI-security project. The repository reports evaluation results with their scope and limitations and does not claim perfect or guaranteed security.
