# SENTINEL Guardian

**AI Agent Security & Runtime Defense**

SENTINEL Guardian is a runtime security layer for tool-using AI agents. It evaluates proposed actions before execution and prevents untrusted content from becoming unauthorized authority.

> **Core principle:** Untrusted content can be evidence, but it cannot grant authority.

Built for the **IndabaX Tunisia — SENTINEL Challenge**.

**Author:** [Chiheb Ben Taghaline](https://github.com/Chiheb-bt)

---

## Why SENTINEL?

AI agents increasingly operate across email, documents, logs, search results, memory, and external tools. That creates a security boundary that ordinary prompt filtering does not fully address: content an agent reads may contain instructions that attempt to influence what the agent does next.

SENTINEL Guardian treats the **origin and trust of information** as security-relevant. It separates evidence from authority, evaluates candidate actions before execution, checks authorization and capabilities, monitors sensitive-data flow, and produces an observable decision with a reason code.

The goal is not to block every suspicious string. A security agent should still be able to inspect hostile logs, analyze malicious documents, and investigate suspicious activity without allowing those sources to authorize consequential actions.

## Core Security Principle

**Untrusted content can be evidence, but it cannot grant authority.**

A document, email, log entry, search result, or memory item may contain useful evidence. Its instructions do not automatically become trusted commands, authorization, confirmation, or elevated capability.

SENTINEL therefore evaluates the relationship between:

- **provenance** — where information came from;
- **trust / taint** — whether that information can be trusted for the requested operation;
- **authority** — who or what is actually authorized to request the action;
- **capability** — whether the agent has the required permission;
- **data flow** — whether sensitive information is moving toward an unsafe destination;
- **consequence** — whether the proposed action creates an external side effect.

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

The deployable HTTP service is in `app/`. The request/response contract is defined in `app/models.py`, and `app/main.py` exposes `/healthz` and `/v1/decision`.

### Decision model

| Decision | Meaning |
|---|---|
| **ALLOW** | The action satisfies the applicable security and authorization checks. |
| **BLOCK** | The action is disallowed or presents a strong security, policy, or data-flow violation. |
| **ESCALATE** | A human decision is required because the system cannot establish sufficient authority or safety. |
| **REWRITE** | A safer non-final action is substituted, such as drafting instead of sending. |

---

## Threat Model

| Attack / risk | Typical entry point | Primary defense |
|---|---|---|
| Direct prompt injection | User or agent-visible instructions | Policy, provenance, action authorization |
| Indirect prompt injection | Documents, email, external content | Provenance / trust and instruction detection |
| Memory poisoning | Persistent agent memory | Memory provenance and trust inheritance |
| Hostile tool output | Search or tool results | Source trust and candidate-action checks |
| Data exfiltration | External communication / tool arguments | Sensitive-data flow detection |
| Unauthorized consequential action | Email, transfer, external side effect | Capability and confirmation checks |
| Multi-step / compositional attack | Chained observations and actions | Provenance, authorization, history, and risk checks |
| Security-analysis hard negative | Legitimate analysis of hostile content | Context-sensitive policy and utility preservation |

---

## Security Controls

### Provenance and trust

SENTINEL tracks where relevant information originated and prevents untrusted sources from silently becoming trusted authority.

### Authority vs. evidence

Information can inform an agent's reasoning without authorizing the resulting action. This distinction is central to the defense model.

### Capabilities and confirmation

Consequential actions require the appropriate authorization. Confirmation is tied to the candidate action rather than being treated as a generic approval signal.

### Sensitive-data flow

The defense checks for sensitive information moving toward external destinations, including common transformed representations such as spaced, reversed, Base64, and hexadecimal forms.

### Memory provenance

Memory is treated as part of the trust boundary. Information originating from an untrusted source must not gain authority simply because it was stored and later recalled.

### Rewrite and escalation

When a final side effect is not sufficiently authorized, SENTINEL can replace it with a safer intermediate action or escalate for human review.

### Observability

Every decision is designed to be explainable through structured reason codes, risk information, and JSONL traces.

---

## Evaluation

The latest verified public HTTP-defense evaluation covered **19/19 scenarios** using the documented offline mock reference model.

| Metric | Result |
|---|---:|
| Public scenarios | **19/19** |
| BTU | **1.0000** |
| ASR | **0.0000** |
| CVR | **0.0000** |
| FBR | **0.0230** |
| UER | **0.0345** |
| Official score | **0.989787** |
| Average decision latency | **~3.8 ms** |

Local automated validation also passes:

- 6/6 core property tests
- 9/9 standalone engine tests
- contract/output-shape checks

These results are evidence from a local public evaluation, **not a guarantee of perfect security or hackathon success**. The public evaluation used the documented offline mock reference model; Qwen3-8B was not used for these measurements because its weights were unavailable in the offline environment.

---

## Hard Negatives

A useful security agent must distinguish between:

> **an instruction attempting to control the agent**

and

> **legitimate security analysis containing suspicious instructions as evidence**.

For example, an analyst may need to read a malicious email or inspect a hostile log. Blocking the analysis merely because the text contains words such as "ignore previous instructions" would reduce utility without necessarily improving security.

SENTINEL therefore evaluates the **source, authority, requested action, and consequences**, rather than treating every suspicious string as an automatic block.

---

## Demo Flow

The core demonstration follows:

**Attack → Detection → Decision → Outcome → Trace**

1. An attacker-controlled document or other untrusted source contains an injected instruction.
2. The agent reads the content and proposes an action.
3. SENTINEL identifies the source provenance and evaluates the candidate action.
4. Authority, capability, data-flow, and risk checks are applied.
5. SENTINEL returns **BLOCK**, **ESCALATE**, or **REWRITE** when the action is not sufficiently authorized.
6. The trace shows why the decision was made and whether a harmful side effect was prevented.
7. A legitimate security-analysis hard negative demonstrates that useful investigation can still be allowed.

---

## Repository Structure

~~~text
app/                    Deployable FastAPI defense and decision logic
  core.py               Production-style decision path
  decision.py           HTTP adapter entry point
  main.py               FastAPI application
  models.py             Request/response schema

engine.py               Standalone/reference engine
tests/                  Core, contract, and engine tests
dev/                    Fixtures, baselines, training, and demo tooling
dashboard/              Observability dashboard
traces/                 JSONL event traces
STRATEGY.md             Project strategy
SAFETY_STATEMENT.md     Responsible-AI / safety statement
TECHNICAL_REPORT_TEMPLATE.md
CONTRIBUTING.md
~~~

> The repository currently contains both a standalone/reference engine and the production-style `app/core.py` decision path. They are intentionally documented separately rather than silently merged.

---

## Installation

From the repository root:

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r app/requirements.txt
~~~

On Windows PowerShell:

~~~powershell
.\.venv\Scripts\Activate.ps1
~~~

## Running Tests

Run the local test suite:

~~~bash
python tests/test_core.py
python tests/test_contract.py
python tests/test_engine.py
~~~

The current verified baseline is **15 passing tests**, with the contract/output-shape checks also passing.

## Running the HTTP Defense

Start the FastAPI defense service:

~~~bash
uvicorn app.main:app --port 8080
~~~

The service exposes:

- `GET /healthz`
- `POST /v1/decision`

## Public Evaluation

The official starter kit is required for the public evaluator. From the starter-kit environment, run the defense service and then use:

~~~bash
sentinel eval public --defense-url http://127.0.0.1:8080 --json
~~~

Use the official starter-kit documentation for the exact environment and evaluation setup.

## Dashboard

The local dashboard can be rebuilt from the available traces:

~~~bash
python dashboard/build_dashboard.py
~~~

---

## Collaboration

1. Clone the repository.
2. Create a focused feature branch.
3. Install the dependencies.
4. Run the tests before making changes.
5. Make a focused change.
6. Add or update regression tests for security-sensitive behavior.
7. Run the full test suite again.
8. Push the branch.
9. Open a pull request with a concise summary and test results.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the collaboration workflow.

Do not commit credentials, `.env` files, virtual environments, caches, or local generated artifacts.

---

## Responsible AI

SENTINEL is a defensive security project. Its purpose is to reduce unauthorized or unsafe behavior by tool-using AI agents while preserving legitimate analysis and user utility.

The system is not presented as perfectly secure. Evaluation results are reported with their scope and limitations, and security decisions remain subject to the assumptions and coverage of the implemented threat model.

---

## Author

**Chiheb Ben Taghaline**

AI / Robotics / Security Engineering

[GitHub — Chiheb-bt](https://github.com/Chiheb-bt)

---

## License

No license is currently declared for this repository. If the project is intended for public reuse, add an explicit license before presenting it as an open-source project.
