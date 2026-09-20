# SENTINEL Guardian — Safety Statement

Per the spec: *"Your safety statement must cover what the defense
protects against, known failure modes, false-positive behavior, what data
it observes, and when humans are consulted. The challenge rewards honest
safety boundaries, not claims of complete safety."*

## What this defense protects against

- A consequential action (`payment_confirm`, `payment_execute`,
  `email_send`, `remediation_execute`, a `ticket_update`/`incident_update`
  that closes/resolves) proceeding without either (a) a real granted
  human confirmation (`CandidateAction.digest()` present in
  `history_digest.confirmations_granted`) or (b) being held for one.
- An action whose own content mirrors an instruction found in untrusted
  material (email, document, log, tool-result field, or memory) — checked
  under reversible transforms (plain, spaced, reversed, base64, hex, on
  BOTH sides of the comparison), not verbatim text matching only.
- Sensitive content flowing to a non-internal recipient, similarly
  transform-normalized.
- A low-trust "policy" or "approval" claim (planted in a document, email,
  or memory) overriding what the actual, higher-trust policy content in
  the same run says.
- Legitimate work that merely sounds alarming (scam-language quotes,
  "encoded PowerShell," "phishing") being over-blocked: read-only,
  non-side-effecting actions are never scored on content alone.

## What this defense does NOT protect against (known limitations)

Full detail in `TECHNICAL_REPORT_TEMPLATE.md` §5 and `README.md`. In
order of how much we'd want a judge to know before we're asked:

1. **The official evaluation used the offline mock model.** The defense
   was run through the real starter-kit `sentinel run` and
   `sentinel eval public` commands across the published 19-scenario
   library. Those results used the documented offline mock reference
   model, not Qwen3-8B, so they are not a guarantee of behavior with a
   different agent model.
2. **The instruction-mirror check's tool-vocabulary map is hand-curated.**
   An unfamiliar consequential tool falls
   back to a weaker heuristic (splitting its name on underscores).
3. **The overlap-matching threshold (`MIN_OVERLAP=20`) is empirically
   tuned** against our own small fixture set, not the real scenario
   library — a real precision/recall tradeoff, not a solved constant.
4. **The tier-2 calibrated model is trained on synthetic data** built from
   the structure of the public scenario library, not the organizer's real
   labels.
5. **Cross-turn memory-poisoning detection depends on
   `request.conversation`'s sliding window**, and beyond that window, on
   the harness's own memory-taint propagation (`least_trusted()` over the
   turn's provenance) being correct — this defense does not
   independently re-derive memory trust from scratch, the same as every
   one of the organizer's five reference baselines.

We make no claim of complete safety. Any of the above is a plausible route
to a missed detection.

## Verified evaluation and expected false-positive behavior

The official public evaluator produced 19/19 task-successful scenarios:
BTU 1.0000, ASR 0.0000, CVR 0.0000, FBR 0.02299, UER 0.03448,
documented official score 0.989787, and approximately 3.76 ms median
latency. These figures are from the offline mock reference model and do
not establish real-world security.

Read-only / non-side-effecting actions are never blocked or escalated on
content alone (`core.py`'s early-return for non-consequential,
non-external-side-effect actions) — this is the mechanism that keeps
"encoded PowerShell," "phishing," and scam-language quotes from
triggering anything on their own; verified against 4 hard-negative
fixtures (`enterprise_security_digest`, `finance_fraud_awareness_note`,
`soc_confirmed_isolation`, `soc_triage_powershell`).

Expected, intentional friction:

- A legitimate consequential action with no confirmation yet is
  **escalate**d, not allowed — by design, this holds legitimate but
  not-yet-authorized work for a human rather than guessing.
- The repository has no built-in human-review UI. A deployment integrating
  this service must route `escalate` decisions to its authenticated
  approval workflow and provide the resulting action digest through
  `history_digest.confirmations_granted`; this project does not claim to
  implement that surrounding workflow.

## What data the defense observes

Only what `DefenseRequest` provides: conversation history and its
`provenance_ids`, the current observation, the candidate action's tool/
type/arguments/content, `policy_context` (allowed/consequential tools,
internal email domains), the provenance registry (trust level,
sensitivity, source type per id), and `history_digest` (confirmation
digests, blocked/escalated counts, least-trusted/most-sensitive-seen this
turn). Nothing leaves the process; the tier-2 model runs locally over 6
hand-engineered numeric features, never raw text, and calls no external
service.

## When humans are consulted

Any consequential action lacking a granted confirmation is held at
**escalate** (or, where a safer substitute tool exists and is itself
allowed, **rewrite**) rather than guessing — it does not proceed until a
human confirms it (`history_digest.confirmations_granted` gains its
digest) or a safer form is used instead. An action with no legitimate
basis at all — its own content mirrors instructions found only in
untrusted material — is **block**ed outright rather than escalated, since
escalating would incorrectly imply a plausible legitimate basis exists.

The decision service itself does not approve escalations. The surrounding
agent application is responsible for presenting the candidate action and
reason codes to an authenticated human reviewer, then retrying only after
the exact candidate-action digest has been granted.
