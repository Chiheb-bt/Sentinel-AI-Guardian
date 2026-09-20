# SENTINEL Guardian — strategy notes

No one can promise a win against 100+ teams. What follows is why this
design is built the way it is, grounded in the real starter kit's own
`docs/scoring.md` and source code, not just the spec PDF.

## 1. Every team gets the same six trust levels — that can't be the differentiator

`src/sentinel/core/provenance.py` hands every team `TrustLevel`,
`Sensitivity`, and a `least_trusted()` helper. `src/sentinel/defenses/
baselines/` ships FIVE working baselines, one of which (`provenance.py`)
already does tool-permission checks, confirmation checks, and verbatim
instruction-overlap detection — and documents its own limitation in its
own docstring: *"taint is tracked by verbatim text overlap, so
paraphrased, encoded, or fragmented instructions and values can slip
through."*

Run `python3 dev/mini_eval.py`. That baseline alone reaches 83% BTU / 20%
ASR / 0% FBR against our fixtures — a **strong** starting point most teams
will reach for free just by reading the starter kit closely. If your
team's headline finding is "we did trust-based filtering," you are
competing on execution polish against 100 teams who read the same
`baselines/provenance.py` you did. The differentiators have to be things
that baseline explicitly doesn't do:

1. **Close its named gap.** Transform-normalized matching (base64/hex/
   reversed/spaced, checked on BOTH sides of the comparison — see
   `app/core.py`'s `_overlaps()`) instead of verbatim-only. This is not
   speculative: `dev/mini_eval.py` shows the organizer's own best baseline
   missing exactly the one scenario (`enterprise_poisoned_invoice`) this
   closes.
2. **Split what it collapses.** The baseline's `is_consequential +
   is_confirmed` check treats "did a human ask for this" and "does the
   data supporting this deserve trust" as one gate. Splitting them (axis A
   / axis B in `core.py`) is what correctly handles `direct_instruction`
   attacks (the user's OWN request is out of policy — axis A says
   nothing, only tool permission and confirmation catch it) versus
   `indirect_prompt_injection` attacks (the tool is legitimately allowed —
   only axis A catches it).
3. **Calibrate, don't hand-tune.** `heuristic_risk` (the organizer's own
   additive-score baseline) misses `enterprise_security_digest` and
   `finance_false_approval` outright — not because the logic is wrong,
   but because `MISSING_CONFIRMATION`'s fixed `+0.35` lands at 0.4,
   just under its own `ESCALATE_AT = 0.45` threshold. A fixed-constant
   score has no mechanism to notice it's wrong at the boundary; a
   genuinely trained-and-calibrated model (`dev/train_soft_risk.py`,
   real numpy logistic regression + a reliability curve, baked into
   `core.py` as constants) does.
4. **Read `history_digest`.** `grep history_digest
   src/sentinel/defenses/baselines/*.py` — only `heuristic_risk` touches
   it, and only as two booleans (`least_trusted_seen`,
   `most_sensitive_seen`). None of the five use `blocked_count` /
   `escalated_count` at all. `core.py`'s tier-2 features do.
5. **Show the iteration, not just the result.** Building the fuzzy matcher
   above took three real bugs, found by testing against realistic
   fixtures and fixed in order: an anchor that only matched the literal
   tool identifier (real injected text says "email the result to...", not
   "call email_draft with..."); a false positive from matching on routing
   metadata (a vendor's own address, which legitimately appears in their
   own document) instead of content fields; and a spaced-out evasion that
   slipped through because only one side of the comparison was
   normalized. All three are documented inline in `app/core.py` and in
   `README.md`. This is exactly what `docs/scoring.md` rewards under
   Technical Report (25 pts, "concrete failure analysis: where and why
   the defense breaks") and under the general principle stated on the
   scoring page: *"an honest failure shown and explained scores higher
   than a hidden one."*

## 2. Where the 100 points live (`docs/scoring.md`)

```
Video & Observability   40   <- spend the most real hours here
Technical Report        25   <- second most; ablation + failure analysis are graded line items
Creativity & Novelty    15   <- smallest bucket, hardest to pad with effort
Engineering & Resp. AI  20   <- mostly "did you do what you said you'd do"
```

Concretely, given the real system:

- **The dashboard is the single highest-leverage artifact you can build**,
  because "Legibility" (part of the 40) explicitly wants risk score,
  confidence, reason codes, and what happened next to be visually clear —
  and the organizer's own `sentinel replay` CLI (`src/sentinel/evaluator/
  replay.py`) is a plain-text scroll of exactly that data. A genuinely
  interactive trace viewer (`dashboard/observability_dashboard.html` in
  this repo: click any event, see the provenance graph walk from
  `provenance_refs` to the actual source events, not just a log line) is
  a visible, judgeable step up from what the starter kit hands you for
  free.
- **The ablation study is a graded line item, not a formality.**
  `dev/mini_eval.py` produces the six-way table in `README.md` from real
  code, against the organizer's own real baselines — reproducible with
  one command, not typed by hand.
- **"Creativity & Novelty" (15 pts) rewards going beyond what SENTINEL
  hands you "out of the box."** The five given baselines ARE the box.
  Doing something none of the five do (transform-normalized matching +
  the two-axis split + calibration + `history_digest` usage) is the
  concrete, checkable version of that requirement.

## 3. Two attack families need two different mechanisms — don't rely on one clever trick

Reading `scenarios/public/enterprise/enterprise_direct_token_request.yaml`
against `enterprise_poisoned_invoice.yaml` side by side is the clearest
way to see this:

- **`direct_instruction`**: the user's own message asks for `email_send`
  to an external helpdesk with a restricted token. `email_send` isn't
  even in `allowed_tools` for that scenario — this is caught by the
  cheapest possible check (tool permission), and axis A (does this mirror
  *injected* content) is irrelevant, because nothing was injected — the
  authenticated user asked for it directly. Axis B / tool-permission is
  what has to stop this.
- **`indirect_prompt_injection`**: the poisoned invoice attack uses
  `email_draft`, a tool that IS legitimately allowed and IS the same tool
  the correct, legitimate reply to the same vendor uses. Tool permission
  says nothing here. Only recognizing that this specific action's content
  mirrors an instruction embedded in untrusted material (axis A) stops it
  — and only checking CONTENT fields, not the recipient, keeps that same
  check from wrongly blocking the legitimate reply (see `core.py`'s
  `CONTENT_ARG_KEYS` and the false positive it fixed).

A defense built around only one of these mechanisms will look strong on
whichever attack family it's tuned for and silently fail the other. Test
against both before you believe either number.

## 4. Disqualifying mistakes to actively guard against

- **Scenario-specific hard-coding disqualifies a decision "however
  correct it looks in the video"** (spec, and implicitly enforced by the
  fact that `DefenseRequest` never includes a scenario id or label at
  all — `core.decide()` has nothing to key off even if you wanted to).
  Audit anything a teammate adds under day-5 pressure against this.
- **Over-blocking is graded, not just under-blocking.** `FBR` and `UER`
  in `docs/scoring.md`'s own metric list exist specifically to catch
  teams that got scared and blocked/escalated everything.
  `soc_triage_powershell` and `finance_fraud_awareness_note` (both hard
  negatives full of alarming vocabulary, both non-consequential) exist in
  `dev/fixtures.py` to keep this honest as you add rules.
- **Declare every external model/dataset** (Team Requirements). This
  defense's only "model" is the tier-2 logistic regression trained on a
  self-written synthetic corpus (`dev/train_soft_risk.py`) — declare that
  plus Qwen3-8B (the reference agent) in the technical report.

## 5. What this repo is, and isn't

A working reference implementation, tested against realistic (not
organizer-provided) fixtures built by hand from the real scenario YAMLs,
because this environment had no internet access to run the real `sentinel
run` / `sentinel eval` commands. See `README.md`'s "What's real here and
what isn't" and `app/README.md` for exactly what to verify first once you
have a working `uv sync` environment.
