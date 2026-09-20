#!/usr/bin/env python3
"""
test_contract.py
------------------
pydantic is not installable in this sandbox (no network -- see README), so
this is a hand-written stand-in for "does core.decide()'s output actually
validate against app/models.py's DefenseDecision". Checks every constraint
that model declares: field set is exact (extra='forbid'), decision is one
of the 4 literals, risk_score/confidence are in [0,1], reason_codes has
<=16 items, explanation is <=500 chars, and the rewrite <-> rewritten_action
invariant from DefenseDecision's model_validator holds.

This is not a substitute for actually running it through pydantic in a
real environment -- do that too, first thing, once `uv sync` works.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core import decide  # noqa: E402
from dev.fixtures import FIXTURES  # noqa: E402

EXPECTED_KEYS = {"decision", "risk_score", "confidence", "reason_codes", "explanation", "rewritten_action", "metadata"}
VALID_DECISIONS = {"allow", "block", "escalate", "rewrite"}
VALID_ACTION_TYPES = {"respond", "tool_call", "memory_write", "request_confirmation"}
VALID_ARG_TYPES = (str, int, float, bool, type(None))


def check_candidate_action_shape(action: dict, path: str) -> list[str]:
    errors = []
    allowed_keys = {"type", "tool", "arguments", "content", "final", "confirmation_for"}
    extra = set(action.keys()) - allowed_keys
    if extra:
        errors.append(f"{path}: unexpected keys {extra} (CandidateAction has extra='forbid')")
    if action.get("type") not in VALID_ACTION_TYPES:
        errors.append(f"{path}: type={action.get('type')!r} not in {VALID_ACTION_TYPES}")
    for k, v in action.get("arguments", {}).items():
        if not isinstance(v, VALID_ARG_TYPES):
            errors.append(f"{path}: arguments[{k!r}]={v!r} has type {type(v)}, not str|int|float|bool|None")
    if action.get("confirmation_for") is not None:
        errors.extend(check_candidate_action_shape(action["confirmation_for"], path + ".confirmation_for"))
    return errors


def check_decision_shape(result: dict) -> list[str]:
    errors = []
    keys = set(result.keys())
    if keys != EXPECTED_KEYS:
        errors.append(f"field set mismatch: got {keys}, expected exactly {EXPECTED_KEYS}")
    if result.get("decision") not in VALID_DECISIONS:
        errors.append(f"decision={result.get('decision')!r} not in {VALID_DECISIONS}")
    for field in ("risk_score", "confidence"):
        v = result.get(field)
        if not isinstance(v, (int, float)) or not (0.0 <= v <= 1.0):
            errors.append(f"{field}={v!r} must be a float in [0.0, 1.0]")
    codes = result.get("reason_codes")
    if not isinstance(codes, list) or len(codes) > 16:
        errors.append(f"reason_codes must be a list of <=16 items, got {codes!r}")
    if not all(isinstance(c, str) for c in (codes or [])):
        errors.append("all reason_codes must be strings")
    explanation = result.get("explanation")
    if explanation is not None and (not isinstance(explanation, str) or len(explanation) > 500):
        errors.append(f"explanation must be None or a string <=500 chars, got len={len(explanation) if explanation else None}")
    # the model_validator invariant
    is_rewrite = result.get("decision") == "rewrite"
    has_rewrite_action = result.get("rewritten_action") is not None
    if is_rewrite != has_rewrite_action:
        errors.append("rewritten_action is required for, and only for, decision='rewrite'")
    if result.get("rewritten_action") is not None:
        errors.extend(check_candidate_action_shape(result["rewritten_action"], "rewritten_action"))
    if not isinstance(result.get("metadata"), dict):
        errors.append("metadata must be a dict")
    return errors


def main() -> bool:
    all_ok = True
    for scenario_id, step_desc, request, _expected in FIXTURES:
        result = decide(request)
        errors = check_decision_shape(result)
        status = "OK" if not errors else "FAIL"
        if errors:
            all_ok = False
        print(f"[{status}] {scenario_id} / {step_desc[:50]}")
        for e in errors:
            print(f"    - {e}")
    print("\nALL CONTRACT CHECKS PASSED" if all_ok else "\nSOME CONTRACT CHECKS FAILED")
    return all_ok


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
