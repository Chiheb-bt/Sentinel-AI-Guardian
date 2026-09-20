#!/usr/bin/env python3
"""tests/test_core.py -- runs dev/fixtures.py through app/core.decide()."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core import decide  # noqa: E402
from dev.fixtures import FIXTURES  # noqa: E402


def run_fixtures(verbose: bool = True) -> bool:
    all_pass = True
    print(f"{'scenario':32} {'step':52} {'expected':10} {'actual':10}")
    print("-" * 110)
    for scenario_id, step_desc, request, expected in FIXTURES:
        result = decide(request)
        actual = result["decision"]
        ok = actual == expected
        all_pass &= ok
        mark = "PASS" if ok else "FAIL <---"
        print(f"{scenario_id:32} {step_desc[:50]:52} {expected:10} {actual:10} {mark}")
        if verbose and not ok:
            print(f"    reason_codes={result['reason_codes']} risk={result['risk_score']} "
                  f"explanation={result['explanation']}")
    print("-" * 110)
    print("ALL FIXTURES PASSED" if all_pass else "SOME FIXTURES FAILED")
    return all_pass


# ---------------------------------------------------------------------
# Property tests, independent of the scenario fixtures.
# ---------------------------------------------------------------------

def _hist(**kw):
    base = dict(steps_taken=1, turn_index=0, tool_calls=[], confirmations_granted=[],
                blocked_count=0, escalated_count=0, least_trusted_seen=None, most_sensitive_seen=None)
    base.update(kw)
    return base


def test_tool_not_allowed_blocks():
    from app.core import decide
    req = {
        "run_id": "t1", "step_id": 1, "user_goal": "x", "conversation": [], "observation": None,
        "candidate_action": {"type": "tool_call", "tool": "email_send", "arguments": {"to": "x@y.com"}},
        "policy_context": {"allowed_tools": ["email_read"], "consequential_tools": ["email_send"]},
        "provenance": [], "history_digest": _hist(),
    }
    assert decide(req)["decision"] == "block"


def test_confirmed_consequential_allows():
    from app.core import action_digest, decide
    action = {"type": "tool_call", "tool": "payment_confirm", "arguments": {"payment_id": "p1"}}
    req = {
        "run_id": "t2", "step_id": 1, "user_goal": "x", "conversation": [], "observation": None,
        "candidate_action": action,
        "policy_context": {"allowed_tools": ["payment_confirm"], "consequential_tools": ["payment_confirm"]},
        "provenance": [], "history_digest": _hist(confirmations_granted=[action_digest(action)]),
    }
    assert decide(req)["decision"] == "allow"


def test_digest_is_order_independent_and_whitespace_normalized():
    from app.core import action_digest
    a = {"type": "tool_call", "tool": "x", "arguments": {"a": 1, "b": "  hi   there "}}
    b = {"type": "tool_call", "tool": "x", "arguments": {"b": "hi there", "a": 1}}
    assert action_digest(a) == action_digest(b)


def test_request_confirmation_always_allowed():
    from app.core import decide
    req = {
        "run_id": "t3", "step_id": 1, "user_goal": "x", "conversation": [], "observation": None,
        "candidate_action": {
            "type": "request_confirmation",
            "confirmation_for": {"type": "tool_call", "tool": "payment_execute", "arguments": {"payment_id": "p1"}},
        },
        "policy_context": {"allowed_tools": ["payment_execute"], "consequential_tools": ["payment_execute"]},
        "provenance": [], "history_digest": _hist(),
    }
    assert decide(req)["decision"] == "allow"


def test_rewrite_produces_valid_rewritten_action():
    from app.core import decide
    req = {
        "run_id": "t4", "step_id": 1, "user_goal": "x", "conversation": [], "observation": None,
        "candidate_action": {"type": "tool_call", "tool": "email_send",
                              "arguments": {"to": "a@atlas.example", "subject": "s", "body": "b"}},
        "policy_context": {"allowed_tools": ["email_send", "email_draft"], "consequential_tools": ["email_send"]},
        "provenance": [], "history_digest": _hist(),
    }
    result = decide(req)
    assert result["decision"] == "rewrite"
    assert result["rewritten_action"] is not None
    assert result["rewritten_action"]["tool"] == "email_draft"


def test_every_decision_has_valid_risk_and_confidence_bounds():
    from app.core import decide
    for _, _, request, _ in __import__("dev.fixtures", fromlist=["FIXTURES"]).FIXTURES:
        result = decide(request)
        assert 0.0 <= result["risk_score"] <= 1.0
        assert 0.0 <= result["confidence"] <= 1.0
        assert result["decision"] in ("allow", "block", "escalate", "rewrite")
        if result["decision"] == "rewrite":
            assert result["rewritten_action"] is not None
        else:
            assert result["rewritten_action"] is None


ALL_TESTS = [v for k, v in list(globals().items()) if k.startswith("test_")]


if __name__ == "__main__":
    fixtures_ok = run_fixtures()
    print()
    failed = 0
    for t in ALL_TESTS:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
    print(f"\n{len(ALL_TESTS) - failed}/{len(ALL_TESTS)} property tests passed")
    sys.exit(0 if fixtures_ok and not failed else 1)
