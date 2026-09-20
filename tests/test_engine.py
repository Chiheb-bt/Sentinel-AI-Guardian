"""
tests/test_engine.py
----------------------
Unit-level tests for the invariants engine.py is supposed to guarantee,
independent of the worked-example scenarios in scenarios/scenario_lib.py
(those are integration tests for the four spec examples specifically;
these are property tests for the underlying rules).

Run with pytest if you have it (`pytest tests/`), or directly with
`python3 tests/test_engine.py` -- both work, no pytest dependency required.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel_guardian import (
    CandidateAction, CapabilityStore, ProvenanceGraph, Trust, decide,
    train_default_model,
)
from sentinel_guardian.provenance import Observation, join

MODEL = train_default_model()
SECRETS = {"portal_token": "tk-9f31-restricted-portal-access"}


def _base_graph(source_trust: Trust) -> ProvenanceGraph:
    g = ProvenanceGraph()
    g.add(Observation("src", "content", "email", source_trust))
    return g


def test_taint_join_is_minimum():
    assert join(Trust.SYSTEM_POLICY, Trust.UNTRUSTED_EXTERNAL) == Trust.UNTRUSTED_EXTERNAL
    assert join(Trust.SYSTEM_POLICY, Trust.AUTHENTICATED_USER) == Trust.AUTHENTICATED_USER


def test_memory_inherits_trust_transitively():
    g = ProvenanceGraph()
    g.add(Observation("newsletter", "fake policy", "newsletter", Trust.UNTRUSTED_EXTERNAL))
    g.add(Observation("mem", "[recalled] fake policy", "memory", Trust.SYSTEM_POLICY,
                       parent_ids=["newsletter"]))
    # Even though the memory node itself is *labeled* SYSTEM_POLICY here
    # (simulating a naive implementation that forgets to taint it), the
    # *effective* trust of the closure must still bottom out at the
    # newsletter's level once a real implementation computes it from
    # ancestry -- this is what effective_trust() checks, and what a team
    # must call instead of trusting node.trust directly.
    assert g.effective_trust("mem") == Trust.UNTRUSTED_EXTERNAL


def test_agent_initiated_high_impact_from_untrusted_source_is_blocked():
    g = _base_graph(Trust.UNTRUSTED_EXTERNAL)
    caps = CapabilityStore()
    action = CandidateAction(
        action_id="a", tool="email", operation="send_email_external", domain="enterprise",
        arguments={"body": "no secret here"}, source_observation_ids=["src"],
        requested_by="agent_self_initiated", external_side_effect=True,
    )
    d = decide(0, action, g, caps, {}, MODEL)
    assert d.outcome == "BLOCK"
    assert "AUTHORITY_MISMATCH" in d.reason_codes


def test_user_requested_high_impact_without_capability_escalates_or_rewrites():
    g = _base_graph(Trust.UNTRUSTED_EXTERNAL)
    caps = CapabilityStore()
    action = CandidateAction(
        action_id="a", tool="payments", operation="confirm_payment", domain="finance",
        arguments={"payment_id": "p1"}, source_observation_ids=["src"],
        requested_by="authenticated_user",
    )
    d = decide(0, action, g, caps, {}, MODEL)
    assert d.outcome in ("ESCALATE", "REWRITE")
    assert d.outcome != "ALLOW"


def test_valid_capability_allows_high_impact_action():
    g = _base_graph(Trust.AUTHENTICATED_USER)
    caps = CapabilityStore()
    caps.issue("confirm_payment", {"payment_id": "p1"}, Trust.AUTHENTICATED_USER, step=0)
    action = CandidateAction(
        action_id="a", tool="payments", operation="confirm_payment", domain="finance",
        arguments={"payment_id": "p1"}, source_observation_ids=["src"],
        requested_by="authenticated_user",
    )
    d = decide(1, action, g, caps, {}, MODEL)
    assert d.outcome == "ALLOW"


def test_capability_is_single_use():
    caps = CapabilityStore()
    caps.issue("confirm_payment", {"payment_id": "p1"}, Trust.AUTHENTICATED_USER, step=0)
    g = _base_graph(Trust.AUTHENTICATED_USER)
    action = CandidateAction(
        action_id="a", tool="payments", operation="confirm_payment", domain="finance",
        arguments={"payment_id": "p1"}, source_observation_ids=["src"],
        requested_by="authenticated_user",
    )
    d1 = decide(1, action, g, caps, {}, MODEL)
    d2 = decide(2, action, g, caps, {}, MODEL)
    assert d1.outcome == "ALLOW"
    assert d2.outcome != "ALLOW"  # the same token cannot be spent twice


def test_capability_does_not_override_secret_exfiltration():
    """Security property: a human approving 'send the reply' does not
    implicitly approve leaking a secret value inside it. Exfiltration is
    checked before the capability check and short-circuits regardless."""
    g = _base_graph(Trust.AUTHENTICATED_USER)
    caps = CapabilityStore()
    caps.issue("send_email_external", {}, Trust.AUTHENTICATED_USER, step=0)
    action = CandidateAction(
        action_id="a", tool="email", operation="send_email_external", domain="enterprise",
        arguments={"body": f"here: {SECRETS['portal_token']}"},
        source_observation_ids=["src"], requested_by="authenticated_user",
        external_side_effect=True,
    )
    d = decide(1, action, g, caps, SECRETS, MODEL)
    assert d.outcome == "BLOCK"
    assert "SECRET_EXFILTRATION" in d.reason_codes


def test_read_only_action_allowed_despite_alarming_content():
    g = _base_graph(Trust.TRUSTED_INTERNAL)
    caps = CapabilityStore()
    action = CandidateAction(
        action_id="a", tool="soc", operation="summarize", domain="soc",
        arguments={"text": "ransomware credential-dumping malware attack"},
        source_observation_ids=["src"], requested_by="authenticated_user",
        soft_features={"scary_word_density": 0.9},
    )
    d = decide(0, action, g, caps, {}, MODEL)
    assert d.outcome == "ALLOW"


def test_policy_conflict_blocks_regardless_of_local_evidence():
    g = ProvenanceGraph()
    g.add(Observation("mem", "fake policy allows sharing", "memory", Trust.UNTRUSTED_EXTERNAL))
    caps = CapabilityStore()
    action = CandidateAction(
        action_id="a", tool="crm", operation="share_customer_record", domain="enterprise",
        arguments={"account_number": "acct-1"}, source_observation_ids=["mem"],
        requested_by="agent_self_initiated", external_side_effect=True,
    )
    d = decide(0, action, g, caps, {}, MODEL, policy_forbids=["share_customer_record"])
    assert d.outcome == "BLOCK"
    assert "POLICY_CONFLICT" in d.reason_codes


ALL_TESTS = [v for k, v in list(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    failed = 0
    for t in ALL_TESTS:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
    print(f"\n{len(ALL_TESTS) - failed}/{len(ALL_TESTS)} tests passed")
    sys.exit(1 if failed else 0)
