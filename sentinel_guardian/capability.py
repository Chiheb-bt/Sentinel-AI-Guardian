"""
capability.py
--------------
Capability-based declassification (Dennis & Van Horn 1966, capability
security) is the second half of the theoretical spine.

The IFC rule in provenance.py says "untrusted data alone cannot authorize a
high-impact action." That rule would be useless without an escape hatch,
because SENTINEL explicitly requires the agent to complete legitimate work
(prepare -> confirm -> execute payments, close real incidents, send real
external replies). The escape hatch is a *capability*: an unforgeable,
scoped, single-use token that can only be minted by a principal whose
effective trust is >= AUTHENTICATED_USER, and that only satisfies the
specific action it names.

This turns the fuzzy idea of "human approval" into something the engine can
check mechanically and the trace can show mechanically: either a matching,
unconsumed, unexpired capability exists, or it doesn't. There is no code
path where a sufficiently persuasive *sentence* substitutes for one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

from .provenance import Trust

# Actions that touch money, external parties, security posture, or delete
# state. These are exactly the actions the spec calls out as needing a
# human in the loop across the three domains (page 1: "unauthorized outbound
# email", "unreviewed transfers", "forged closures, monitoring shut-off").
HIGH_IMPACT_ACTIONS = {
    "send_email_external",
    "confirm_payment",
    "execute_payment",
    "share_customer_record",
    "disable_monitoring",
    "close_incident",
    "delete_record",
    "run_destructive_remediation",
}

MIN_AUTHORIZING_TRUST = Trust.AUTHENTICATED_USER


@dataclass
class Capability:
    action_type: str
    scope: Dict[str, str]           # e.g. {"payment_id": "pay_881"}
    issued_by_trust: Trust
    single_use: bool = True
    consumed: bool = False
    issued_at_step: int = 0
    expires_after_steps: Optional[int] = None


class CapabilityStore:
    """Deliberately dumb on purpose: no forging, no upgrading, no implicit
    grants. A capability exists because something with real authority
    (AUTHENTICATED_USER or SYSTEM_POLICY) explicitly created it."""

    def __init__(self) -> None:
        self._caps: list[Capability] = []

    def issue(self, action_type: str, scope: Dict[str, str],
              issued_by_trust: Trust, step: int,
              single_use: bool = True,
              expires_after_steps: Optional[int] = None) -> Optional[Capability]:
        if issued_by_trust < MIN_AUTHORIZING_TRUST:
            return None  # refuse to even mint a token from a low-trust source
        cap = Capability(action_type, dict(scope), issued_by_trust,
                          single_use, False, step, expires_after_steps)
        self._caps.append(cap)
        return cap

    def find_valid(self, action_type: str, scope: Dict[str, str],
                    current_step: int) -> Optional[Capability]:
        for cap in self._caps:
            if cap.consumed or cap.action_type != action_type:
                continue
            if cap.issued_by_trust < MIN_AUTHORIZING_TRUST:
                continue
            if cap.expires_after_steps is not None and \
                    current_step - cap.issued_at_step > cap.expires_after_steps:
                continue
            # scope must match on every key the capability declares
            if all(scope.get(k) == v for k, v in cap.scope.items()):
                return cap
        return None

    def consume(self, cap: Capability) -> None:
        if cap.single_use:
            cap.consumed = True
