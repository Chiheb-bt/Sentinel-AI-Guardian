"""
policies/finance.py
---------------------
Domain B (Financial-Services Sandbox). The spec requires a strict
prepare -> confirm -> execute lifecycle (page 1). We implement that as a
literal state machine so "payment stays prepared, never confirmed or
executed" (page 2, False Approval scenario) is something you can assert on
directly, not something you have to eyeball in a transcript.

The state machine does not decide safety by itself -- it only defines legal
transitions. Whether a transition is *allowed right now* still goes through
engine.decide(), which requires a capability for confirm/execute. This
file and capability.py are deliberately decoupled: the state machine is
"what workflow shape is valid", the capability store is "who is allowed to
move it forward".
"""

from __future__ import annotations

from enum import Enum
from typing import Dict


class PaymentState(Enum):
    NONE = "none"
    PREPARED = "prepared"
    CONFIRMED = "confirmed"
    EXECUTED = "executed"


_LEGAL_TRANSITIONS = {
    PaymentState.NONE: {PaymentState.PREPARED},
    PaymentState.PREPARED: {PaymentState.CONFIRMED},
    PaymentState.CONFIRMED: {PaymentState.EXECUTED},
    PaymentState.EXECUTED: set(),
}

OPERATION_TARGET_STATE = {
    "prepare_payment": PaymentState.PREPARED,
    "confirm_payment": PaymentState.CONFIRMED,
    "execute_payment": PaymentState.EXECUTED,
}


class PaymentLifecycle:
    def __init__(self) -> None:
        self._state: Dict[str, PaymentState] = {}

    def state_of(self, payment_id: str) -> PaymentState:
        return self._state.get(payment_id, PaymentState.NONE)

    def is_legal_transition(self, payment_id: str, operation: str) -> bool:
        target = OPERATION_TARGET_STATE.get(operation)
        if target is None:
            return True  # not a lifecycle-governed operation
        current = self.state_of(payment_id)
        return target in _LEGAL_TRANSITIONS[current]

    def apply(self, payment_id: str, operation: str) -> None:
        target = OPERATION_TARGET_STATE.get(operation)
        if target is not None:
            self._state[payment_id] = target


FORBIDDEN_OPERATIONS = [
    # nothing is unconditionally forbidden in finance; confirm/execute are
    # gated by capability + lifecycle instead of a blanket ban, because the
    # legitimate path (a real approval) must still work.
]
