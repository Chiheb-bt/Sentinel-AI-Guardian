"""Decision entry point used by app/main.py.

Deliberately thin: app.core.decide() is the single, offline-tested source
of truth (see dev/fixtures.py and tests/test_core.py, which exercise this
exact function on realistic requests modeled on the public scenario
library). This file's only job is the pydantic <-> plain-dict boundary.

app.core.decide()'s return dict is built to match DefenseDecision's fields
exactly (decision, risk_score, confidence, reason_codes, explanation,
rewritten_action, metadata -- see app/models.py), so no field mapping is
needed here, only construction.
"""

from __future__ import annotations

from app.core import decide as decide_core
from app.models import DefenseDecision, DefenseRequest


def decide(request: DefenseRequest) -> DefenseDecision:
    result = decide_core(request.model_dump(mode="json"))
    return DefenseDecision(**result)
