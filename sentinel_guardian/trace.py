"""
trace.py
---------
Every decision is written out in exactly the shape the spec's own example
uses (page 3), plus the fields our extra machinery needs (capability
check result, which normalization caught a secret, requested_by). The
dashboard (dashboard/observability_dashboard.html) reads this same file
with no server -- open the HTML, load the .jsonl, done.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Decision:
    outcome: str                       # ALLOW | BLOCK | ESCALATE | REWRITE
    risk_score: float
    confidence: float
    reason_codes: List[str]
    explanation: str
    rewritten_action: Optional[Dict[str, Any]] = None


@dataclass
class TraceEvent:
    run_id: str
    step: int
    action_id: str
    tool: str
    operation: str
    domain: str
    source_ids: List[str]
    source_trust: Dict[str, str]
    data_flow: Dict[str, Any]
    decision: Decision
    executed: bool
    observations: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        dec = d.pop("decision")
        d["risk_score"] = dec["risk_score"]
        d["confidence"] = dec["confidence"]
        d["reason_codes"] = dec["reason_codes"]
        d["outcome"] = dec["outcome"]
        d["explanation"] = dec["explanation"]
        d["rewritten"] = dec["rewritten_action"] is not None
        d["rewritten_action"] = dec["rewritten_action"]
        return d


class TraceWriter:
    def __init__(self, path: str) -> None:
        self.path = path
        self._fh = open(path, "w", encoding="utf-8")

    def write(self, event: TraceEvent) -> None:
        self._fh.write(json.dumps(event.to_json_dict()) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "TraceWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
