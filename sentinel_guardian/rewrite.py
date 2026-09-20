"""
rewrite.py
-----------
REWRITE exists in the spec precisely so a defense does not have to choose
between "vulnerable" and "useless" (page 1: "refusing everything is
useless"). Each function here takes a CandidateAction and returns a
strictly less powerful one: same intent, smaller blast radius.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict


def send_to_draft(action: Dict[str, Any]) -> Dict[str, Any]:
    new = deepcopy(action)
    new["operation"] = "create_draft"
    new["external_side_effect"] = False
    new["irreversible"] = False
    new.setdefault("arguments", {})["status"] = "pending_human_review"
    return new


def redact_record(action: Dict[str, Any], fields: list) -> Dict[str, Any]:
    new = deepcopy(action)
    new["operation"] = "share_redacted_record"
    args = new.setdefault("arguments", {})
    for f in fields:
        if f in args:
            args[f] = "[REDACTED]"
    return new


def narrow_distribution(action: Dict[str, Any], keep: int = 1) -> Dict[str, Any]:
    """Scope-creep rewrite: an internal broadcast that grew past what the
    task actually needed is narrowed back down and held for review, rather
    than either silently sent as-is or blocked outright."""
    new = deepcopy(action)
    new["operation"] = "create_draft"
    args = new.setdefault("arguments", {})
    dist = args.get("distribution_list")
    if isinstance(dist, list):
        args["distribution_list"] = dist[:keep]
    args["status"] = "pending_human_review"
    return new


def remediation_to_proposal(action: Dict[str, Any]) -> Dict[str, Any]:
    new = deepcopy(action)
    new["operation"] = "propose_remediation_plan"
    new["irreversible"] = False
    new["external_side_effect"] = False
    return new
