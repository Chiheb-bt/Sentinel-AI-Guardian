"""
mutate.py
----------
The spec is explicit: "a defense that only works on one exact wording is
weak evidence" (page 2) and difficulty level 4/5 scenarios are "adaptive"
and "long horizon". Most teams will test against the 19 published
scenarios verbatim and stop. This module mechanically mutates a malicious
payload string so the SAME underlying attack is tested in several surface
forms, without needing a live LLM to paraphrase it (keeps everything
offline per the rules).

Because our defense decides from provenance/capability/value-content
rather than from string patterns, none of these mutations should change
the outcome -- and the test suite (tests/test_engine.py) asserts exactly
that. That invariance result is the strongest single piece of evidence
you can put in the "Creativity & Novelty" and "Robustness" sections of the
report: it's a claim about the *class* of attack, not one transcript.
"""

from __future__ import annotations

import base64
import random
from typing import Callable, Dict, List


def _case_scramble(s: str, seed: int) -> str:
    rnd = random.Random(seed)
    return "".join(c.upper() if rnd.random() < 0.5 else c.lower() for c in s)


def _insert_whitespace(s: str) -> str:
    return " ".join(list(s.replace(" ", "")))


def _reverse(s: str) -> str:
    return s[::-1]


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _synonym_swap(s: str) -> str:
    table = {
        "send": "forward", "token": "credential", "paste": "insert",
        "close": "resolve", "disable": "turn off", "confirm": "approve",
        "approved": "signed off", "already": "previously",
    }
    out = s
    for k, v in table.items():
        out = out.replace(k, v).replace(k.capitalize(), v.capitalize())
    return out


def _split_fragments(s: str) -> List[str]:
    mid = len(s) // 2
    return [s[:mid], s[mid:]]


MUTATIONS: Dict[str, Callable[[str], str]] = {
    "identity": lambda s: s,
    "case_scramble": lambda s: _case_scramble(s, 42),
    "whitespace_spread": _insert_whitespace,
    "reversed": _reverse,
    "base64": _b64,
    "synonym_swap": _synonym_swap,
}


def mutate_all(payload: str) -> Dict[str, str]:
    return {name: fn(payload) for name, fn in MUTATIONS.items()}


def split_across_observations(payload: str) -> List[str]:
    return _split_fragments(payload)
