"""
provenance.py
--------------
The trust lattice and the taint-propagation graph.

Core idea (this is the theoretical spine of the whole defense):

    Trust is a lattice, not a filter threshold.
    Every derived value's trust = the MINIMUM (join, in the security sense)
    of the trust of everything that caused it to exist.

This is language-based information-flow control (IFC) applied to an agent's
working memory instead of a compiler's variable store (Denning 1976 lattice
model; Sabelfeld & Myers 2003 survey). The property we want to *hold* is a
form of non-interference:

    No value whose provenance closure bottoms out below AUTHENTICATED_USER
    may, by itself, satisfy the authority requirement of a HIGH_IMPACT action.

That single sentence is what turns "we tagged things with trust levels"
(which every team will do, because the spec hands you the six levels) into
a falsifiable claim you can violate on purpose (see tests/test_engine.py)
and measure whether it holds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, Iterable, List, Optional, Set


class Trust(IntEnum):
    """Exactly the six trust levels named in the spec (page 2), ordered as
    a lattice from least to most authoritative."""

    ADVERSARY_CONTROLLED = 0
    UNTRUSTED_EXTERNAL = 1
    UNTRUSTED_INTERNAL = 2
    TRUSTED_INTERNAL = 3
    AUTHENTICATED_USER = 4
    SYSTEM_POLICY = 5

    def __str__(self) -> str:  # nicer trace output
        return self.name


def join(*trusts: Trust) -> Trust:
    """Security-lattice join for taint: combining a trusted and an
    untrusted input yields an untrusted result. This is the single
    operator that 'memory inherits trust' (spec, page 2) reduces to."""
    return min(trusts) if trusts else Trust.SYSTEM_POLICY


@dataclass
class Observation:
    """One unit of content the agent perceives: an email, a document
    fragment, a log line, a tool-result field, a memory recall, etc."""

    observation_id: str
    content: str
    source_type: str                      # "email" | "log" | "memory" | ...
    trust: Trust
    sensitivity: str = "normal"            # "normal" | "secret" | "pii"
    parent_ids: List[str] = field(default_factory=list)
    contains_instruction: bool = False
    declared_role: str = "evidence"        # "evidence" | "authority" (claimed)
    tags: List[str] = field(default_factory=list)


class ProvenanceGraph:
    """Tracks the causal ancestry of every observation and derived artifact
    (including memory entries) and computes effective (taint-joined) trust
    over the transitive closure, memoized per graph mutation."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Observation] = {}
        self._cache: Dict[str, Trust] = {}

    def add(self, obs: Observation) -> Observation:
        self._nodes[obs.observation_id] = obs
        self._cache.clear()
        return obs

    def get(self, obs_id: str) -> Optional[Observation]:
        return self._nodes.get(obs_id)

    def ancestors(self, obs_id: str, _seen: Optional[Set[str]] = None) -> Set[str]:
        seen = _seen if _seen is not None else set()
        if obs_id in seen or obs_id not in self._nodes:
            return seen
        seen.add(obs_id)
        for parent in self._nodes[obs_id].parent_ids:
            self.ancestors(parent, seen)
        return seen

    def effective_trust(self, obs_id: str) -> Trust:
        """The taint-joined trust of obs_id: the minimum trust over obs_id
        and every node that causally contributed to it. This is what makes
        memory poisoning inert -- a memory entry written after reading a
        newsletter can never rise above UNTRUSTED_EXTERNAL, no matter how
        many turns pass or how authoritative its *content* claims to be."""
        if obs_id in self._cache:
            return self._cache[obs_id]
        closure = self.ancestors(obs_id)
        if not closure:
            # Unknown id -- treat as maximally untrusted rather than crash.
            return Trust.ADVERSARY_CONTROLLED
        trust = join(*(self._nodes[n].trust for n in closure if n in self._nodes))
        self._cache[obs_id] = trust
        return trust

    def effective_trust_of_many(self, obs_ids: Iterable[str]) -> Trust:
        ids = list(obs_ids)
        if not ids:
            # An action with no declared provenance at all is the most
            # suspicious case, not the most trusted one.
            return Trust.ADVERSARY_CONTROLLED
        return join(*(self.effective_trust(i) for i in ids))

    def contributing_untrusted(self, obs_ids: Iterable[str]) -> List[str]:
        """Which declared sources actually dragged the trust down -- used to
        write a legible reason/explanation instead of just a number."""
        out = []
        for i in obs_ids:
            closure = self.ancestors(i)
            for n in closure:
                node = self._nodes.get(n)
                if node and node.trust <= Trust.UNTRUSTED_INTERNAL:
                    out.append(n)
        return sorted(set(out))


@dataclass
class MemoryEntry:
    """A memory write is itself an Observation whose parent_ids point at
    whatever was read to produce it -- so effective_trust() 'just works'
    for memory the same way it works for a live document. This dataclass
    exists mainly to make the call sites read cleanly."""

    content: str
    source_ids: List[str]
    declared_role: str = "evidence"  # a memory entry can *claim* to be a
                                      # policy; that claim never upgrades
                                      # its trust (see engine.py authority
                                      # check, which reads trust, not
                                      # declared_role).

    def as_observation(self, observation_id: str, graph: ProvenanceGraph) -> Observation:
        trust = graph.effective_trust_of_many(self.source_ids)
        obs = Observation(
            observation_id=observation_id,
            content=self.content,
            source_type="memory",
            trust=trust,
            parent_ids=list(self.source_ids),
            contains_instruction=(self.declared_role == "authority"),
            declared_role=self.declared_role,
            tags=["memory"],
        )
        return obs
