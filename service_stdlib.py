#!/usr/bin/env python3
"""
service_stdlib.py
-------------------
Exposes sentinel_guardian.engine.decide() over HTTP so it can be pointed
to by `sentinel run --defense-url http://127.0.0.1:8080 --model qwen3-8b`
(spec page 4). Built on Python's stdlib http.server ONLY -- no fastapi,
no pydantic, nothing to `pip install` -- because this container has no
network access to install anything, and because it means this literally
runs the moment you clone the repo, with no setup step to get wrong
before your first rehearsal run.

IMPORTANT -- READ THIS BEFORE YOUR FIRST REAL RUN:
The exact JSON shape the real `sentinel run` harness POSTs is defined by
the starter kit (github.com/Skan22/Sentinel_Starter_Kit), which is not
reachable from the environment this file was written in (no internet
access here). `parse_request()` below is the ONE function you need to
edit once you have the real repo open: make it turn the harness's actual
request body into a CandidateAction + list of Observations, using
whatever field names the real schema uses. `format_response()` is the
other one: make it turn our Decision back into whatever shape the harness
expects for allow/block/escalate/rewrite. Everything else in this file,
and all of sentinel_guardian/, should not need to change.

If the starter kit does ship a FastAPI scaffold (the spec says the
`python-defense` kit includes one), it's almost certainly cleaner to
`pip install fastapi` in their scaffold and call `decide()` from inside
it instead of running this file standalone -- this file exists so you
have a working, testable server on day 0 even before you've looked at
their code.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict

from sentinel_guardian import (
    CandidateAction, CapabilityStore, ProvenanceGraph, Trust, decide,
    train_default_model,
)
from sentinel_guardian.provenance import Observation

MODEL = train_default_model()
KNOWN_SECRETS: Dict[str, str] = {
    # TODO: populate from the sandbox's synthetic secret registry once you
    # have the real simulator running.
}

# Persistent across the process lifetime so capabilities/state survive
# multiple steps of the same run. Keyed by run_id.
_graphs: Dict[str, ProvenanceGraph] = {}
_caps: Dict[str, CapabilityStore] = {}

TRUST_NAME_MAP = {t.name: t for t in Trust}


def _get_run_state(run_id: str):
    if run_id not in _graphs:
        _graphs[run_id] = ProvenanceGraph()
        _caps[run_id] = CapabilityStore()
    return _graphs[run_id], _caps[run_id]


def parse_request(body: Dict[str, Any]):
    """*** EDIT ME to match the real starter-kit schema. ***
    Expected (placeholder) shape, adjust field names once you have the
    real one:
    {
      "run_id": "...", "step": 3,
      "observations": [{"id","content","source_type","trust","parent_ids",
                         "contains_instruction"}, ...],
      "action": {"action_id","tool","operation","domain","arguments",
                 "source_observation_ids","requested_by",
                 "external_side_effect","ambiguous_scope"}
    }
    """
    run_id = body.get("run_id", "default")
    step = body.get("step", 0)
    graph, caps = _get_run_state(run_id)

    for o in body.get("observations", []):
        trust = TRUST_NAME_MAP.get(o.get("trust", "UNTRUSTED_EXTERNAL"), Trust.UNTRUSTED_EXTERNAL)
        graph.add(Observation(
            observation_id=o["id"], content=o.get("content", ""),
            source_type=o.get("source_type", "unknown"), trust=trust,
            parent_ids=o.get("parent_ids", []),
            contains_instruction=o.get("contains_instruction", False),
        ))

    a = body["action"]
    action = CandidateAction(
        action_id=a.get("action_id", "a"), tool=a.get("tool", ""),
        operation=a["operation"], domain=a.get("domain", "enterprise"),
        arguments=a.get("arguments", {}),
        source_observation_ids=a.get("source_observation_ids", []),
        requested_by=a.get("requested_by", "agent_self_initiated"),
        irreversible=a.get("irreversible", False),
        external_side_effect=a.get("external_side_effect", False),
        ambiguous_scope=a.get("ambiguous_scope", False),
        soft_features=a.get("soft_features", {}),
    )
    return run_id, step, graph, caps, action


def format_response(decision) -> Dict[str, Any]:
    """*** EDIT ME to match whatever response shape the harness expects. ***"""
    return {
        "outcome": decision.outcome,
        "risk_score": decision.risk_score,
        "confidence": decision.confidence,
        "reason_codes": decision.reason_codes,
        "explanation": decision.explanation,
        "rewritten_action": decision.rewritten_action,
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep stdout clean; comment out to debug

    def do_POST(self):
        if self.path not in ("/decide", "/"):
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw)
            run_id, step, graph, caps, action = parse_request(body)
            decision = decide(step, action, graph, caps, KNOWN_SECRETS, MODEL)
            response = format_response(decision)
            status = 200
        except Exception as e:  # noqa: BLE001 -- surface the error to the caller
            response = {"error": str(e)}
            status = 400

        payload = json.dumps(response).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main(host: str = "127.0.0.1", port: int = 8080):
    server = HTTPServer((host, port), Handler)
    print(f"SENTINEL Guardian defense service listening on http://{host}:{port}/decide")
    print("POST a JSON body (see parse_request() docstring) to get a decision back.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
