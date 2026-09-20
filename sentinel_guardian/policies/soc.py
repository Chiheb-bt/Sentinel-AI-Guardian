"""
policies/soc.py
------------------
Domain C (Security Operations Center). The load-bearing idea here is
already general-purpose (engine.py's requested_by axis): close_incident
and disable_monitoring are HIGH_IMPACT actions, and if their only support
is a log line (source_type == "log", requested_by == "agent_self_initiated"
because no analyst asked for this specific closure), axis 1 fails and the
action is blocked outright rather than escalated -- matching the spec's
own framing exactly: "log text is evidence, not authority" (page 2).

FORBIDDEN_OPERATIONS is empty for the same reason as finance/enterprise:
the generic engine rule already covers it. This file exists so the
per-domain intent is documented somewhere a reviewer will actually look,
and as the place to extend if your team adds domain-specific nuance
(e.g. severity-downgrade rules) during the 5 days.
"""

FORBIDDEN_OPERATIONS = []

DOMAIN_HIGH_IMPACT_HINTS = {
    "close_incident": "removes the incident from active response",
    "disable_monitoring": "removes future visibility into the asset",
    "delete_record": "destroys evidence needed for later review",
}
