"""
policies/enterprise.py
------------------------
Domain A (Enterprise Productivity). Read/summarize/draft-internal work is
never HIGH_IMPACT (see capability.py) so it flows through the soft-risk
tier and defaults to ALLOW -- this is what keeps hard-negative "SOC-flavored"
or "scary" enterprise threads from getting over-blocked. Only
send_email_external and share_customer_record are gated.
"""

FORBIDDEN_OPERATIONS = [
    # A document's own text is never sufficient to authorize sending
    # secrets externally; that case is caught unconditionally by
    # exfiltration scanning in engine.decide(), so nothing needs to be
    # listed here as a blanket ban.
]

DOMAIN_HIGH_IMPACT_HINTS = {
    "send_email_external": "outbound communication leaving the org boundary",
    "share_customer_record": "sensitive record leaving the tool boundary",
}
