#!/usr/bin/env python3
"""
build_dashboard.py
--------------------
Reads every traces/*.jsonl file (real Event-schema artifacts, one per
run_id) and embeds them as the dashboard's default demo data, so opening
dashboard/observability_dashboard.html works immediately with zero setup.
Re-run after `python3 dev/run_demo.py` any time fixtures/traces change.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACES = ROOT / "traces"
TEMPLATE = ROOT / "dashboard" / "template.html"
OUTPUT = ROOT / "dashboard" / "observability_dashboard.html"


def main():
    bundle = {}
    for path in sorted(TRACES.glob("*.jsonl")):
        events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        bundle[path.stem] = events

    template = TEMPLATE.read_text()
    injected = template.replace("__TRACE_BUNDLE_JSON__", json.dumps(bundle))
    OUTPUT.write_text(injected)
    print(f"Embedded {len(bundle)} runs ({sum(len(v) for v in bundle.values())} events total)")
    print(f"Wrote {OUTPUT} ({OUTPUT.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    main()
