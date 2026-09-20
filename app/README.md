# Deploying this defense

This folder is a literal drop-in for `starter-kits/python-defense/app/` in
the real SENTINEL starter kit.

## Deploy

```bash
# from the real Sentinel_Starter_Kit-main checkout:
cp -r starter-kits/python-defense ../sentinel-guardian-defense
cd ../sentinel-guardian-defense
rm -rf app
cp -r /path/to/this/repo/app .
uv sync   # or: pip install -r app/requirements.txt --break-system-packages

uvicorn app.main:app --port 8080
# in another terminal, from the starter kit root:
sentinel run --scenario scenarios/public/enterprise/enterprise_poisoned_invoice.yaml \
  --defense-url http://127.0.0.1:8080 --model qwen3-8b
```

## What's actually in here

- `core.py` -- the real decision engine, pure stdlib. This is the file
  that matters; everything else is thin glue around it. It is the exact
  same file exercised by `tests/test_core.py` and `dev/run_demo.py` in the
  parent repo, so what you deploy is what was tested, not a rewrite of it.
- `decision.py` -- 6 lines: pydantic model in, plain dict to `core.decide()`,
  pydantic model out.
- `main.py`, `models.py` -- copied field-for-field from the organizer's
  own `starter-kits/python-defense/app/` (confirmed against the uploaded
  starter kit, not approximated).
- `requirements.txt` -- identical pins to the organizer's own
  `starter-kits/python-defense/requirements.txt`: fastapi, uvicorn,
  pydantic. Nothing else. `core.py`'s tier-2 model runs on baked-in
  constants (see `core.py`'s module docstring and
  `../dev/train_soft_risk.py`), so there is no numpy/sklearn dependency to
  go missing in your deployment.

## Before you trust this against the real scenario library

This was built and tested in a sandboxed environment with **no internet
access** -- `uv sync` / `pip install fastapi pydantic` could not run there,
so `core.py` was validated against hand-built fixtures modeled on the real
scenario YAMLs (`../dev/fixtures.py`), not against the actual
`sentinel run` / `sentinel eval` commands. Three real bugs were found and
fixed this way already (see `core.py`'s comments on the tool-vocabulary
anchor, the content-field restriction, and the bidirectional-compaction
fix) -- which is exactly why the next step matters:

1. Run `uv run pytest ../tests/` (or `python3 ../tests/test_core.py` and
   `python3 ../tests/test_contract.py`, no pytest required) the moment you
   have a real environment, to confirm nothing about pydantic's actual
   validation behavior differs from the hand-written contract check in
   `test_contract.py`.
2. Run `sentinel run --defense-url ...` against a few published scenarios
   BEFORE the ablation/report numbers go anywhere final, and diff the
   real trace against `../traces/*.jsonl`'s decisions for the same
   scenario, if you rebuilt an equivalent fixture.
3. Watch `blocked_count` / `escalated_count` in a long real run -- those
   come from `history_digest`, which this defense reads but has only been
   exercised here with hand-set values, not the real harness's actual
   accounting.
