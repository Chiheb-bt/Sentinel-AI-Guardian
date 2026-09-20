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
# in another terminal, from the starter kit root. The verified offline
# evaluation uses the documented mock model:
sentinel run --scenario scenarios/public/enterprise/enterprise_poisoned_invoice.yaml \
  --defense-url http://127.0.0.1:8080 --model mock
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

## Verified public evaluation

The real starter-kit CLI and evaluator were run against the published
public scenario library using the documented offline mock reference model.
All 19/19 scenarios were task-successful:

- BTU: 1.0000
- ASR: 0.0000
- CVR: 0.0000
- FBR: 0.02299
- UER: 0.03448
- Documented official score: 0.989787
- Median decision latency: approximately 3.76 ms

These results are not a Qwen3-8B comparison or a guarantee of real-world
security. The implementation still has the documented limitations around
synthetic calibration data, hand-curated tool vocabulary, overlap
thresholds, and memory-window dependence.
