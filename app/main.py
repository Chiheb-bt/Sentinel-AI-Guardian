"""FastAPI service implementing the SENTINEL v1 defense API.

Identical in shape to starter-kits/python-defense/app/main.py -- the only
thing this repo changes is decision.py (which now calls the tested engine
in core.py) and models.py (copied verbatim, since it was already exactly
right). Run with: uvicorn app.main:app --port 8080
"""

from __future__ import annotations

from fastapi import FastAPI

from app.decision import decide
from app.models import DefenseDecision, DefenseRequest

app = FastAPI(title="SENTINEL Guardian defense", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision", response_model=DefenseDecision)
def decision(request: DefenseRequest) -> DefenseDecision:
    return decide(request)
