#!/usr/bin/env python3
"""
train_soft_risk.py
--------------------
Trains the tiny logistic-regression tier-2 model and prints the constants
that get pasted into app/core.py's _SOFT_WEIGHTS / _SOFT_BIAS / _CAL_X /
_CAL_Y. Run this whenever you change FEATURE_NAMES or the training corpus
in this file, then copy the printed block into core.py by hand (kept as a
manual step on purpose: baking in unreviewed numbers automatically is how
a calibration bug ships silently).

The corpus below is synthetic, written by hand from the STRUCTURE of the
public scenario library (attack family x consequential/confirmed/external/
untrusted-source-count/sensitive/mirror combinations), not from the
organizer's actual scenario files, their labels, or their held-out data --
we do not have access to those. Treat every number this script prints as
illustrative until re-trained against real `sentinel eval` output.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.core import FEATURE_NAMES  # noqa: E402


def featurize(sample: dict) -> np.ndarray:
    return np.array([sample.get(name, 0.0) for name in FEATURE_NAMES], dtype=float)


def synthetic_corpus() -> list[tuple[dict, int]]:
    """(features, label) pairs. label=1 means "this action should NOT be
    allowed as-is" (illegitimate or under-authorized); label=0 means
    legitimate. Every hard case (tool not allowed, mirror detected,
    sensitive-to-sink) is already resolved by a deterministic rule in
    core.decide() before tier 2 is ever consulted -- so tier 2 only needs
    to be good at the RESIDUAL, softer cases: consequential-but-unconfirmed
    actions of varying legitimacy, and read-only actions with varying
    amounts of untrusted/sensitive context. That is what this corpus
    models; it deliberately does NOT include mirror=1 or a fresh
    sensitive-to-sink case as "hard negatives" because those never reach
    this model in practice.
    """
    data: list[tuple[dict, int]] = []
    rng = np.random.default_rng(13)

    def add(n: int, label: int, **kw):
        for _ in range(n):
            jitter = {k: float(np.clip(v + rng.normal(0, 0.11), 0.0, 1.0)) for k, v in kw.items()}
            data.append((jitter, label))

    # --- Illegitimate / under-authorized (label=1) ------------------------
    # Consequential, unconfirmed, no mirror detected yet (mirror cases are
    # already blocked upstream) -- e.g. a direct out-of-policy request for
    # a consequential action, or an escalation attempt riding on a
    # borderline-confirmed digest mismatch.
    add(360, 1, consequential=1.0, confirmed=0.0, external_recipient=0.6,
        untrusted_source_count=0.4, sensitive_context=0.3,
        prior_blocked_or_escalated=0.4)
    add(280, 1, consequential=1.0, confirmed=0.0, external_recipient=0.1,
        untrusted_source_count=0.8, sensitive_context=0.6,
        prior_blocked_or_escalated=0.6)
    # Read-only but heavily contaminated context (many distinct untrusted
    # sources touched this run) -- modestly elevated, not blocked outright.
    add(200, 1, consequential=0.0, confirmed=0.0, external_recipient=0.0,
        untrusted_source_count=1.0, sensitive_context=0.8,
        prior_blocked_or_escalated=0.8)
    # Genuinely ambiguous middle ground: consequential, unconfirmed, but
    # otherwise looks ordinary -- some of these are legitimate actions that
    # simply haven't been confirmed *yet* (a human will approve next),
    # some are not. Neither the corpus nor a real defense can fully
    # separate these from features alone, which is the honest point of
    # including them: they are what keeps the calibration curve from being
    # a step function.
    add(240, 1, consequential=1.0, confirmed=0.0, external_recipient=0.3,
        untrusted_source_count=0.2, sensitive_context=0.2,
        prior_blocked_or_escalated=0.2)

    # --- Legitimate (label=0) ----------------------------------------------
    # Consequential and properly confirmed (soc_confirmed_isolation,
    # finance_refund_confirmed, enterprise_security_digest-style cases).
    add(400, 0, consequential=1.0, confirmed=1.0, external_recipient=0.3,
        untrusted_source_count=0.1, sensitive_context=0.1,
        prior_blocked_or_escalated=0.0)
    # Read-only / non-consequential work, including hard negatives full of
    # alarming vocabulary or touching sensitive-but-legitimately-needed
    # content (finance_fraud_awareness_note, soc_triage_powershell,
    # enterprise_security_digest's read step).
    add(480, 0, consequential=0.0, confirmed=0.0, external_recipient=0.0,
        untrusted_source_count=0.2, sensitive_context=0.4,
        prior_blocked_or_escalated=0.0)
    add(320, 0, consequential=0.0, confirmed=0.0, external_recipient=0.0,
        untrusted_source_count=0.0, sensitive_context=0.0,
        prior_blocked_or_escalated=0.0)
    # The same ambiguous middle ground as above, but legitimate: a
    # consequential action about to be confirmed by the simulated human
    # (e.g. mid-escalation on a reference-plan-aligned step).
    add(240, 0, consequential=1.0, confirmed=0.0, external_recipient=0.3,
        untrusted_source_count=0.15, sensitive_context=0.15,
        prior_blocked_or_escalated=0.1)

    return data


def train_logreg(X: np.ndarray, y: np.ndarray, l2: float = 0.6, lr: float = 0.35, epochs: int = 4000):
    n, d = X.shape
    w = np.zeros(d)
    b = 0.0
    for _ in range(epochs):
        z = X @ w + b
        p = 1.0 / (1.0 + np.exp(-z))
        grad_w = X.T @ (p - y) / n + l2 * w / n
        grad_b = float(np.mean(p - y))
        w -= lr * grad_w
        b -= lr * grad_b
    return w, b


def calibration_curve(raw: np.ndarray, y: np.ndarray, n_bins: int = 6):
    edges = np.linspace(0, 1, n_bins + 1)
    xs, ys = [0.0], [0.0]
    for i in range(n_bins):
        mask = (raw >= edges[i]) & (raw <= edges[i + 1])
        if mask.sum() > 0:
            xs.append(float(raw[mask].mean()))
            ys.append(float(y[mask].mean()))
    xs.append(1.0)
    ys.append(1.0)
    order = np.argsort(xs)
    xs = np.array(xs)[order]
    ys = np.maximum.accumulate(np.array(ys)[order])  # enforce monotonicity
    return xs, ys


def main():
    corpus = synthetic_corpus()
    rng = np.random.default_rng(7)
    idx = rng.permutation(len(corpus))
    corpus = [corpus[i] for i in idx]
    split = int(len(corpus) * 0.7)
    train, val = corpus[:split], corpus[split:]

    X_train = np.stack([featurize(s) for s, _ in train])
    y_train = np.array([lab for _, lab in train], dtype=float)
    w, b = train_logreg(X_train, y_train)

    X_val = np.stack([featurize(s) for s, _ in val])
    y_val = np.array([lab for _, lab in val], dtype=float)
    z_val = X_val @ w + b
    raw_val = 1.0 / (1.0 + np.exp(-z_val))
    cal_x, cal_y = calibration_curve(raw_val, y_val, n_bins=8)

    # Report honest quality numbers on the held-out split.
    calibrated_val = np.interp(raw_val, cal_x, cal_y)
    pred = (calibrated_val >= 0.5).astype(float)
    accuracy = float((pred == y_val).mean())
    brier = float(np.mean((calibrated_val - y_val) ** 2))

    print("=== Trained weights (paste into app/core.py) ===")
    print(f"FEATURE_NAMES order: {FEATURE_NAMES}")
    print(f"_SOFT_WEIGHTS = [{', '.join(f'{v:.4f}' for v in w)}]")
    print(f"_SOFT_BIAS = {b:.4f}")
    print(f"_CAL_X = [{', '.join(f'{v:.3f}' for v in cal_x)}]")
    print(f"_CAL_Y = [{', '.join(f'{v:.3f}' for v in cal_y)}]")
    print()
    print("=== Held-out quality (honest, small synthetic val split) ===")
    print(f"n_train={len(train)} n_val={len(val)}")
    print(f"val accuracy={accuracy:.3f}  val Brier={brier:.4f}")


if __name__ == "__main__":
    main()
