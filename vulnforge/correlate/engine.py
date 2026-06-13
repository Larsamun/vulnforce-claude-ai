"""Correlation engine (Phase 6 - scaffold).

Matches SAST findings (a code sink at file:line for an endpoint) with DAST findings
(runtime behavior at that endpoint) and, when both point at the same weakness,
emits a single CORRELATED finding promoted to higher confidence. With no DAST
findings yet, this is a no-op that simply returns the SAST findings unchanged.
"""
from __future__ import annotations

from ..models import Finding, Engine, Confidence


def correlate(sast: list[Finding], dast: list[Finding]) -> list[Finding]:
    """Return the merged finding set. TODO(P6): real endpoint<->sink matching and
    confidence promotion. For now: pass-through + dedup-friendly tagging."""
    if not dast:
        return list(sast)

    correlated: list[Finding] = []
    matched_dast_ids: set[str] = set()

    for s in sast:
        endpoint = (s.endpoint or "").lower()
        for d in dast:
            if endpoint and endpoint == (d.endpoint or "").lower():
                s.correlated_with.append(d.fingerprint())
                s.confidence = Confidence.CONFIRMED
                s.engine = Engine.CORRELATED
                matched_dast_ids.add(d.fingerprint())

    correlated.extend(sast)
    correlated.extend(d for d in dast if d.fingerprint() not in matched_dast_ids)
    return correlated
