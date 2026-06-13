"""AI Test Planner (Phase 5 - scaffold).

Turns SAST findings + app description + discovered routes into a prioritized,
safety-bounded DAST test plan. Until the LLM-backed version lands, a deterministic
heuristic derives test intents from SAST findings that carry `suggested_dast_tests`
or sit in attack-relevant categories. This already gives DAST something better than
blind fuzzing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import AppDescription, ScanConfig
from ..models import Finding
from .provider import LLMProvider

_GUIDED_CATEGORIES = {"injection", "xss", "ssrf", "path-traversal", "secret", "security"}


@dataclass
class TestIntent:
    name: str
    reason: str
    target_hint: str                # file/endpoint the SAST finding points at
    category: str
    risk: str
    safe_for_prod: bool = True
    source_finding_id: str = ""


@dataclass
class TestPlan:
    intents: list[TestIntent] = field(default_factory=list)

    def safe_only(self) -> "TestPlan":
        return TestPlan([i for i in self.intents if i.safe_for_prod])


def build_plan(
    description: AppDescription,
    findings: list[Finding],
    config: ScanConfig,
    provider: LLMProvider,
) -> TestPlan:
    """Heuristic plan now; LLM-guided plan when a provider is wired in (TODO P5)."""
    intents: list[TestIntent] = []
    for f in findings:
        if f.category not in _GUIDED_CATEGORIES and not f.suggested_dast_tests:
            continue
        reason = f.suggested_dast_tests[0] if f.suggested_dast_tests else (
            f"SAST flagged {f.category} at {f.file}:{f.line}; validate dynamically."
        )
        intents.append(
            TestIntent(
                name=f"Validate: {f.title}"[:120],
                reason=reason,
                target_hint=f"{f.file}:{f.line}" if f.file else (f.endpoint or ""),
                category=f.category,
                risk=f.severity.value,
                safe_for_prod=f.category != "injection",  # injection probes gated to deep mode
                source_finding_id=f.fingerprint(),
            )
        )
    return TestPlan(intents)
