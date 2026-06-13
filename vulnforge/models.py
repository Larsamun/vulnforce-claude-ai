"""Normalized data model shared by every scanner, the correlation engine, and the
report layer.

The whole point of an orchestrator is that Semgrep, Gitleaks, Trivy, ZAP, Nuclei,
etc. all speak different output formats but funnel into ONE `Finding` schema. That
schema is the contract that makes correlation, dedup, ranking, and reporting
possible.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        """Map the many severity spellings used by tools into our scale."""
        if isinstance(value, Severity):
            return value
        s = str(value or "").strip().lower()
        mapping = {
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "blocker": cls.CRITICAL,
            "high": cls.HIGH,
            "error": cls.HIGH,
            "severe": cls.HIGH,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "warning": cls.MEDIUM,
            "warn": cls.MEDIUM,
            "low": cls.LOW,
            "minor": cls.LOW,
            "note": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "unknown": cls.INFO,
            "none": cls.INFO,
        }
        return mapping.get(s, cls.MEDIUM)


class Engine(str, Enum):
    SAST = "sast"
    DAST = "dast"
    CORRELATED = "correlated"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    INFORMATIONAL = "informational"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


_SECRET_PATTERN = re.compile(r".")


def mask_secret(value: Optional[str]) -> Optional[str]:
    """Mask a secret value, keeping only a short fingerprint + length. Used so raw
    secret material never lands in normalized findings or reports."""
    if not value:
        return value
    digest = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:8]
    return f"<redacted:{len(value)}chars:sha256={digest}>"


@dataclass
class Finding:
    """One normalized security finding."""

    source: str                      # tool name: "semgrep", "gitleaks", "trivy", "zap"...
    engine: Engine
    category: str                    # injection | secret | dependency | misconfig | header ...
    severity: Severity
    title: str
    description: str = ""

    # Location (SAST)
    file: Optional[str] = None
    line: Optional[int] = None

    # Location (DAST)
    endpoint: Optional[str] = None
    method: Optional[str] = None

    evidence: Optional[str] = None
    rule_id: Optional[str] = None
    cwe: list[str] = field(default_factory=list)
    owasp: Optional[str] = None
    remediation: Optional[str] = None
    references: list[str] = field(default_factory=list)

    # Correlation / triage
    confidence: Confidence = Confidence.POSSIBLE
    suggested_dast_tests: list[str] = field(default_factory=list)
    correlated_with: list[str] = field(default_factory=list)

    raw: dict = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable id for dedup. Based on the dimensions that make a finding 'the
        same finding' so re-runs and overlapping tools collapse cleanly."""
        key = "|".join(
            str(x)
            for x in (
                self.source,
                self.engine.value,
                self.rule_id or self.title,
                self.file or self.endpoint or "",
                self.line if self.line is not None else "",
            )
        )
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["engine"] = self.engine.value
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["id"] = self.fingerprint()
        return d


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings by fingerprint, keeping the highest severity."""
    by_id: dict[str, Finding] = {}
    for f in findings:
        fid = f.fingerprint()
        existing = by_id.get(fid)
        if existing is None or f.severity.rank > existing.severity.rank:
            by_id[fid] = f
    return list(by_id.values())


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Rank for reporting: severity desc, then confirmed-first, then source/title."""
    conf_rank = {
        Confidence.CONFIRMED: 5,
        Confidence.LIKELY: 4,
        Confidence.POSSIBLE: 3,
        Confidence.NEEDS_REVIEW: 2,
        Confidence.INFORMATIONAL: 1,
        Confidence.FALSE_POSITIVE: 0,
    }
    return sorted(
        findings,
        key=lambda f: (-f.severity.rank, -conf_rank.get(f.confidence, 0), f.source, f.title),
    )


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
