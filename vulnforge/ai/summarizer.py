"""App summary + executive risk narrative. Uses the LLM provider when available,
otherwise produces a solid deterministic summary from the description + findings.
Either way the report gets a useful narrative - AI just makes it sharper."""
from __future__ import annotations

from ..config import AppDescription
from ..models import Finding, Severity, severity_counts
from .provider import LLMProvider

_SYSTEM = (
    "You are a senior application security engineer writing concise, accurate "
    "summaries for a security report. No fluff. No invented findings."
)


def summarize_app(desc: AppDescription, stack: list[str], provider: LLMProvider) -> str:
    if provider.available:
        prompt = (
            f"Application: {desc.application_name}\n"
            f"Purpose: {desc.business_purpose}\n"
            f"Users: {', '.join(desc.primary_users)}\n"
            f"Data criticality: {desc.data_criticality}\n"
            f"Sensitive data: {', '.join(desc.sensitive_data)}\n"
            f"Critical flows: {', '.join(desc.critical_flows)}\n"
            f"Detected stack: {', '.join(stack) or 'unknown'}\n\n"
            "Write a 3-4 sentence overview of what this application is, who uses it, "
            "and which security properties matter most for it."
        )
        out = provider.complete(_SYSTEM, prompt, max_tokens=400)
        if out:
            return out
    return _deterministic_app_summary(desc, stack)


def executive_risk(desc: AppDescription, findings: list[Finding], provider: LLMProvider) -> str:
    counts = severity_counts(findings)
    if provider.available:
        top = "; ".join(
            f"{f.severity.value}: {f.title}" for f in findings[:8]
        )
        prompt = (
            f"Application: {desc.application_name} (data criticality: {desc.data_criticality}).\n"
            f"Finding counts: {counts}.\n"
            f"Top findings: {top}\n\n"
            "Write a 3-5 sentence executive risk summary for leadership: overall risk "
            "level, what is most exposed, and the top remediation priority. Be precise."
        )
        out = provider.complete(_SYSTEM, prompt, max_tokens=400)
        if out:
            return out
    return _deterministic_exec_summary(desc, findings, counts)


def _deterministic_app_summary(desc: AppDescription, stack: list[str]) -> str:
    users = ", ".join(desc.primary_users) or "unspecified users"
    parts = [
        f"{desc.application_name} is used by {users}.",
    ]
    if desc.business_purpose:
        parts.append(desc.business_purpose.rstrip("."))
    if desc.sensitive_data:
        parts.append(
            f"It handles sensitive data including {', '.join(desc.sensitive_data[:6])}, "
            f"rated {desc.data_criticality} criticality."
        )
    if stack:
        parts.append(f"Detected technology: {', '.join(stack)}.")
    if desc.testing_goals:
        parts.append(f"Primary testing focus: {', '.join(desc.testing_goals)}.")
    return " ".join(p.rstrip(".") + "." for p in parts)


def _deterministic_exec_summary(desc: AppDescription, findings: list[Finding], counts: dict) -> str:
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    if crit:
        level = "Critical"
    elif high:
        level = "High"
    elif counts.get("medium", 0):
        level = "Medium"
    elif any(counts.values()):
        level = "Low"
    else:
        level = "Minimal"
    lines = [
        f"Overall risk: {level}. The scan recorded "
        f"{counts.get('critical',0)} critical, {counts.get('high',0)} high, "
        f"{counts.get('medium',0)} medium, {counts.get('low',0)} low and "
        f"{counts.get('info',0)} informational findings."
    ]
    top = findings[0] if findings else None
    if top:
        lines.append(
            f"The most severe issue is “{top.title}” ({top.severity.value}, "
            f"{top.confidence.value})."
        )
    if desc.data_criticality in ("high", "critical") and (crit or high):
        lines.append(
            "Because this application handles high-criticality data, confirmed access-control "
            "and injection findings should be remediated before the next release."
        )
    return " ".join(lines)
