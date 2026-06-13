"""Render the HTML report (developer / security / executive views in one page)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__
from ..context import RunContext
from ..models import Finding, Severity, severity_counts, sort_findings
from ..ai.provider import LLMProvider
from ..ai import summarizer
from . import mermaid

_TEMPLATE_DIR = Path(__file__).parent / "templates"

_SEV_COLOR = {
    "critical": "#7c1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#2563eb",
    "info": "#475569",
}


def render_html(ctx: RunContext, findings: list[Finding], provider: LLMProvider) -> Path:
    findings = sort_findings(findings)
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["sevcolor"] = lambda s: _SEV_COLOR.get(str(s), "#475569")

    # Diagrams (only for the most serious findings to keep the report focused).
    diagrams = []
    for f in findings:
        if f.severity.rank >= Severity.HIGH.rank:
            diagrams.append({
                "title": f.title,
                "severity": f.severity.value,
                "attack_path": mermaid.attack_path_diagram(f),
                "dataflow": mermaid.dataflow_diagram(f),
            })
        if len(diagrams) >= 6:
            break

    context = {
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "desc": ctx.description,
        "config": ctx.config,
        "stack": ctx.detected_stack,
        "stages": ctx.stages,
        "findings": findings,
        "counts": severity_counts(findings),
        "app_summary": summarizer.summarize_app(ctx.description, ctx.detected_stack, provider),
        "exec_summary": summarizer.executive_risk(ctx.description, findings, provider),
        "ai_enabled": provider.available,
        "ai_provider": provider.name,
        "arch_diagram": mermaid.architecture_diagram(ctx.description, ctx.detected_stack),
        "trust_diagram": mermaid.trust_boundary_diagram(ctx.description),
        "finding_diagrams": diagrams,
    }

    html = env.get_template("report.html.j2").render(**context)
    out = ctx.out_dir / "report.html"
    out.write_text(html, encoding="utf-8")
    return out
