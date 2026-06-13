"""The scan orchestrator: ingest -> discover -> SAST -> (DAST) -> correlate ->
report. Linear, observable, and resilient - any single scanner failure is recorded
and the pipeline continues."""
from __future__ import annotations

from pathlib import Path

from . import console as ui
from .config import ScanConfig, AppDescription, ScanMode
from .context import RunContext, StageStatus, ingest_repo
from .stack import detect_stack
from .models import Finding, dedupe, sort_findings, severity_counts
from .tooling import ToolRunner, RunnerMode
from .scanners.registry import get_sast_scanner
from .ai.provider import get_provider
from .ai.planner import build_plan
from .correlate import correlate
from .report.normalize import write_findings_json
from .report.html import render_html


def run_scan(config: ScanConfig, description: AppDescription, runner_mode: RunnerMode,
             tool_timeout: int) -> RunContext:
    ctx = RunContext.create(config, description)
    runner = ToolRunner(mode=runner_mode, timeout=tool_timeout)
    provider = get_provider(config.ai.provider)

    # 1. Ingest code -----------------------------------------------------------
    ui.stage("Ingesting code under test")
    code_root: Path | None = None
    try:
        code_root = ingest_repo(config.repo, ctx.workspace)
        ui.ok(f"code ready at {code_root}")
    except Exception as exc:  # noqa: BLE001
        ui.err(f"repo ingestion failed: {exc}")
        ctx.record(StageStatus("ingest", "error", detail=str(exc)))

    # 2. Discover stack --------------------------------------------------------
    if code_root:
        ui.stage("Discovering technology stack")
        ctx.detected_stack = detect_stack(code_root)
        ui.ok(", ".join(ctx.detected_stack) or "no obvious stack markers found")

    # 3. SAST ------------------------------------------------------------------
    sast_findings: list[Finding] = []
    if code_root:
        ui.stage("Running SAST engine")
        for name in config.sast_scanners:
            scanner = get_sast_scanner(name)
            if scanner is None:
                ui.warn(f"unknown SAST scanner '{name}', skipping")
                ctx.record(StageStatus(name, "skipped", detail="unknown scanner"))
                continue
            try:
                outcome = scanner.scan(str(code_root), runner, _raw_writer(ctx))
            except Exception as exc:  # noqa: BLE001 - a scanner must never kill the run
                ui.err(f"{name} crashed: {exc}")
                ctx.record(StageStatus(name, "error", detail=str(exc)))
                continue
            sast_findings.extend(outcome.findings)
            ctx.record(StageStatus(name, outcome.state, detail=outcome.detail,
                                   findings=len(outcome.findings)))
            if outcome.state == "ran":
                ui.ok(f"{name}: {len(outcome.findings)} finding(s)")
            elif outcome.state == "skipped":
                ui.skipped(f"{name}: {outcome.detail}")
            else:
                ui.err(f"{name}: {outcome.detail}")

    sast_findings = dedupe(sast_findings)

    # 4. AI test plan (guides DAST; informational in this phase) ---------------
    ui.stage("Building AI-guided test plan")
    plan = build_plan(description, sast_findings, config, provider)
    if config.scan_mode == ScanMode.SAFE:
        plan = plan.safe_only()
    ui.ok(f"{len(plan.intents)} prioritized test intent(s) derived from SAST"
          + ("" if provider.available else " (heuristic; AI disabled)"))

    # 5. DAST (Phase 3+) -------------------------------------------------------
    dast_findings: list[Finding] = []
    if config.target.base_url:
        ui.stage("DAST engine")
        ui.skipped("DAST adapters are scaffolded; enable in a later phase")
        ctx.record(StageStatus("dast", "skipped", detail="not yet implemented (Phase 3+)"))

    # 6. Correlate -------------------------------------------------------------
    findings = sort_findings(dedupe(correlate(sast_findings, dast_findings)))

    # 7. Report ----------------------------------------------------------------
    ui.stage("Generating report")
    json_path = write_findings_json(ctx, findings)
    ui.ok(f"findings.json -> {json_path}")
    if "html" in config.formats:
        html_path = render_html(ctx, findings, provider)
        ui.ok(f"report.html -> {html_path}")

    ctx.write_run_metadata()

    counts = severity_counts(findings)
    ui.stage("Done")
    ui.info(f"total findings: {len(findings)}  "
            f"(critical {counts['critical']}, high {counts['high']}, "
            f"medium {counts['medium']}, low {counts['low']}, info {counts['info']})")
    return ctx


def _raw_writer(ctx: RunContext):
    """Returns a (filename, text) -> path callable that persists raw tool output."""
    def write(filename: str, text: str) -> str:
        path = ctx.raw_path(filename)
        try:
            path.write_text(text or "", encoding="utf-8")
        except Exception:
            pass
        return str(path)
    return write
