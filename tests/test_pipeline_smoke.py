"""End-to-end smoke test that does NOT require any scanner or Docker: it runs the
full pipeline with the 'native' runner so every scanner skips gracefully, and
asserts the report + findings.json are still produced. This proves the
fail-gracefully contract and the orchestration wiring."""
from pathlib import Path

from vulnforge.config import ScanConfig, AppDescription, RepoSpec
from vulnforge.tooling import RunnerMode
from vulnforge.pipeline import run_scan


def test_pipeline_runs_and_reports_even_with_no_scanners(tmp_path):
    # A tiny local "repo".
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "requirements.txt").write_text("flask==0.12.2\n", encoding="utf-8")
    (repo / "app.py").write_text("API_KEY = 'placeholder'\n", encoding="utf-8")

    config = ScanConfig()
    config.repo = RepoSpec(path=str(repo))
    config.out = str(tmp_path / "out")
    # Force native runner with no tools installed -> all scanners skip gracefully.
    desc = AppDescription(application_name="Smoke App", primary_users=["customer"])

    ctx = run_scan(config, desc, runner_mode=RunnerMode.NATIVE, tool_timeout=30)

    out = Path(config.out)
    assert (out / "findings.json").exists()
    assert (out / "report.html").exists()
    assert (out / "run.json").exists()
    # stack detection still worked offline
    assert any("Python" in s for s in ctx.detected_stack)
    # scanners recorded as skipped, pipeline did not crash
    states = {s.name: s.state for s in ctx.stages}
    assert states.get("semgrep") in {"skipped", "ran"}
