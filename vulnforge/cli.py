"""VulnForge AI command-line interface.

Commands:
  vulnforge init [FILE]      Write a starter description YAML.
  vulnforge doctor           Show which scanners/tools are available.
  vulnforge scan ...         Run a scan and produce a report.
  vulnforge report DIR       Re-render the HTML report from an existing run.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from . import console as ui
from .config import (
    AppDescription, ScanConfig, RepoSpec, AIConfig, ScanMode, ConfigError,
)
from .tooling import RunnerMode, ToolRunner, docker_available
from .scanners.registry import known_sast, get_sast_scanner, known_dast
from .pipeline import run_scan

_DEFAULT_DESC = """\
application_name: "My Application"
business_purpose: "Describe what the app does and who relies on it."
primary_users: [customer, admin]
data_criticality: medium        # low | medium | high | critical
sensitive_data: []
critical_flows: [login]
testing_goals: [broken access control, IDOR, security headers]
out_of_scope: [denial of service, destructive testing]
environment: staging            # dev | test | staging | prod
notes: ""
"""


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except ConfigError as exc:
        ui.err(str(exc))
        return 2
    except KeyboardInterrupt:
        ui.warn("interrupted")
        return 130


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulnforge", description="Combined SAST + DAST security orchestrator.")
    p.add_argument("--version", action="version", version=f"VulnForge AI {__version__}")
    sub = p.add_subparsers(dest="command")

    # init
    pi = sub.add_parser("init", help="Write a starter description YAML.")
    pi.add_argument("file", nargs="?", default="app-description.yaml")
    pi.set_defaults(func=_cmd_init)

    # doctor
    pd = sub.add_parser("doctor", help="Report scanner/tool availability.")
    pd.add_argument("--runner", choices=[m.value for m in RunnerMode], default="auto")
    pd.set_defaults(func=_cmd_doctor)

    # scan
    ps = sub.add_parser("scan", help="Run a scan.")
    src = ps.add_argument_group("code source (choose one)")
    src.add_argument("--repo", help="Git repo URL to clone.")
    src.add_argument("--path", help="Local folder to scan.")
    src.add_argument("--zip", help="Zip archive of source to scan.")
    ps.add_argument("--branch", default="main")
    ps.add_argument("--url", help="Target base URL (for DAST, later phases).")
    ps.add_argument("--description", help="Path to description YAML.")
    ps.add_argument("--config", help="Path to a full scan-config YAML.")
    ps.add_argument("--out", default="runs/scan", help="Output directory.")
    ps.add_argument("--mode", choices=[m.value for m in ScanMode], default="safe")
    ps.add_argument("--sast", help="Comma-separated SAST scanners (default: all).")
    ps.add_argument("--ai", choices=["none", "anthropic", "openai"], help="AI provider.")
    ps.add_argument("--runner", choices=[m.value for m in RunnerMode], default="auto")
    ps.add_argument("--timeout", type=int, default=900, help="Per-tool timeout (s).")
    ps.add_argument("--authorized", action="store_true", help="Record explicit scan authorization.")
    ps.set_defaults(func=_cmd_scan)

    return p


def _cmd_init(args) -> int:
    path = Path(args.file)
    if path.exists():
        ui.err(f"{path} already exists; refusing to overwrite.")
        return 1
    path.write_text(_DEFAULT_DESC, encoding="utf-8")
    ui.ok(f"wrote starter description to {path}")
    ui.info("Edit it, then run:  vulnforge scan --repo <url> --description " + str(path))
    return 0


def _cmd_doctor(args) -> int:
    ui.banner(__version__)
    runner = ToolRunner(mode=RunnerMode(args.runner))
    ui.stage("Environment")
    ui.info(f"docker daemon: {'available' if docker_available() else 'NOT available'}")
    ui.info(f"runner preference: {args.runner}")
    ui.stage("SAST scanners")
    for name in known_sast():
        scanner = get_sast_scanner(name)
        avail = scanner.availability(runner)
        line = f"{name:<10} -> {avail.value}"
        (ui.ok if avail.value != "unavailable" else ui.skipped)(line)
    ui.stage("DAST scanners")
    if not known_dast():
        ui.skipped("none implemented yet (Phase 3+)")
    return 0


def _cmd_scan(args) -> int:
    ui.banner(__version__)

    # Base config: from --config file, else built from flags.
    if args.config:
        config = ScanConfig.load(args.config)
    else:
        config = ScanConfig()

    # Flag overrides.
    if args.repo or args.path or args.zip:
        config.repo = RepoSpec(url=args.repo, path=args.path, zip=args.zip, branch=args.branch)
    if args.branch:
        config.repo.branch = args.branch
    if args.url:
        config.target.base_url = args.url
    if args.out:
        config.out = args.out
    if args.mode:
        config.scan_mode = ScanMode(args.mode)
    if args.sast:
        config.sast_scanners = [s.strip() for s in args.sast.split(",") if s.strip()]
    if args.ai:
        config.ai = AIConfig(provider=args.ai)
    if args.authorized:
        config.authorized = True

    config.validate_for_sast()

    # Description.
    if args.description:
        description = AppDescription.load(args.description)
    elif args.config:
        # try description embedded in config file path's sibling? Keep simple: minimal.
        description = AppDescription.minimal()
        ui.warn("no --description provided; using minimal context (less precise prioritization)")
    else:
        description = AppDescription.minimal()
        ui.warn("no --description provided; using minimal context (less precise prioritization)")

    run_scan(
        config=config,
        description=description,
        runner_mode=RunnerMode(args.runner),
        tool_timeout=args.timeout,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
