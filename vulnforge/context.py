"""Run directory management and repo ingestion.

A 'run' is one scan of one target. Everything it produces lives under a single
self-contained directory so runs never interfere and evidence is easy to find.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import __version__
from .config import RepoSpec, ScanConfig, AppDescription, ConfigError
from . import console as ui


@dataclass
class StageStatus:
    name: str
    state: str                      # ran | skipped | error
    detail: str = ""
    findings: int = 0


@dataclass
class RunContext:
    out_dir: Path
    workspace: Path                 # code under test (cloned/unzipped/local)
    raw_dir: Path                   # raw tool output
    config: ScanConfig
    description: AppDescription
    started_at: str
    stages: list[StageStatus] = field(default_factory=list)
    detected_stack: list[str] = field(default_factory=list)

    @classmethod
    def create(cls, config: ScanConfig, description: AppDescription) -> "RunContext":
        out_dir = Path(config.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        workspace = out_dir / "workspace"
        raw_dir = out_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            out_dir=out_dir,
            workspace=workspace,
            raw_dir=raw_dir,
            config=config,
            description=description,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

    def record(self, status: StageStatus) -> None:
        self.stages.append(status)

    def raw_path(self, filename: str) -> Path:
        return self.raw_dir / filename

    def write_run_metadata(self) -> None:
        meta = {
            "vulnforge_version": __version__,
            "started_at": self.started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "operator": self.config.operator,
            "authorized": self.config.authorized,
            "scan_mode": self.config.scan_mode.value,
            "environment": self.description.environment,
            "application": self.description.application_name,
            "detected_stack": self.detected_stack,
            "stages": [s.__dict__ for s in self.stages],
        }
        (self.out_dir / "run.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


def ingest_repo(spec: RepoSpec, workspace: Path) -> Path:
    """Materialize the code under test into `workspace`. Returns the code root.

    Supports: git clone (url), local folder copy (path), or zip extraction (zip).
    """
    spec.validate()
    if workspace.exists():
        shutil.rmtree(workspace, ignore_errors=True)
    workspace.mkdir(parents=True, exist_ok=True)

    if spec.url:
        return _clone(spec.url, spec.branch, workspace)
    if spec.path:
        return _copy_local(spec.path, workspace)
    if spec.zip:
        return _unzip(spec.zip, workspace)
    raise ConfigError("No repo source resolved.")  # unreachable after validate()


def _clone(url: str, branch: str, workspace: Path) -> Path:
    if shutil.which("git") is None:
        raise ConfigError("git is not installed; cannot clone a repo URL. Use a local path or zip instead.")
    ui.info(f"cloning {url} (branch {branch}, shallow)")
    cmd = ["git", "clone", "--depth", "1", "--branch", branch, url, str(workspace)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        # Retry without a fixed branch (repo default branch may differ).
        ui.warn(f"branch '{branch}' clone failed, retrying default branch")
        shutil.rmtree(workspace, ignore_errors=True)
        workspace.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["git", "clone", "--depth", "1", url, str(workspace)],
            capture_output=True, text=True, timeout=600,
        )
        if r.returncode != 0:
            raise ConfigError(f"git clone failed: {r.stderr.strip()[:400]}")
    return workspace


def _copy_local(path: str, workspace: Path) -> Path:
    src = Path(path)
    if not src.exists():
        raise ConfigError(f"Local repo path not found: {src}")
    if src.is_file():
        raise ConfigError(f"Expected a folder for repo.path, got a file: {src}")
    ui.info(f"copying local folder {src}")
    shutil.rmtree(workspace, ignore_errors=True)
    shutil.copytree(src, workspace, ignore=shutil.ignore_patterns(
        ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"
    ))
    return workspace


def _unzip(zip_path: str, workspace: Path) -> Path:
    src = Path(zip_path)
    if not src.exists():
        raise ConfigError(f"Zip file not found: {src}")
    ui.info(f"extracting {src}")
    with zipfile.ZipFile(src) as zf:
        # Guard against zip-slip.
        base = workspace.resolve()
        for member in zf.namelist():
            dest = (workspace / member).resolve()
            if not str(dest).startswith(str(base)):
                raise ConfigError(f"Unsafe path in zip (zip-slip): {member}")
        zf.extractall(workspace)
    # If the zip contained a single top-level folder, descend into it.
    entries = [p for p in workspace.iterdir() if not p.name.startswith("__MACOSX")]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return workspace
