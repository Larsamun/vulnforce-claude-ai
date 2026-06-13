"""Load and validate the two user inputs: the application *description* (business
context) and the *scan config* (what/where to scan). Both are YAML; CLI flags
override config values. Everything is lenient - missing optional fields get sane
defaults so a minimal description still works.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml


class ScanMode(str, Enum):
    SAFE = "safe"
    DEEP = "deep"
    RELEASE = "release"


class ConfigError(Exception):
    """Raised for unrecoverable configuration problems (bad YAML, no repo, etc.)."""


def _load_yaml(path: str | os.PathLike) -> dict:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"File not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Expected a mapping at the top of {p}, got {type(data).__name__}")
    return data


@dataclass
class AppDescription:
    """The 'business brain' of the scan. Drives prioritization."""

    application_name: str = "Unnamed application"
    business_purpose: str = ""
    primary_users: list[str] = field(default_factory=list)
    data_criticality: str = "medium"
    sensitive_data: list[str] = field(default_factory=list)
    critical_flows: list[str] = field(default_factory=list)
    testing_goals: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    environment: str = "staging"
    notes: str = ""
    raw: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | os.PathLike) -> "AppDescription":
        d = _load_yaml(path)
        return cls(
            application_name=d.get("application_name", cls.application_name),
            business_purpose=str(d.get("business_purpose", "")).strip(),
            primary_users=_as_list(d.get("primary_users")),
            data_criticality=str(d.get("data_criticality", "medium")).lower(),
            sensitive_data=_as_list(d.get("sensitive_data")),
            critical_flows=_as_list(d.get("critical_flows")),
            testing_goals=_as_list(d.get("testing_goals")),
            out_of_scope=_as_list(d.get("out_of_scope")),
            environment=str(d.get("environment", "staging")).lower(),
            notes=str(d.get("notes", "")).strip(),
            raw=d,
        )

    @classmethod
    def minimal(cls) -> "AppDescription":
        return cls()


@dataclass
class RepoSpec:
    url: Optional[str] = None
    path: Optional[str] = None
    zip: Optional[str] = None
    branch: str = "main"

    def validate(self) -> None:
        provided = [x for x in (self.url, self.path, self.zip) if x]
        if len(provided) == 0:
            raise ConfigError("No code source given. Provide one of: repo.url / repo.path / repo.zip")
        if len(provided) > 1:
            raise ConfigError("Provide exactly one of repo.url / repo.path / repo.zip")


@dataclass
class TargetSpec:
    base_url: Optional[str] = None
    api_specs: list[str] = field(default_factory=list)


@dataclass
class AuthSpec:
    storage_state: Optional[str] = None


@dataclass
class AIConfig:
    provider: str = "none"          # none | anthropic | openai
    explain_findings: bool = True
    use_sast_to_guide_dast: bool = True


@dataclass
class ScanConfig:
    authorized: bool = False
    operator: str = ""
    scan_mode: ScanMode = ScanMode.SAFE
    repo: RepoSpec = field(default_factory=RepoSpec)
    target: TargetSpec = field(default_factory=TargetSpec)
    auth: AuthSpec = field(default_factory=AuthSpec)
    sast_scanners: list[str] = field(default_factory=lambda: ["semgrep", "gitleaks", "trivy"])
    dast_scanners: list[str] = field(default_factory=lambda: ["headers", "nuclei", "zap"])
    ai: AIConfig = field(default_factory=AIConfig)
    out: str = "runs/scan"
    formats: list[str] = field(default_factory=lambda: ["html", "json"])
    include_mermaid: bool = True

    @classmethod
    def load(cls, path: str | os.PathLike) -> "ScanConfig":
        d = _load_yaml(path)
        repo = d.get("repo", {}) or {}
        target = d.get("target", {}) or {}
        auth = d.get("auth", {}) or {}
        scanners = d.get("scanners", {}) or {}
        ai = d.get("ai", {}) or {}
        reporting = d.get("reporting", {}) or {}
        return cls(
            authorized=bool(d.get("authorized", False)),
            operator=str(d.get("operator", "")),
            scan_mode=_parse_mode(d.get("scan_mode", "safe")),
            repo=RepoSpec(
                url=repo.get("url"),
                path=repo.get("path"),
                zip=repo.get("zip"),
                branch=str(repo.get("branch", "main")),
            ),
            target=TargetSpec(
                base_url=target.get("base_url"),
                api_specs=_as_list(target.get("api_specs")),
            ),
            auth=AuthSpec(storage_state=auth.get("storage_state")),
            sast_scanners=_as_list(scanners.get("sast")) or ["semgrep", "gitleaks", "trivy"],
            dast_scanners=_as_list(scanners.get("dast")) or ["headers", "nuclei", "zap"],
            ai=AIConfig(
                provider=str(ai.get("provider", "none")).lower(),
                explain_findings=bool(ai.get("explain_findings", True)),
                use_sast_to_guide_dast=bool(ai.get("use_sast_to_guide_dast", True)),
            ),
            out=str(reporting.get("out", "runs/scan")),
            formats=_as_list(reporting.get("formats")) or ["html", "json"],
            include_mermaid=bool(reporting.get("include_mermaid", True)),
        )

    def validate_for_sast(self) -> None:
        self.repo.validate()

    def validate_for_dast(self, environment: str = "") -> None:
        if not self.target.base_url:
            raise ConfigError("DAST requested but target.base_url is not set.")
        if not self.authorized:
            raise ConfigError(
                "active DAST requires explicit authorization (pass --authorized or set authorized: true)"
            )
        if self.scan_mode == ScanMode.DEEP and environment.lower() == "prod":
            raise ConfigError("refusing 'deep' scan mode against a production environment")


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _parse_mode(value: Any) -> ScanMode:
    try:
        return ScanMode(str(value).lower())
    except ValueError:
        return ScanMode.SAFE
