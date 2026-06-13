"""The Scanner contract every SAST/DAST tool adapter implements.

A Scanner declares how it can run (native binary and/or docker image) and knows how
to (a) execute against a target and (b) parse its raw output into normalized
`Finding`s. The orchestrator handles availability, skipping, and error capture so
individual adapters stay small.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from ..models import Finding, Engine
from ..tooling import ToolRunner, Availability


@dataclass
class ScannerOutcome:
    """Result of attempting to run one scanner."""
    scanner: str
    state: str                      # ran | skipped | error
    findings: list[Finding] = field(default_factory=list)
    detail: str = ""
    raw_file: Optional[str] = None


class Scanner(ABC):
    name: str = "scanner"
    engine: Engine = Engine.SAST
    native_binary: Optional[str] = None
    docker_image: Optional[str] = None

    def availability(self, runner: ToolRunner) -> Availability:
        return runner.resolve(self.native_binary, self.docker_image)

    @abstractmethod
    def scan(self, target_dir: str, runner: ToolRunner, raw_out) -> ScannerOutcome:
        """Run against `target_dir` (SAST) or a URL (DAST). `raw_out` is a callable
        (filename, text) -> path used to persist raw tool output for evidence."""
        raise NotImplementedError
