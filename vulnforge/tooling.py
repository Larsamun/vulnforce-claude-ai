"""Tool availability detection and a uniform command runner.

This is the seam that lets VulnForge 'fail gracefully': before running any scanner
we resolve how (or whether) it can run - native binary on PATH, or via Docker, or
not at all - and the pipeline adapts instead of crashing.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Optional, Sequence


class RunnerMode(str, Enum):
    AUTO = "auto"       # prefer docker, fall back to native
    DOCKER = "docker"   # docker only
    NATIVE = "native"   # native only


class Availability(str, Enum):
    NATIVE = "native"
    DOCKER = "docker"
    UNAVAILABLE = "unavailable"


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@lru_cache(maxsize=1)
def docker_available() -> bool:
    """True if a usable Docker daemon is reachable."""
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=20,
        )
        return r.returncode == 0
    except Exception:
        return False


def native_available(binary: Optional[str]) -> bool:
    return bool(binary) and shutil.which(binary) is not None


def docker_image_present(image: str) -> bool:
    """True if the image is already pulled locally (so we can run offline / fast)."""
    if not docker_available():
        return False
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, text=True, timeout=20,
        )
        return r.returncode == 0
    except Exception:
        return False


class ToolRunner:
    """Runs external tools either natively or in Docker, with timeouts and output
    capture. One instance per scan; carries the configured runner preference."""

    def __init__(self, mode: RunnerMode = RunnerMode.AUTO, timeout: int = 900):
        self.mode = mode
        self.timeout = timeout

    def resolve(self, native_binary: Optional[str], docker_image: Optional[str]) -> Availability:
        """Decide how a given tool can run under the current preference."""
        can_native = native_available(native_binary)
        can_docker = bool(docker_image) and docker_available()
        if self.mode == RunnerMode.NATIVE:
            return Availability.NATIVE if can_native else Availability.UNAVAILABLE
        if self.mode == RunnerMode.DOCKER:
            return Availability.DOCKER if can_docker else Availability.UNAVAILABLE
        # AUTO: prefer native if already installed (fast), else docker.
        if can_native:
            return Availability.NATIVE
        if can_docker:
            return Availability.DOCKER
        return Availability.UNAVAILABLE

    def run_native(self, cmd: Sequence[str], cwd: Optional[str] = None) -> CommandResult:
        return self._run(list(cmd), cwd=cwd)

    def run_docker(
        self,
        image: str,
        args: Sequence[str],
        mounts: Optional[dict[str, str]] = None,
        workdir: Optional[str] = None,
        network: Optional[str] = None,
        read_only_mounts: bool = False,
    ) -> CommandResult:
        """Run `image` with the given args. `mounts` maps host path -> container path."""
        cmd: list[str] = ["docker", "run", "--rm"]
        for host, container in (mounts or {}).items():
            host_abs = str(Path(host).resolve())
            suffix = ":ro" if read_only_mounts else ""
            cmd += ["-v", f"{host_abs}:{container}{suffix}"]
        if workdir:
            cmd += ["-w", workdir]
        if network:
            cmd += ["--network", network]
        cmd.append(image)
        cmd += list(args)
        return self._run(cmd)

    def _run(self, cmd: list[str], cwd: Optional[str] = None) -> CommandResult:
        try:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env={**os.environ},
            )
            return CommandResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ""
            err = exc.stderr or ""
            if isinstance(out, bytes):
                out = out.decode("utf-8", "ignore")
            if isinstance(err, bytes):
                err = err.decode("utf-8", "ignore")
            return CommandResult(124, out, f"timed out after {self.timeout}s\n{err}", timed_out=True)
        except FileNotFoundError as exc:
            return CommandResult(127, "", f"command not found: {exc}")
        except Exception as exc:  # noqa: BLE001
            return CommandResult(1, "", f"failed to run {cmd[0]}: {exc}")
