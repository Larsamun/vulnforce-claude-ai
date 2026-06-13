"""Thin presentation helpers. Uses `rich` when available, degrades to plain print.

Keeping this isolated means the rest of the code calls `ui.stage(...)` / `ui.ok(...)`
without caring whether rich is installed - another small 'fail gracefully' seam.
"""
from __future__ import annotations

from contextlib import contextmanager

try:
    from rich.console import Console
    from rich.theme import Theme

    _console = Console(
        theme=Theme(
            {
                "ok": "bold green",
                "warn": "bold yellow",
                "err": "bold red",
                "stage": "bold cyan",
                "muted": "dim",
            }
        )
    )
    _RICH = True
except Exception:  # pragma: no cover - rich is a declared dep, but stay robust
    _console = None
    _RICH = False


def _emit(markup: str, plain: str) -> None:
    if _RICH:
        _console.print(markup)
    else:
        print(plain)


def banner(version: str) -> None:
    _emit(
        f"[stage]VulnForge AI[/stage] [muted]v{version}[/muted]  "
        f"[muted]combined SAST + DAST orchestrator[/muted]",
        f"VulnForge AI v{version} - combined SAST + DAST orchestrator",
    )


def stage(text: str) -> None:
    _emit(f"\n[stage]>> {text}[/stage]", f"\n>> {text}")


def ok(text: str) -> None:
    _emit(f"  [ok]+[/ok] {text}", f"  [OK] {text}")


def warn(text: str) -> None:
    _emit(f"  [warn]! {text}[/warn]", f"  [WARN] {text}")


def err(text: str) -> None:
    _emit(f"  [err]x {text}[/err]", f"  [ERROR] {text}")


def info(text: str) -> None:
    _emit(f"  [muted]{text}[/muted]", f"  {text}")


def skipped(text: str) -> None:
    _emit(f"  [muted]- skip:[/muted] {text}", f"  [SKIP] {text}")


@contextmanager
def step(text: str):
    """Context manager that prints start, and OK/ERROR depending on exceptions."""
    _emit(f"  [muted]...[/muted] {text}", f"  ... {text}")
    try:
        yield
    except Exception as exc:  # noqa: BLE001 - surface, never crash the pipeline here
        err(f"{text}: {exc}")
        raise
    else:
        ok(text)
