# VulnForge AI — Architecture

## Principle

Keep it simple and robust. A linear, observable pipeline with a clean adapter per
external tool. Each stage emits progress and survives the failure of any single
tool. One target per run; state lives in a self-contained run directory.

## Pipeline

```
                ┌─────────────────────┐
                │   CLI  (vulnforge)   │
                └──────────┬──────────┘
                           │  loads description.yaml + scan-config
                ┌──────────▼──────────┐
                │  App Context Builder │  business context + detected stack
                └──────────┬──────────┘
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  SAST Engine  │  │  DAST Engine  │  │  AI Test      │
│ semgrep/      │  │ zap/nuclei/   │  │  Planner      │
│ gitleaks/trivy│  │ headers (🚧)  │  │  (🚧)         │
└───────┬───────┘  └───────┬───────┘  └───────┬───────┘
        └──────────────────┼──────────────────┘
                ┌──────────▼──────────┐
                │ Correlation Engine  │  fuse SAST+DAST -> confidence  (🚧)
                └──────────┬──────────┘
                ┌──────────▼──────────┐
                │ Visual Mapping      │  Mermaid diagrams  (🚧)
                └──────────┬──────────┘
                ┌──────────▼──────────┐
                │ Report + findings   │  HTML + findings.json
                └─────────────────────┘
```

(🚧 = scaffolded contract, implemented in later phases.)

## Module map (code)

| Package | Responsibility |
|---------|---------------|
| `vulnforge/cli.py` | Argparse CLI: `init`, `scan`, `report`, `doctor` |
| `vulnforge/config.py` | Load/validate description + scan config (dataclasses) |
| `vulnforge/models.py` | `Finding`, `Severity`, normalized schema, dedup |
| `vulnforge/context.py` | Run directory + repo ingestion (clone / unzip / local) |
| `vulnforge/tooling.py` | Tool availability detection + command runner (Docker/native), timeouts |
| `vulnforge/console.py` | Rich-based progress + graceful status reporting |
| `vulnforge/scanners/base.py` | `Scanner` ABC, `Availability`, `ScannerOutcome` |
| `vulnforge/scanners/registry.py` | Discovery + availability resolution |
| `vulnforge/scanners/sast/*` | Semgrep / Gitleaks / Trivy adapters |
| `vulnforge/scanners/dast/*` | DAST adapters (scaffold) |
| `vulnforge/ai/provider.py` | Provider-agnostic LLM interface (none/anthropic/openai) |
| `vulnforge/ai/*` | summarizer / planner / correlator (scaffold) |
| `vulnforge/correlate/*` | SAST↔DAST correlation (scaffold) |
| `vulnforge/report/*` | HTML report + findings.json + Mermaid |

## Tool adapter contract

Every external tool is a `Scanner` subclass that declares a `docker_image` and/or a
`native_binary`. At runtime the registry resolves an `Availability`
(`native` > `docker` > `unavailable`, per the configured runner preference). A
scanner that is `unavailable` is **skipped**, recorded as a skipped stage, and the
pipeline continues. A scanner that runs but errors is caught, recorded with its
stderr, and likewise does not abort the run.

This is what makes the tool "fail gracefully" and "show progression": the report
always lists, per scanner, one of `ran` / `skipped (not available)` / `error`.

## Run directory layout

```
runs/<name>/
  run.json                 # run metadata + per-stage status
  workspace/               # cloned/unzipped code under test
  raw/                     # raw tool output (semgrep.json, gitleaks.json, ...)
  findings.json            # normalized, deduplicated findings
  report.html             # final report
```

## AI abstraction

`ai/provider.py` exposes `get_provider()` returning a `LLMProvider` with a single
`complete(system, prompt) -> str`. Implementations: `NullProvider` (default —
deterministic templated text, zero dependencies), `AnthropicProvider`,
`OpenAIProvider`. The rest of the codebase never imports a vendor SDK directly, so
swapping or disabling AI is a one-line config change and never breaks a scan.
