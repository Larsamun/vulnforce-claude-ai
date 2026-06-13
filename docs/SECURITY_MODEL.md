# VulnForge AI — Security Model

VulnForge is an offensive-security tool: it runs scanners that can touch source
code, secrets, and live applications. It must be safe to operate and must not
become a liability itself.

## Authorization

- Every run records an **explicit authorization** marker (`authorized: true` in the
  scan config, plus the operator identity and target) in `run.json`. No
  authorization record → the run refuses active DAST testing.
- Active DAST against `prod` requires `scan_mode: safe`. `deep` mode is rejected
  against an environment marked `prod`.

## Scan modes (safety envelope)

| Mode | Destructive payloads | Brute force | DoS / heavy fuzz | Rate limited |
|------|----------------------|-------------|------------------|--------------|
| safe | no | no | no | yes |
| deep | controlled/validated | no | bounded | yes |
| release | no | no | no | yes |

Default is `safe`. The AI test planner emits a `safe_for_prod` flag per test; in
`safe` mode, tests without it are dropped.

## Isolation

- Each scan runs in its own **run directory**; tools that support containerization
  run in Docker with the workspace mounted read-only where possible.
- No access to the host filesystem beyond the mounted scan workspace.
- Per-tool **timeouts** and output caps prevent runaway processes.

## Secrets & credentials

- Gitleaks/Trivy will surface secrets found in code. Raw secret *values* are
  **masked** in normalized findings and reports (only a fingerprint + location is
  kept).
- Auth material for DAST (cookies, tokens, Playwright `storageState`) is treated as
  sensitive: stored only under the run directory, never logged, and excluded from
  the repo via `.gitignore`. Production hardening (encryption at rest, per-workspace
  isolation) is a documented follow-up.

## AI data handling

- The AI layer is **optional** and **off by default** (`VULNFORGE_AI_PROVIDER=none`).
- When enabled, only summaries/metadata of findings are sent to the provider, not
  raw secret values. Operators should treat any external AI provider as an external
  service and confirm policy before enabling it on sensitive codebases.

## Logging

- Tool stderr/stdout is captured under `raw/` for evidence and debugging.
- Secrets are masked before anything is written to normalized output or the report.
