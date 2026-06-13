"""Lightweight technology-stack detection from marker files in the workspace.

This is the cheap version of 'asset and context discovery' - enough to label the
report and steer scanners/AI, without a full code graph (a later phase)."""
from __future__ import annotations

import json
from pathlib import Path

# marker filename -> human label
_MARKERS: dict[str, str] = {
    "package.json": "Node.js",
    "requirements.txt": "Python",
    "pyproject.toml": "Python",
    "Pipfile": "Python",
    "pom.xml": "Java (Maven)",
    "build.gradle": "Java/Kotlin (Gradle)",
    "build.gradle.kts": "Java/Kotlin (Gradle)",
    "composer.json": "PHP",
    "go.mod": "Go",
    "Gemfile": "Ruby",
    "Cargo.toml": "Rust",
    "Dockerfile": "Docker",
    "docker-compose.yml": "Docker Compose",
    "docker-compose.yaml": "Docker Compose",
}

# package.json dependency -> framework label
_JS_FRAMEWORKS = {
    "next": "Next.js",
    "react": "React",
    "@angular/core": "Angular",
    "vue": "Vue",
    "express": "Express",
    "@nestjs/core": "NestJS",
    "fastify": "Fastify",
}
_PY_FRAMEWORKS = {
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
}


def detect_stack(root: str | Path) -> list[str]:
    root = Path(root)
    found: list[str] = []

    for marker, label in _MARKERS.items():
        # shallow + one level deep is enough for monorepos' obvious roots
        if (root / marker).exists() or any(root.glob(f"*/{marker}")):
            if label not in found:
                found.append(label)

    # Enrich with frameworks from package.json
    for pkg in [root / "package.json", *root.glob("*/package.json")]:
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
            for dep, label in _JS_FRAMEWORKS.items():
                if dep in deps and label not in found:
                    found.append(label)
        except Exception:
            continue

    # Enrich with Python frameworks from requirements.txt
    for req in [root / "requirements.txt", *root.glob("*/requirements.txt")]:
        try:
            text = req.read_text(encoding="utf-8").lower()
            for dep, label in _PY_FRAMEWORKS.items():
                if dep in text and label not in found:
                    found.append(label)
        except Exception:
            continue

    # IaC
    if any(root.rglob("*.tf")):
        found.append("Terraform")
    if any(root.rglob("*.bicep")):
        found.append("Bicep")

    return found
