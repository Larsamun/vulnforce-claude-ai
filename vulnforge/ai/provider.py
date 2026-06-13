"""Provider-agnostic LLM interface.

The rest of the codebase depends only on `LLMProvider.complete(...)`. Vendor SDKs
are imported lazily inside their provider so the package installs and runs with no
AI dependencies at all. Default provider is `none`, which returns deterministic,
templated text - so AI being unavailable NEVER breaks a scan.
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Optional


class LLMProvider(ABC):
    name = "none"
    available = False

    @abstractmethod
    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024) -> str: ...


class NullProvider(LLMProvider):
    """No external AI. Callers detect `available is False` and use deterministic
    fallbacks; this stub exists so call sites never need a None check."""
    name = "none"
    available = False

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024) -> str:
        return ""


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        self.model = model or os.environ.get("VULNFORGE_ANTHROPIC_MODEL", "claude-sonnet-4-6")
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.available = False
        self._client = None
        if self._api_key:
            try:
                import anthropic  # lazy
                self._client = anthropic.Anthropic(api_key=self._api_key)
                self.available = True
            except Exception:
                self.available = False

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024) -> str:
        if not self.available or self._client is None:
            return ""
        try:
            msg = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            return "".join(getattr(b, "text", "") for b in msg.content).strip()
        except Exception:
            return ""


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        self.model = model or os.environ.get("VULNFORGE_OPENAI_MODEL", "gpt-4o")
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.available = False
        self._client = None
        if self._api_key:
            try:
                from openai import OpenAI  # lazy
                self._client = OpenAI(api_key=self._api_key)
                self.available = True
            except Exception:
                self.available = False

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024) -> str:
        if not self.available or self._client is None:
            return ""
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            )
            return (resp.choices[0].message.content or "").strip()
        except Exception:
            return ""


def get_provider(name: Optional[str] = None) -> LLMProvider:
    """Resolve a provider by name (or VULNFORGE_AI_PROVIDER env). Always returns a
    usable object; if the requested provider can't initialize, falls back to Null."""
    choice = (name or os.environ.get("VULNFORGE_AI_PROVIDER", "none")).strip().lower()
    if choice == "anthropic":
        p = AnthropicProvider()
        return p if p.available else NullProvider()
    if choice == "openai":
        p = OpenAIProvider()
        return p if p.available else NullProvider()
    return NullProvider()
