"""Provider selection. The one place that knows which providers exist.

Adding Claude/Gemini/another popular model later is: write its provider class, then append it in
`visibility_providers` (and, if it should be the default writer, branch in `get_report_provider`).
Nothing else changes.
"""

from __future__ import annotations

import os

from auditor.llm.base import LLMProvider
from auditor.llm.gemini_provider import GeminiProvider
from auditor.llm.offline_provider import OfflineProvider
from auditor.llm.openai_provider import OpenAIProvider

# provider name -> class. One place adds a provider; get_report_provider and visibility_providers
# both read it.
_PROVIDERS = {"openai": OpenAIProvider, "gemini": GeminiProvider}


def get_report_provider() -> LLMProvider:
    """The report writer, chosen by AUDITOR_PROVIDER (openai default, or gemini for the free tier).
    Falls back to the offline template when the chosen provider has no key configured."""
    provider_cls = _PROVIDERS.get(os.environ.get("AUDITOR_PROVIDER", "openai").lower())
    if provider_cls is not None:
        provider = provider_cls()
        if provider.available:
            return provider
    return OfflineProvider()


def visibility_providers() -> list[LLMProvider]:
    """Models to poll for the "what does AI say about your business" check.

    A list on purpose: the product feature is showing the buyer what *each* mainstream model says,
    so every provider with a key configured is polled (OpenAI, Gemini, ...). With no key configured
    it returns the offline provider so the check degrades to a clear "unavailable" notice.
    """
    providers: list[LLMProvider] = [p for cls in _PROVIDERS.values() if (p := cls()).available]
    if not providers:
        providers.append(OfflineProvider())
    return providers
