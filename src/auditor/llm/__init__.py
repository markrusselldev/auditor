"""Modular LLM adapter.

One thin interface (`LLMProvider`), one job: turn a compact JSON of findings (plus, for the
vision read, one screenshot) into schema-validated JSON. Providers are pluggable so OpenAI today
and Claude/Gemini/others later are drop-ins behind the same call. This is deliberately NOT a
routing/streaming/fallback framework; that is a v2 concern.
"""

from auditor.llm.base import LLMError, LLMProvider
from auditor.llm.registry import get_report_provider, visibility_providers

__all__ = [
    "LLMProvider",
    "LLMError",
    "get_report_provider",
    "visibility_providers",
]
