"""Gemini through its OpenAI-compatible endpoint.

Gemini publishes an OpenAI-compatible Chat Completions API, so the whole wire format - messages,
`response_format` json_schema (Structured Outputs, supported on Gemini 2.5+), and image inputs -
matches OpenAIProvider exactly. This adapter is therefore just OpenAIProvider with a different base
URL, API key env, and default model; nothing about the request/parse logic changes.

Why it exists: Gemini has a genuinely free tier (no card), so it is the zero-cost way to run the
live report + AI-visibility calls. Select it with AUDITOR_PROVIDER=gemini and GEMINI_API_KEY. The
free tier trains on submitted content, which is acceptable here (we send public page content + our
own findings, never user secrets); the paid tier carries a no-training guarantee if that changes.

NOTE: verified against the documented compat format and unit-tested with a mocked HTTP layer. Run a
live smoke test with a real GEMINI_API_KEY before relying on it (the app degrades to the offline
template on any provider error, so a format mismatch fails safe, not loud).
"""

from __future__ import annotations

import os

from auditor.llm.openai_provider import OpenAIProvider

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"
# gemini-3.6-flash is a current free-tier flash model (checked Sep 2026). Google rotates its model
# lineup and free-tier eligibility periodically, so override per deploy with AUDITOR_REPORT_MODEL.
GEMINI_DEFAULT_MODEL = "gemini-3.6-flash"


class GeminiProvider(OpenAIProvider):
    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = 45.0,
    ) -> None:
        super().__init__(
            api_key=api_key if api_key is not None else os.environ.get("GEMINI_API_KEY", ""),
            base_url=base_url or os.environ.get("GEMINI_BASE_URL") or GEMINI_BASE_URL,
            model=model or os.environ.get("AUDITOR_REPORT_MODEL") or GEMINI_DEFAULT_MODEL,
            timeout=timeout,
        )
        self.name = "gemini"
