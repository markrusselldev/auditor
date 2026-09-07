"""OpenAI (default GPT-4o-mini) via the Chat Completions REST endpoint, stdlib only.

No SDK: one urllib POST keeps the dependency surface flat and makes the base URL a swap, so any
OpenAI-compatible endpoint (or a compatible Gemini/Claude gateway) drops in by env var. Uses
Structured Outputs (`json_schema`, strict) so the model returns schema-valid JSON, and supports an
optional image for the grounded vision read.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request

from auditor.llm.base import LLMError

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIProvider:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = 45.0,
    ) -> None:
        self.name = "openai"
        self.api_key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY", "")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.model = model or os.environ.get("AUDITOR_REPORT_MODEL") or DEFAULT_MODEL
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict,
        image_png: bytes | None = None,
        temperature: float = 0.2,
        offline_fallback: dict | None = None,
    ) -> dict:
        if not self.available:
            if offline_fallback is not None:
                return dict(offline_fallback)
            raise LLMError("OPENAI_API_KEY is not set")
        user_content: list[dict] | str = user
        if image_png is not None:
            data_url = "data:image/png;base64," + base64.b64encode(image_png).decode("ascii")
            user_content = [
                {"type": "text", "text": user},
                {"type": "image_url", "image_url": {"url": data_url, "detail": "low"}},
            ]
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_content},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "auditor_response", "strict": True, "schema": schema},
            },
        }
        try:
            content = self._post(payload)
            return json.loads(content)
        except (LLMError, json.JSONDecodeError, KeyError, ValueError) as exc:
            # A free public tool must not 500 because the model timed out or returned junk: fall back
            # to the caller's deterministic result when one exists, and surface the cause otherwise.
            print(f"{self.name} provider error: {exc}", file=sys.stderr, flush=True)
            if offline_fallback is not None:
                return dict(offline_fallback)
            raise LLMError(str(exc)) from exc

    def _post(self, payload: dict) -> str:
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise LLMError(f"HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LLMError(str(exc)) from exc
        return body["choices"][0]["message"]["content"]
