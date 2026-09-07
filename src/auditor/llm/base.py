"""The provider interface. One method, so adding a provider stays cheap."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class LLMError(RuntimeError):
    """A provider call failed (network, auth, malformed response). Callers degrade, not crash."""


@runtime_checkable
class LLMProvider(Protocol):
    """A single structured-completion call.

    Every AI call in this tool returns schema-validated JSON (Structured Outputs), grounds strictly
    in the supplied `user` payload (and optional screenshot), runs at low temperature, and is told
    to answer "insufficient information" rather than invent. A provider that cannot reach a live
    model returns `offline_fallback` unchanged so the app still works with no key.
    """

    name: str
    available: bool

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
        """Return a dict conforming to `schema`.

        `schema` is a JSON Schema object (the `schema` half of an OpenAI `json_schema` response
        format). `image_png`, when given, is attached as an image input for a grounded vision read.
        """
        ...
