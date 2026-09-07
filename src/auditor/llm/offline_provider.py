"""No-key fallback: returns the caller's deterministic `offline_fallback`.

Keeps the whole app runnable, testable, and demoable with no API key set. It never invents prose;
each call site supplies a deterministic result (a template report, or a plain "unavailable"
notice) that this provider hands back verbatim.
"""

from __future__ import annotations


class OfflineProvider:
    name = "offline"
    available = True

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
        return dict(offline_fallback) if offline_fallback else {}
