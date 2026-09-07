"""Gemini via its OpenAI-compatible endpoint: same wire format as OpenAIProvider, different base
URL / key / model. Unit-tested with a mocked HTTP layer (no live key); a real-key smoke test is a
separate manual step before relying on it."""

import json
import unittest
from unittest.mock import patch

from auditor.llm.gemini_provider import GEMINI_BASE_URL, GeminiProvider


class _FakeResp:
    def __init__(self, payload):
        self._p = json.dumps(payload).encode()

    def read(self):
        return self._p

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_CHAT_OK = {"choices": [{"message": {"content": '{"ok": true}'}}]}
_SCHEMA = {"type": "object", "additionalProperties": False,
           "required": ["ok"], "properties": {"ok": {"type": "boolean"}}}


class GeminiProviderTest(unittest.TestCase):
    def test_defaults_point_at_the_compat_endpoint(self):
        p = GeminiProvider(api_key="k")
        self.assertEqual(p.name, "gemini")
        self.assertEqual(p.base_url, GEMINI_BASE_URL)
        self.assertTrue(p.model.startswith("gemini"))
        self.assertTrue(p.available)

    def test_key_from_env(self):
        with patch.dict("os.environ", {"GEMINI_API_KEY": "abc"}):
            self.assertTrue(GeminiProvider().available)
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(GeminiProvider().available)

    def test_completes_json_against_the_gemini_endpoint(self):
        captured = {}

        def _fake_urlopen(request, timeout=None):
            captured["url"] = request.full_url
            captured["auth"] = request.headers.get("Authorization")
            return _FakeResp(_CHAT_OK)

        p = GeminiProvider(api_key="secret")
        with patch("auditor.llm.openai_provider.urllib.request.urlopen", _fake_urlopen):
            out = p.complete_json(system="s", user="u", schema=_SCHEMA)
        self.assertEqual(out, {"ok": True})
        self.assertEqual(captured["url"], f"{GEMINI_BASE_URL}/chat/completions")
        self.assertEqual(captured["auth"], "Bearer secret")

    def test_unavailable_returns_offline_fallback(self):
        p = GeminiProvider(api_key="")
        out = p.complete_json(system="s", user="u", schema=_SCHEMA, offline_fallback={"ok": False})
        self.assertEqual(out, {"ok": False})


class RegistrySelectionTest(unittest.TestCase):
    def test_provider_flag_selects_gemini(self):
        from auditor.llm.registry import get_report_provider
        with patch.dict("os.environ", {"AUDITOR_PROVIDER": "gemini", "GEMINI_API_KEY": "k"}):
            self.assertIsInstance(get_report_provider(), GeminiProvider)

    def test_visibility_polls_every_keyed_provider(self):
        from auditor.llm.registry import visibility_providers
        with patch.dict("os.environ", {"OPENAI_API_KEY": "a", "GEMINI_API_KEY": "b"}):
            names = {p.name for p in visibility_providers()}
        self.assertEqual(names, {"openai", "gemini"})

    def test_no_keys_degrades_to_offline(self):
        from auditor.llm.registry import get_report_provider, visibility_providers
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(get_report_provider().name, "offline")
            self.assertEqual([p.name for p in visibility_providers()], ["offline"])


if __name__ == "__main__":
    unittest.main()
