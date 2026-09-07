"""AI-visibility checks: the new, differentiating layer.

Deterministic code decides everything factual: is there an llms.txt, is schema.org present and
parseable, does robots.txt block the AI crawlers buyers recognize. Exactly one call reaches a live
model, the "what does AI say about your business" query, and it runs behind a hard hallucination
guard: report only genuine knowledge, signal "little / no AI visibility" rather than invent.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from auditor import security

# A browser UA, not a bot UA: some hosts 403-wall unknown agents. Kept local (one string) so this
# module imports fast and tests without pulling the Playwright/crawlee engine.
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

# The crawlers a buyer recognizes. Table-driven: adding one is a single list entry.
AI_CRAWLERS = ("GPTBot", "Google-Extended", "CCBot", "ClaudeBot", "PerplexityBot")


@dataclass(slots=True)
class CheckResult:
    key: str
    present: bool
    status: str          # human-readable one-liner
    detail: dict = field(default_factory=dict)


def _fetch_text(url: str, timeout: float = 12.0) -> tuple[int | str, str, str]:
    """Return (status, final_url, body). status is "" on a transport error, body "" on failure."""
    # SSRF egress guard: refuse a non-global initial host, and (via the guarded opener) any redirect
    # hop that lands on one. See auditor.security.
    if security.host_is_blocked(urlsplit(url).hostname):
        return "", url, ""
    request = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA})
    try:
        with security.urlopen_guarded(request, timeout=timeout) as response:
            raw = response.read(2_000_000)  # cap: these files are tiny; do not slurp a huge page
            return response.status, response.geturl(), raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, url, ""
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, security.SecurityError):
        return "", url, ""


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def check_llms_txt(base_url: str, timeout: float = 12.0) -> CheckResult:
    """llms.txt is the emerging convention for handing an LLM a curated map of your site."""
    target = urljoin(_origin(base_url) + "/", "llms.txt")
    status, _final, body = _fetch_text(target, timeout)
    present = status == 200 and body.strip() != "" and "<html" not in body[:2000].lower()
    if present:
        return CheckResult("llms_txt", True, "llms.txt is published", {"url": target, "bytes": len(body)})
    return CheckResult("llms_txt", False, "No llms.txt found", {"url": target, "http_status": status})


class _SchemaParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_ld = False
        self._buffer: list[str] = []
        self.ld_blocks: list[str] = []
        self.microdata_types: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        adict = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and adict.get("type", "").lower() == "application/ld+json":
            self._in_ld = True
            self._buffer = []
        if "itemtype" in adict and "schema.org" in adict["itemtype"].lower():
            self.microdata_types.append(adict["itemtype"].rsplit("/", 1)[-1])

    def handle_data(self, data: str) -> None:
        if self._in_ld:
            self._buffer.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_ld:
            self.ld_blocks.append("".join(self._buffer))
            self._in_ld = False


def _collect_types(node: object, out: list[str]) -> None:
    if isinstance(node, dict):
        value = node.get("@type")
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, list):
            out.extend(t for t in value if isinstance(t, str))
        if "@graph" in node:
            _collect_types(node["@graph"], out)
    elif isinstance(node, list):
        for item in node:
            _collect_types(item, out)


def check_schema_org(homepage_html: str) -> CheckResult:
    """Present AND valid: schema.org markup that actually parses and carries an @type."""
    parser = _SchemaParser()
    try:
        parser.feed(homepage_html or "")
    except Exception:  # a malformed page must never crash the scan
        pass
    types: list[str] = []
    parse_errors = 0
    for block in parser.ld_blocks:
        block = block.strip()
        if not block:
            continue
        try:
            _collect_types(json.loads(block), types)
        except json.JSONDecodeError:
            parse_errors += 1
    types.extend(parser.microdata_types)
    unique = sorted({t for t in types if t})
    if unique:
        return CheckResult(
            "schema_org", True,
            f"schema.org present ({', '.join(unique[:6])})",
            {"types": unique, "json_ld_blocks": len(parser.ld_blocks), "parse_errors": parse_errors},
        )
    if parser.ld_blocks and parse_errors:
        return CheckResult("schema_org", False, "schema.org markup present but does not parse",
                           {"json_ld_blocks": len(parser.ld_blocks), "parse_errors": parse_errors})
    return CheckResult("schema_org", False, "No schema.org structured data found", {})


def _parse_robots(text: str) -> dict[str, list[tuple[str, str]]]:
    groups: dict[str, list[tuple[str, str]]] = {}
    current: list[str] = []
    started_rules = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field_name, _, value = line.partition(":")
        field_name = field_name.strip().lower()
        value = value.strip()
        if field_name == "user-agent":
            if started_rules:
                current = []
                started_rules = False
            current.append(value.lower())
            groups.setdefault(value.lower(), [])
        elif field_name in ("disallow", "allow"):
            started_rules = True
            for agent in current:
                groups[agent].append((field_name, value))
    return groups


def _bot_status(groups: dict[str, list[tuple[str, str]]], bot: str) -> str:
    """"blocked" (Disallow: /), "allowed", or "not_specified" (falls under * or nothing)."""
    rules = groups.get(bot.lower())
    scope = bot
    if rules is None:
        rules = groups.get("*")
        scope = "*"
    if rules is None:
        return "not_specified"
    blocked = any(directive == "disallow" and value == "/" for directive, value in rules)
    if scope == "*" and blocked is False and not rules:
        return "not_specified"
    return "blocked" if blocked else "allowed"


def check_ai_crawler_access(base_url: str, timeout: float = 12.0) -> CheckResult:
    """Does robots.txt let the recognized AI crawlers in? Blocking them hides you from AI answers."""
    target = urljoin(_origin(base_url) + "/", "robots.txt")
    status, _final, body = _fetch_text(target, timeout)
    if status != 200 or not body.strip():
        # No robots.txt means nothing is disallowed: every crawler is allowed by default.
        per_bot = dict.fromkeys(AI_CRAWLERS, "allowed")
        return CheckResult("ai_crawler_access", True, "No robots.txt (all AI crawlers allowed)",
                           {"per_bot": per_bot, "robots_present": False})
    groups = _parse_robots(body)
    per_bot = {bot: _bot_status(groups, bot) for bot in AI_CRAWLERS}
    blocked = [bot for bot, state in per_bot.items() if state == "blocked"]
    if blocked:
        return CheckResult("ai_crawler_access", False,
                           f"robots.txt blocks {', '.join(blocked)}",
                           {"per_bot": per_bot, "robots_present": True, "blocked": blocked})
    return CheckResult("ai_crawler_access", True, "AI crawlers are allowed",
                       {"per_bot": per_bot, "robots_present": True, "blocked": []})


# --- The one live query: what does mainstream AI say about this business? ---

_WHAT_AI_SAYS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["has_reliable_knowledge", "summary", "confidence"],
    "properties": {
        "has_reliable_knowledge": {
            "type": "boolean",
            "description": "True ONLY if you hold genuine, reliable knowledge of THIS specific business.",
        },
        "summary": {
            "type": "string",
            "description": "If has_reliable_knowledge is false, say plainly that you have little or no "
                           "reliable information on this business. Never invent plausible-sounding facts.",
        },
        "confidence": {"type": "string", "enum": ["none", "low", "medium", "high"]},
    },
}

_WHAT_AI_SAYS_SYSTEM = (
    "You are a mainstream AI assistant answering what you actually know about a specific business, "
    "from your training only. This is a visibility check, so accuracy matters more than helpfulness. "
    "Report ONLY genuine, reliable knowledge. If you do not have reliable information about this exact "
    "business, set has_reliable_knowledge to false and say so plainly. Do NOT guess, do NOT infer from "
    "the name, and never present invented or plausible-sounding claims as fact. Distinguish 'I have no "
    "reliable information on this business' from confident knowledge."
)


def what_ai_says(business_name: str, homepage_url: str, providers) -> list[dict]:
    """Poll each provider for what it genuinely knows. Fan-out is a list so more models append later."""
    results: list[dict] = []
    user = (
        f"Business name: {business_name or '(unknown)'}\n"
        f"Website: {homepage_url}\n\n"
        "What do you reliably know about this specific business? Follow the guard exactly."
    )
    for provider in providers:
        fallback = {
            "has_reliable_knowledge": False,
            "summary": "No AI model is configured, so this live check did not run.",
            "confidence": "none",
        }
        answer = provider.complete_json(
            system=_WHAT_AI_SAYS_SYSTEM,
            user=user,
            schema=_WHAT_AI_SAYS_SCHEMA,
            temperature=0.0,
            offline_fallback=fallback,
        )
        results.append({"model": provider.name, **answer})
    return results


def run_ai_visibility(
    homepage_url: str, homepage_html: str, business_name: str, providers, timeout: float = 12.0,
) -> dict:
    """Run all four AI-visibility checks and return a compact, JSON-serializable summary."""
    llms = check_llms_txt(homepage_url, timeout)
    schema = check_schema_org(homepage_html)
    crawlers = check_ai_crawler_access(homepage_url, timeout)
    ai_answers = what_ai_says(business_name, homepage_url, providers)
    return {
        "llms_txt": _as_dict(llms),
        "schema_org": _as_dict(schema),
        "ai_crawler_access": _as_dict(crawlers),
        "what_ai_says": ai_answers,
    }


def _as_dict(result: CheckResult) -> dict:
    return {"key": result.key, "present": result.present, "status": result.status, "detail": result.detail}
