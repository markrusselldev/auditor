from __future__ import annotations

import csv
import os
import re
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urldefrag, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


USER_AGENT = "Auditor/1.0 website-validator (+https://markrussell.io)"
MAX_REDIRECTS = 10
MAX_PAGE_BYTES = 1_000_000
MAX_VERIFICATION_BYTES = 65_536

CATEGORY_KEYWORDS = {
    "donation": ("donate", "donation", "donations", "giving", "give", "support us"),
    "ticket": ("ticket", "tickets", "box office", "admission", "admissions", "purchase"),
    "contact": ("contact", "contact us", "get in touch"),
    "membership": ("member", "members", "membership", "join", "renew"),
    "registration": ("register", "registration", "rsvp", "sign up", "signup"),
    "event": ("event", "events", "calendar", "what's on", "whats on"),
}

DANGEROUS_TERMS = {
    "login", "log-in", "logout", "log-out", "signin", "sign-in", "admin",
    "account", "my-account", "cart", "add-to-cart", "remove", "delete",
    "destroy", "checkout", "search", "wp-login", "wp-admin",
}
ASSET_EXTENSIONS = {
    ".7z", ".avi", ".css", ".doc", ".docx", ".gif", ".gz", ".ico",
    ".jpeg", ".jpg", ".js", ".json", ".mov", ".mp3", ".mp4", ".pdf",
    ".png", ".ppt", ".pptx", ".rar", ".svg", ".tar", ".txt", ".webp",
    ".xls", ".xlsx", ".xml", ".zip",
}
TEST_TERMS = {"test", "testing", "staging", "sandbox", "demo", "dev", "qa", "localhost"}
PLACEHOLDER_HOSTS = {"example.com", "example.org", "example.net"}
PARKING_PHRASES = (
    "domain is for sale", "buy this domain", "parked free", "domain parking",
    "this domain may be for sale", "website coming soon",
)


@dataclass(frozen=True, slots=True)
class RevenueTarget:
    category: str
    control: str
    url: str
    source_page: str
    kind: str
    invalid_reason: str = ""


@dataclass(slots=True)
class FetchResult:
    tested_url: str
    final_url: str = ""
    status_code: int | str = ""
    outcome: str = ""
    detail: str = ""
    redirects: int = 0
    elapsed_ms: int = 0
    content_type: str = ""
    body: str = ""
    attempts: tuple[str, ...] = ()


@dataclass(slots=True)
class Finding:
    organization: str
    homepage: str
    finding_type: str
    category: str
    severity: str
    source_page: str
    link_text_or_control: str
    tested_url: str
    final_url: str
    status_code: int | str
    evidence: str
    verification: str
    elapsed_ms: int


@dataclass(slots=True)
class ScanSummary:
    organization: str
    homepage: str
    pages_scanned: int
    revenue_targets_checked: int
    actionable_findings: int
    critical_findings: int
    high_findings: int
    scan_outcome: str


class TrackingRedirectHandler(HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def __init__(self) -> None:
        super().__init__()
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        return super().redirect_request(req, fp, code, msg, headers, normalize_url(newurl))


def _metadata(attrs: dict[str, str], text: str = "") -> str:
    values = [text]
    for name in ("aria-label", "title", "id", "class", "alt"):
        values.append(attrs.get(name, ""))
    return " ".join(" ".join(values).split())


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self.iframes: list[tuple[str, str]] = []
        self.forms: list[dict[str, object]] = []
        self.buttons: list[dict[str, object]] = []
        self._anchor: dict[str, object] | None = None
        self._button: dict[str, object] | None = None
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {key.lower(): value or "" for key, value in attrs_list}
        tag = tag.lower()
        if tag == "a" and self._anchor is None:
            self._anchor = {"attrs": attrs, "text": []}
        elif tag == "form":
            self._form = {"attrs": attrs, "text": [], "buttons": []}
        elif tag == "button":
            self._button = {"attrs": attrs, "text": []}
        elif tag == "iframe" and attrs.get("src"):
            self.iframes.append((attrs["src"], _metadata(attrs)))
        elif tag == "img":
            alt = attrs.get("alt", "")
            if self._anchor is not None and alt:
                self._anchor["text"].append(alt)  # type: ignore[union-attr]
            if self._button is not None and alt:
                self._button["text"].append(alt)  # type: ignore[union-attr]
            if self._form is not None and alt:
                self._form["text"].append(alt)  # type: ignore[union-attr]
        if self._form is not None and tag in {"input", "select", "textarea"}:
            self._form["text"].append(_metadata(attrs, attrs.get("value", "")))  # type: ignore[union-attr]

    def handle_data(self, data: str) -> None:
        if self._anchor is not None:
            self._anchor["text"].append(data)  # type: ignore[union-attr]
        if self._button is not None:
            self._button["text"].append(data)  # type: ignore[union-attr]
        if self._form is not None:
            self._form["text"].append(data)  # type: ignore[union-attr]

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "a" and self._anchor is not None:
            attrs = self._anchor["attrs"]
            text = "".join(self._anchor["text"])
            href = attrs.get("href", "")  # type: ignore[union-attr]
            if href:
                self.anchors.append((href, _metadata(attrs, text)))  # type: ignore[arg-type]
            self._anchor = None
        elif tag == "button" and self._button is not None:
            attrs = self._button["attrs"]
            text = "".join(self._button["text"])
            button = {"attrs": attrs, "control": _metadata(attrs, text)}
            self.buttons.append(button)
            if self._form is not None:
                self._form["buttons"].append(button)  # type: ignore[union-attr]
            self._button = None
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def normalize_url(value: str, base_url: str | None = None) -> str:
    value = value.strip()
    if not value:
        raise ValueError("URL is empty")
    if base_url:
        value = urljoin(base_url, value)
    elif "://" not in value:
        value = f"https://{value}"
    value, _fragment = urldefrag(value)
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("URL has no hostname")
    host = parsed.hostname.lower().encode("idna").decode("ascii")
    if ":" in host:
        host = f"[{host}]"
    if parsed.port and not ((scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)):
        host = f"{host}:{parsed.port}"
    path = quote(re.sub(r"/{2,}", "/", parsed.path or "/"), safe="/%:@!$&'()*+,;=-._~")
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit((scheme, host, path, query, ""))


def resolve_url(source_url: str, value: str) -> str | None:
    try:
        return normalize_url(value, source_url)
    except (ValueError, UnicodeError):
        return None


def is_valid_mailto(value: str) -> bool:
    """Return whether value is an intentional, minimally valid email action."""
    if any(character.isspace() for character in value):
        return False
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "mailto" or parsed.netloc or parsed.fragment:
        return False
    addresses = parsed.path.split(",")
    return bool(addresses) and all(
        re.fullmatch(r"[^@,]+@[^@,\.]+(?:\.[^@,\.]+)+", address)
        for address in addresses
    )


def _invalid_action_reason(value: str) -> str:
    stripped = value.strip()
    lowered = stripped.lower()
    if not stripped:
        return "missing form action"
    if stripped.startswith("#") or lowered in {"javascript:", "javascript:void(0)", "about:blank"}:
        return "placeholder form action"
    return "invalid action URL"


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", value.lower()))


def classify_target(*values: str) -> str | None:
    candidate = " ".join(values).lower().replace("-", " ").replace("_", " ")
    tokens = _tokens(candidate)
    for category, keywords in CATEGORY_KEYWORDS.items():
        for keyword in keywords:
            if (" " in keyword and keyword in candidate) or keyword in tokens:
                return category
    return None


def is_dangerous_url(url: str) -> bool:
    parsed = urlsplit(url)
    candidate = f"{parsed.path} {parsed.query}".lower()
    tokens = _tokens(candidate)
    if tokens & DANGEROUS_TERMS:
        return True
    return any(key.lower() in {"action", "do", "cmd"} for key, _ in parse_qsl(parsed.query))


def _site_host(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def is_same_site(url: str, homepage: str) -> bool:
    return _site_host(url) == _site_host(homepage)


def is_html_candidate(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return not any(path.endswith(extension) for extension in ASSET_EXTENSIONS)


def is_suspicious_destination(url: str) -> bool:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if host in PLACEHOLDER_HOSTS or host.endswith(".example.com"):
        return True
    labels_and_path = _tokens(f"{host} {parsed.path}")
    return bool(labels_and_path & TEST_TERMS)


def discover_page(html: str, source_url: str) -> tuple[list[RevenueTarget], list[tuple[str, str]]]:
    parser = PageParser()
    parser.feed(html)
    targets: list[RevenueTarget] = []
    crawl_links: list[tuple[str, str]] = []
    seen_targets: set[str] = set()

    def add_target(category: str, control: str, raw_url: str, kind: str) -> None:
        if category == "contact" and is_valid_mailto(raw_url):
            return
        if kind in {"form", "button"} and _invalid_action_reason(raw_url) == "placeholder form action":
            targets.append(RevenueTarget(
                category, control, raw_url, source_url, kind, "placeholder form action",
            ))
            return
        url = resolve_url(source_url, raw_url)
        if url is None:
            reason = _invalid_action_reason(raw_url) if kind in {"form", "button"} else "invalid action URL"
            targets.append(RevenueTarget(category, control, raw_url, source_url, kind, reason))
        elif url not in seen_targets and not is_dangerous_url(url):
            seen_targets.add(url)
            targets.append(RevenueTarget(category, control, url, source_url, kind))

    for href, control in parser.anchors:
        url = resolve_url(source_url, href)
        if url is not None and not is_dangerous_url(url):
            crawl_links.append((url, control))
        category = classify_target(control, href)
        if category:
            add_target(category, control, href, "anchor")

    for src, control in parser.iframes:
        category = classify_target(control, src)
        if category:
            add_target(category, control, src, "iframe")

    for button in parser.buttons:
        attrs = button["attrs"]
        control = button["control"]
        action = attrs.get("formaction", "")  # type: ignore[union-attr]
        category = classify_target(control, action)
        if action and category:
            add_target(category, control, action, "button")

    for form in parser.forms:
        attrs = form["attrs"]
        form_text = _metadata(attrs, " ".join(form["text"]))  # type: ignore[arg-type]
        action = attrs.get("action", "")  # type: ignore[union-attr]
        buttons = form["buttons"]
        category = classify_target(form_text, action)
        for button in buttons:  # type: ignore[union-attr]
            button_attrs = button["attrs"]
            button_control = button["control"]
            button_action = button_attrs.get("formaction", "")
            button_category = classify_target(button_control, button_action, form_text)
            category = category or button_category
        if category:
            if action:
                add_target(category, form_text, action, "form")
            elif not any(button["attrs"].get("formaction") for button in buttons):  # type: ignore[union-attr]
                targets.append(RevenueTarget(category, form_text, "", source_url, "form", "missing form action"))

    return targets, crawl_links


def _fetch(raw_url: str, timeout: float, body_limit: int = MAX_PAGE_BYTES) -> FetchResult:
    started = time.monotonic()
    try:
        tested_url = normalize_url(raw_url)
    except (ValueError, UnicodeError) as exc:
        return FetchResult(raw_url, outcome="invalid_url", detail=str(exc))
    redirects = TrackingRedirectHandler()
    opener = build_opener(redirects)
    try:
        request = Request(tested_url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        })
        with opener.open(request, timeout=timeout) as response:
            raw_body = response.read(body_limit)
            charset = response.headers.get_content_charset() or "utf-8"
            body = raw_body.decode(charset, errors="replace")
            status = response.getcode()
            return FetchResult(
                tested_url=tested_url,
                final_url=response.geturl(),
                status_code=status,
                outcome="redirect" if redirects.redirect_count else "ok",
                detail=(f"Redirected {redirects.redirect_count} time(s)" if redirects.redirect_count else "HTTP request succeeded"),
                redirects=redirects.redirect_count,
                elapsed_ms=round((time.monotonic() - started) * 1000),
                content_type=response.headers.get_content_type(),
                body=body,
            )
    except HTTPError as exc:
        detail = f"Server returned HTTP {exc.code}: {exc.reason}"
        outcome = "redirect_error" if exc.code in {301, 302, 303, 307, 308} else "http_error"
        return FetchResult(
            tested_url, exc.geturl() or "", exc.code, outcome, detail,
            redirects.redirect_count, round((time.monotonic() - started) * 1000),
        )
    except URLError as exc:
        reason = exc.reason
        if isinstance(reason, (ssl.SSLError, ssl.CertificateError)):
            outcome, detail = "ssl_error", f"SSL verification failed: {reason}"
        elif isinstance(reason, (socket.timeout, TimeoutError)):
            outcome, detail = "timeout", f"Request exceeded {timeout:g} seconds"
        else:
            outcome, detail = "unreachable", f"Unable to reach site: {reason}"
        return FetchResult(
            tested_url, outcome=outcome, detail=detail,
            redirects=redirects.redirect_count,
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )
    except (socket.timeout, TimeoutError):
        return FetchResult(
            tested_url, outcome="timeout", detail=f"Request exceeded {timeout:g} seconds",
            redirects=redirects.redirect_count,
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )
    except (ValueError, UnicodeError) as exc:
        return FetchResult(
            tested_url, outcome="invalid_url", detail=f"Invalid URL: {exc}",
            redirects=redirects.redirect_count,
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )


def _fetch_confirming_timeout(
    raw_url: str,
    timeout: float,
    body_limit: int = MAX_PAGE_BYTES,
) -> FetchResult:
    first = _fetch(raw_url, timeout, body_limit)
    first_attempt = (
        f"attempt 1: timeout={timeout:g}s, outcome={first.outcome}, "
        f"elapsed={first.elapsed_ms}ms"
    )
    if first.outcome != "timeout":
        first.attempts = (first_attempt,)
        return first

    retry_timeout = max(10.0, timeout * 2)
    second = _fetch(raw_url, retry_timeout, body_limit)
    second_attempt = (
        f"attempt 2: timeout={retry_timeout:g}s, outcome={second.outcome}, "
        f"elapsed={second.elapsed_ms}ms"
    )
    second.attempts = (first_attempt, second_attempt)
    second.elapsed_ms += first.elapsed_ms
    if second.outcome == "timeout":
        second.detail = f"Timed out twice ({first.detail}; {second.detail})"
    return second


def _verification(result: FetchResult, prefix: str) -> str:
    attempts = "; ".join(result.attempts)
    return f"{prefix}; {attempts}" if attempts else prefix


def severity_for(category: str, finding_type: str) -> str:
    if finding_type == "suspicious_destination":
        return "medium"
    if category in {"donation", "ticket"}:
        return "critical"
    return "high"


def _finding_from_result(
    organization: str,
    homepage: str,
    target: RevenueTarget,
    result: FetchResult,
) -> Finding | None:
    finding_type = ""
    if result.outcome in {"http_error"} and isinstance(result.status_code, int) and result.status_code >= 400:
        finding_type = "broken_revenue_target"
    elif result.outcome in {"timeout", "unreachable", "ssl_error"}:
        finding_type = f"revenue_target_{result.outcome}"
    elif result.outcome == "redirect_error" or result.redirects > MAX_REDIRECTS:
        finding_type = "redirect_loop_or_excessive"
    elif is_suspicious_destination(result.final_url or result.tested_url):
        finding_type = "suspicious_destination"
    elif result.final_url and not is_same_site(result.final_url, result.tested_url):
        body = result.body.lower()
        if any(phrase in body for phrase in PARKING_PHRASES):
            finding_type = "unrelated_or_parked_destination"
    if not finding_type:
        return None
    return Finding(
        organization, homepage, finding_type, target.category,
        severity_for(target.category, finding_type), target.source_page,
        target.control, result.tested_url, result.final_url, result.status_code,
        result.detail, _verification(result, f"GET without form submission; redirects={result.redirects}"),
        result.elapsed_ms,
    )


def _homepage_finding(organization: str, homepage: str, result: FetchResult) -> Finding | None:
    if result.outcome not in {"invalid_url", "http_error", "timeout", "unreachable", "ssl_error", "redirect_error"}:
        return None
    if result.outcome == "ssl_error":
        finding_type = "ssl_certificate_failure"
    elif result.outcome == "redirect_error":
        finding_type = "redirect_loop_or_excessive"
    elif result.outcome == "http_error" and isinstance(result.status_code, int) and result.status_code >= 500:
        finding_type = "homepage_server_error"
    else:
        finding_type = "homepage_unreachable"
    return Finding(
        organization, homepage, finding_type, "homepage", "high", homepage,
        "Homepage", result.tested_url, result.final_url, result.status_code,
        result.detail, _verification(result, f"GET; redirects={result.redirects}"), result.elapsed_ms,
    )


def scan_organization(
    organization: str,
    raw_homepage: str,
    timeout: float,
    max_pages: int,
) -> tuple[list[Finding], ScanSummary]:
    if max_pages < 1:
        raise ValueError("max_pages must be at least 1")
    try:
        homepage = normalize_url(raw_homepage)
    except ValueError:
        homepage = raw_homepage
    findings: list[Finding] = []
    homepage_result = _fetch_confirming_timeout(raw_homepage, timeout)
    pages_scanned = 1
    homepage_finding = _homepage_finding(organization, homepage, homepage_result)
    if homepage_finding:
        findings.append(homepage_finding)
        return findings, _summary(organization, homepage, pages_scanned, 0, findings, "homepage_failed")

    canonical_homepage = homepage_result.final_url or homepage_result.tested_url
    fetch_cache = {normalize_url(homepage_result.tested_url): homepage_result}
    page_results: list[tuple[str, FetchResult]] = [(canonical_homepage, homepage_result)]
    _home_targets, home_links = discover_page(homepage_result.body, canonical_homepage)
    ranked_links: list[tuple[int, str]] = []
    seen_pages = {normalize_url(canonical_homepage)}
    for url, control in home_links:
        if not is_same_site(url, canonical_homepage) or not is_html_candidate(url):
            continue
        normalized = normalize_url(url)
        if normalized in seen_pages:
            continue
        seen_pages.add(normalized)
        ranked_links.append((0 if classify_target(control, url) else 1, normalized))
    ranked_links.sort(key=lambda item: item[0])
    for _priority, url in ranked_links[: max_pages - 1]:
        result = _fetch_confirming_timeout(url, timeout)
        fetch_cache[url] = result
        pages_scanned += 1
        if result.outcome in {"ok", "redirect"} and result.content_type in {"text/html", "application/xhtml+xml"}:
            page_results.append((result.final_url or result.tested_url, result))

    targets: list[RevenueTarget] = []
    seen_target_urls: set[str] = set()
    invalid_keys: set[tuple[str, str, str]] = set()
    for source_page, page_result in page_results:
        page_targets, _links = discover_page(page_result.body, source_page)
        for target in page_targets:
            if target.invalid_reason:
                key = (target.source_page, target.control, target.invalid_reason)
                if key not in invalid_keys:
                    invalid_keys.add(key)
                    targets.append(target)
            elif target.url not in seen_target_urls:
                seen_target_urls.add(target.url)
                targets.append(target)

    checked = 0
    for target in targets:
        if target.invalid_reason:
            findings.append(Finding(
                organization, homepage, "revenue_form_action_invalid", target.category,
                severity_for(target.category, "revenue_form_action_invalid"),
                target.source_page, target.control, target.url, "", "",
                target.invalid_reason, "Static form inspection; form not submitted", 0,
            ))
            continue
        checked += 1
        result = fetch_cache.get(target.url)
        if result is None:
            result = _fetch_confirming_timeout(target.url, timeout, MAX_VERIFICATION_BYTES)
            fetch_cache[target.url] = result
        finding = _finding_from_result(organization, homepage, target, result)
        if finding:
            findings.append(finding)

    outcome = "findings" if findings else "ok"
    return findings, _summary(organization, homepage, pages_scanned, checked, findings, outcome)


def _summary(
    organization: str,
    homepage: str,
    pages_scanned: int,
    checked: int,
    findings: list[Finding],
    outcome: str,
) -> ScanSummary:
    return ScanSummary(
        organization, homepage, pages_scanned, checked, len(findings),
        sum(item.severity == "critical" for item in findings),
        sum(item.severity == "high" for item in findings), outcome,
    )


def read_organizations(path: Path) -> list[tuple[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not {"organization", "url"}.issubset(set(reader.fieldnames or [])):
            raise ValueError("Input CSV must contain organization and url columns")
        return [
            ((row.get("organization") or "").strip(), (row.get("url") or "").strip())
            for row in reader
            if (row.get("organization") or "").strip() or (row.get("url") or "").strip()
        ]


def _write_csv(rows: list[object], path: Path, row_type: type) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = list(row_type.__dataclass_fields__)
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _read_rows(path: Path, row_type: type) -> list[object]:
    if not path.exists():
        return []
    integer_fields = {
        name for name, field in row_type.__dataclass_fields__.items()
        if field.type in {int, "int"} or name in {"status_code", "elapsed_ms"}
    }
    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            values = {}
            for name in row_type.__dataclass_fields__:
                value = row.get(name, "")
                if name in integer_fields and value != "":
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                values[name] = value
            rows.append(row_type(**values))
    return rows


def _deduplicate(rows: list[object]) -> list[object]:
    unique = []
    seen = set()
    for row in rows:
        key = tuple(asdict(row).values())
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return unique


def _deduplicate_summaries(rows: list[ScanSummary]) -> list[ScanSummary]:
    unique = []
    seen = set()
    for row in rows:
        if row.organization not in seen:
            seen.add(row.organization)
            unique.append(row)
    return unique


def scan_csv(
    input_path: Path,
    output_dir: Path,
    timeout: float = 15.0,
    max_pages: int = 5,
    resume: bool = False,
) -> tuple[list[Finding], list[ScanSummary]]:
    findings = _deduplicate(_read_rows(output_dir / "findings.csv", Finding)) if resume else []
    summaries = _deduplicate_summaries(_read_rows(output_dir / "scan-summary.csv", ScanSummary)) if resume else []
    completed = {summary.organization for summary in summaries}
    organizations = read_organizations(input_path)
    for index, (organization, homepage) in enumerate(organizations, start=1):
        if organization in completed:
            continue
        organization_findings, summary = scan_organization(
            organization, homepage, timeout, max_pages,
        )
        findings = _deduplicate([*findings, *organization_findings])
        summaries.append(summary)
        completed.add(organization)
        _write_csv(findings, output_dir / "findings.csv", Finding)
        _write_csv(summaries, output_dir / "scan-summary.csv", ScanSummary)
        print(
            f"[{index}/{len(organizations)}] {organization} - "
            f"{summary.pages_scanned} pages, {summary.revenue_targets_checked} targets, "
            f"{summary.actionable_findings} findings"
        )
    if not organizations:
        _write_csv(findings, output_dir / "findings.csv", Finding)
        _write_csv(summaries, output_dir / "scan-summary.csv", ScanSummary)
    return findings, summaries
