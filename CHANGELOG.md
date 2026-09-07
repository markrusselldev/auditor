# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-09-07

First tracked release. Scans a website for real, externally visible failures and
ranks them by how strongly each is verified.

### Added
- Static crawler and a deeper second-pass crawl that detect externally visible
  failures: broken images and assets, dead links, SSL/certificate errors, and
  mobile layout breakage (viewport overflow, unusable navigation).
- Browser verifier (Playwright) that re-checks findings in a real render, and a
  desktop/phone render pass that flags mobile-only breakage.
- Revenue-path form verification: for a site the operator owns (consent-gated), it
  fills and submits the contact or donation form to confirm the submit path fires
  and reaches a live endpoint. It never delivers real data and never triggers the
  site's own analytics.
- AI-visibility checks: `llms.txt`, `schema.org` markup, robots access for AI
  crawlers, and one live "what AI says about this site" read with a guard against
  hallucinated claims.
- Accessibility check using a vendored copy of axe-core.
- Findings carry a confidence tier (high/medium/low) from verification strength,
  a separate revenue-relevance tag, a rolled-up grade, and one ranked CSV.
- Web service with a one-page front end (live at audit.markrussell.io).
- `--version` flag, reporting the single-sourced package version.

### Security
- SSRF egress guard on every request and redirect hop, a result cache, a global
  daily scan cap, and a per-registrable-domain cap on the consent-gated deep test.
- Container runs as a non-root user.
- Optional scan analytics that never store an IP address (off by default).

[Unreleased]: https://github.com/markrusselldev/auditor/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/markrusselldev/auditor/releases/tag/v0.9.0
