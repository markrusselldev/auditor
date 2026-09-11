# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] - 2026-09-11

Dogfooding the pipeline on real cohorts surfaced a scan-scope bug and several
false-positive classes; this release fixes them and unifies the batch and web paths
onto one pipeline behind a single `scan` command.

### Changed
- The `scan` batch command now runs the **full audit pipeline** - the same `scan_url` the web tool
  runs - over every site in a CSV, so a batch and the live site exercise identical code. Each site
  runs in its own subprocess with a hard `--per-site-timeout`, and `--workers` sites run in parallel
  (the Playwright sync API is not thread-safe, so scans are isolated by process, not thread). It
  replaces the previous static-crawler behavior of `scan`.
- `scan` is now the only command on the `auditor` CLI. The older `audit-v2` command is archived in
  `auditor.legacy_cli` (not deleted, just off the main CLI; run via `python -m auditor.legacy_cli
  audit-v2`). The deep-revenue path's browser verification, previously reached by spawning the
  `browser-verify` command, now uses a dedicated internal worker (`auditor.browser_verify_worker`)
  that calls the verifier directly - an internal process, not a user command.

### Fixed
- Reachability checks now stay on the audited site. When a donation, ticketing, or
  contact link leads to an external platform, the scan confirms the link resolves and
  stops there instead of following it into the third-party site. This keeps scans fast
  and focused on the site being audited, and prevents an external platform's own page
  content from being read as a finding.
- Reachability now honors a per-site time budget, so a site with a large first-party
  ticketing or events section can no longer run away with the whole scan; the check
  stops once the budget is spent and reports on the controls it verified. Configurable
  via `AUDITOR_REACHABILITY_BUDGET_SECONDS` (default 60; 0 disables the limit).
- A contact or signup form that submits to a hosted third-party endpoint (Mailchimp,
  PayPal, and similar) is no longer reported as broken. Those endpoints answer a
  health-check GET with a 404 while still accepting real submissions, so only a dead
  endpoint on the site's own domain is flagged now.
- Embedded third-party content (video, donation or ticketing widgets) and third-party
  images are no longer reported as broken when they fail only under the automated
  render; those platforms often block or lazy-load for an automated visit while serving
  real visitors normally. A genuine failure of the site's own assets is still caught.
- A page that loads and then immediately redirects is no longer misreported as
  unreachable; only a page whose navigation genuinely fails is flagged.
- A finding names a control by a short label instead of quoting a whole sentence of
  link text when an entire sentence is wrapped in a link.
- A live donation page is no longer flagged solely because its page copy contains the
  word "demo"; the test/sandbox check now requires an explicit environment indicator
  (for example, "test mode" or "sandbox mode").
- The www vs non-www check now runs only on a real registered domain. A site served from
  a subdomain - a department page, or a store hosted on a platform like Square or Shopify -
  is no longer flagged for a missing "www" address that no visitor types and the owner
  cannot set up.
- A form is reported as unsubmittable only when it has two or more text fields and no way
  to send it. A single search box (which submits on Enter), a filter dropdown (which acts
  on selection), and a form whose submit control is a styled link or role=button (as page
  builders like Divi and Elementor use) are no longer misreported as broken.
- A search or other GET form is checked at the address it actually submits to, carrying its
  own fields, rather than the bare action URL. A search endpoint that answers a bare request
  with a 404 but works with a query is no longer flagged.
- Mobile navigation is judged usable when the site's links are visible and tappable, even
  when they are not wrapped in a nav landmark (a full-width stacked menu with no hamburger).
  It is flagged only when the primary destinations are genuinely unreachable on a phone.
- A broken-image finding now says whether it is a content image (the broken-image icon a
  visitor sees) or a background image (a missing texture), and marks a third-party asset as
  such instead of blaming the phone breakpoint for it.
- A page that fails to load during the crawl is re-checked before being reported. A login
  page that loops a cookie-less crawler (a Shopify customer-account page redirects to
  Shopify's own login), a rate-limited response, and a momentary connection blip are no
  longer reported as broken pages; a genuinely dead page still is.
- A booking, donation, or contact link whose destination fails to load during the scan is
  re-checked before it is called a broken revenue path, so a momentary DNS or connection
  blip is not reported as a dead link.
- Mobile horizontal-scroll (reflow) is now flagged only when a visible, on-screen element
  genuinely extends past the phone viewport, measured after the page settles. Off-screen or
  hidden menus, elements clipped by an ancestor, a layout that is briefly wide only during
  load, and the Google reCAPTCHA badge no longer count as overflow.

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

[Unreleased]: https://github.com/markrusselldev/auditor/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/markrusselldev/auditor/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/markrusselldev/auditor/releases/tag/v0.9.0
