# badsite - a deliberately broken fixture for end-to-end testing

A tiny two-page site that trips as many detectors as a plain-HTTP local server can, so you can scan
it with the tool and see how every finding renders in the report. It is served by a static file
server, so any missing path (`/gone-forever.html`, `/donate-broken.html`, `/contact-submit`,
`/does-not-exist.png`) returns a real 404.

## What it triggers

- **Page basics**: no title on the homepage, no meta description or canonical on either page, no h1.
- **Images & assets**: two broken images, both missing alt text.
- **Links & reachability**: a dead internal link (Catalog -> 404).
- **Revenue paths**: a Donate control that 404s, and a contact form posting to a dead endpoint.
- **Mobile experience**: a fixed 520px block (wider than a phone, not desktop) forces mobile-only horizontal overflow.
- **Accessibility** (axe-core): low-contrast text, form inputs with no label, images with no alt.

## What it CANNOT trip on plain HTTP

Mixed content (needs an https page), www-vs-non-www redirect (needs two hosts), SPF/DMARC (needs
DNS), and SSL errors (needs a bad cert). Verify those against real sites.

## Run the full local test

Serve the badsite, then run the auditor with the SSRF escape hatch on (it refuses localhost by
default) and the caps off, and scan it:

```bash
# 1. Serve the broken site on :9000
python3 -m http.server 9000 --directory tests/fixtures/badsite

# 2. In another shell, run the auditor allowing local targets, and scan the badsite
AUDITOR_ALLOW_PRIVATE_HOSTS=1 AUDITOR_DISABLE_LIMITS=1 PYTHONPATH=src python3 -m auditor.web
# then open http://localhost:8080 and scan  http://localhost:9000
```
