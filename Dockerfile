# Auditor web service for Cloud Run (or any container host).
# Chromium needs ~2GB RAM: deploy with at least --memory 2Gi.
FROM python:3.11-slim

# Chromium cannot use its own sandbox inside a container without extra privileges, so it fails to
# launch and every browser check (mobile, vitals, accessibility, screenshot, form-submit) silently
# no-ops. Disable it here so the image works out of the box. Cloud Run gen2 (gVisor) provides the
# isolation instead, and the app-side SSRF guard governs egress - this is NOT a weakening of the
# abuse/SSRF controls (unlike AUDITOR_DISABLE_LIMITS / AUDITOR_ALLOW_PRIVATE_HOSTS, which are dev-only).
ENV AUDITOR_CHROMIUM_SANDBOX=0 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Install the package with its deployed-only extras (analytics/geo; see pyproject [deploy]), then the
# Chromium browser + its system libraries. The extras are always installed so analytics can be turned
# on at deploy with env vars alone; they add little and the code no-ops without the env/config.
COPY pyproject.toml README.md ./
COPY src ./src
# GeoLite2 files (optional coarse geo, auditor.geo) are added at the geo-enablement step, not here:
# they are MaxMind-licensed and gitignored, so `gcloud run deploy --source` never uploads them into
# the build context. Create the dir so the path exists; the app degrades to "unknown" without files.
RUN mkdir -p geoip
RUN pip install --upgrade pip \
    && pip install '.[deploy]' \
    && playwright install --with-deps chromium

# Defense in depth for a container that renders untrusted pages: run as a non-root user. The build
# steps above need root (apt system libs via --with-deps); switch only now, and hand /app plus the
# shared Playwright browser cache (PLAYWRIGHT_BROWSERS_PATH) to that user so Chromium still launches.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app /ms-playwright
USER appuser

EXPOSE 8080

# The service reads PORT (Cloud Run sets it). Per-IP rate limiting is in-memory, so pin the
# service to a single instance (min=max=1) at deploy for the limiter to hold; the provider's
# hard monthly spend cap is the financial backstop. OPENAI_API_KEY is injected at deploy, never
# baked into the image.
CMD ["python", "-m", "auditor.web"]
