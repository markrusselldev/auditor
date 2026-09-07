"""Coarse, in-memory geo/network lookup for analytics. The IP is read once here and never stored.

Uses MaxMind GeoLite2 (Country + ASN) when the .mmdb files and the maxminddb reader are present, and
degrades to "unknown" otherwise so the tool runs the same with or without them. We derive only a
country code and a rough network type; the raw IP never leaves this call.

network_type is a HEURISTIC, not real VPN detection: an IP whose network operator looks like a
hosting/cloud provider is flagged "hosting", which usually means a VPN, proxy, or bot and that the
country is unreliable for it. Free data cannot tell a consumer VPN on a residential IP from a real
home connection, so treat "residential" as "probably a real location", never a guarantee.
"""

from __future__ import annotations

import os

# Substrings that mark an ASN org as a hosting/cloud/VPN network (location unreliable). Matched
# lowercased against the autonomous-system org name. Not exhaustive; covers the common providers.
_HOSTING_MARKERS = (
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "ovh", "hetzner", "linode",
    "akamai", "cloudflare", "fastly", "vultr", "choopa", "contabo", "leaseweb", "oracle", "scaleway",
    "hosting", "datacenter", "data center", "colocation", "colo", "vpn", "m247", "datacamp", "nforce",
)

_country_reader = None
_asn_reader = None
_loaded = False


def _load() -> None:
    """Open the MaxMind readers once from the configured paths. Any failure leaves them None."""
    global _country_reader, _asn_reader, _loaded
    if _loaded:
        return
    _loaded = True
    try:
        import maxminddb  # optional dependency; absence just means no geo enrichment
    except Exception:
        return
    for env, attr in (("AUDITOR_GEOIP_COUNTRY_DB", "_country_reader"),
                      ("AUDITOR_GEOIP_ASN_DB", "_asn_reader")):
        path = os.environ.get(env, "")
        if not path or not os.path.exists(path):
            continue
        try:
            globals()[attr] = maxminddb.open_database(path)
        except Exception:
            globals()[attr] = None


def _classify(org: str | None) -> str:
    if not org:
        return "unknown"
    low = org.lower()
    return "hosting" if any(marker in low for marker in _HOSTING_MARKERS) else "residential"


def lookup(ip: str | None, *, country_reader=None, asn_reader=None) -> dict:
    """Return {country, network_type, asn_org} for an IP. The IP is used here and never stored.

    Readers can be injected for testing; otherwise they are loaded from AUDITOR_GEOIP_COUNTRY_DB /
    AUDITOR_GEOIP_ASN_DB if present. Any lookup failure yields the unknown shape, never an exception.
    """
    result = {"country": None, "network_type": "unknown", "asn_org": None}
    if not ip:
        return result
    if country_reader is None and asn_reader is None:
        _load()
        country_reader, asn_reader = _country_reader, _asn_reader
    try:
        if country_reader is not None:
            rec = country_reader.get(ip) or {}
            result["country"] = (rec.get("country") or {}).get("iso_code")
    except Exception:
        pass
    try:
        if asn_reader is not None:
            rec = asn_reader.get(ip) or {}
            org = rec.get("autonomous_system_organization")
            result["asn_org"] = org
            result["network_type"] = _classify(org)
    except Exception:
        pass
    return result
