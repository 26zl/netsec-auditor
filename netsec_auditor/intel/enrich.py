"""External threat-intel enrichment — EPSS scores, CISA KEV membership, and
passive Shodan InternetDB lookups, with local caching and CVE prioritization.

Every network call is wrapped so failures return empty/neutral results instead
of raising. The ``parse_*`` and ``prioritize`` helpers are pure and network-free
so they can be unit-tested with crafted payloads.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx

from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)

# Cache root shared with the rest of the toolkit.
CACHE_ROOT = Path.home() / ".netsec-auditor"
# Neutral UA: public feeds (CISA KEV) WAF-block scanner-flavoured User-Agents.
USER_AGENT = "netsec-auditor/1.0"
DEFAULT_TIMEOUT = 30.0


def _to_float(value: Any) -> float:
    """Coerce an API value (often a numeric string) to float, defaulting to 0.0."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def parse_epss(payload: dict[str, Any]) -> dict[str, dict[str, float]]:
    """Extract per-CVE EPSS score and percentile from a FIRST.org response.

    Accepts the ``{"data": [{"cve": ..., "epss": ..., "percentile": ...}]}`` shape
    and returns ``{cve: {"epss": float, "percentile": float}}``.
    """
    scores: dict[str, dict[str, float]] = {}
    for row in payload.get("data", []):
        cve = row.get("cve")
        if not cve:
            continue
        scores[cve] = {
            "epss": _to_float(row.get("epss")),
            "percentile": _to_float(row.get("percentile")),
        }
    return scores


def parse_kev(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map ``cveID`` to its entry from a CISA KEV catalog payload."""
    entries: dict[str, dict[str, Any]] = {}
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cveID")
        if cve:
            entries[cve] = item
    return entries


def parse_internetdb(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Shodan InternetDB response to fixed list-valued keys.

    An empty payload (e.g. a 404 "no data") yields an empty dict.
    """
    if not payload:
        return {}
    keys = ("ports", "cpes", "hostnames", "tags", "vulns")
    return {key: list(payload.get(key) or []) for key in keys}


def prioritize(cve_id: str, cvss: float, epss: float, in_kev: bool) -> dict[str, Any]:
    """Assign a remediation priority label; ``epss`` is the EPSS percentile (0..1).

    Rule: KEV membership -> "critical" (fix now); else percentile >= 0.9 or
    cvss >= 9 -> "high"; else cvss >= 7 -> "medium"; else "low".
    """
    if in_kev:
        priority = "critical"  # known-exploited: fix now
    elif epss >= 0.9 or cvss >= 9:
        priority = "high"
    elif cvss >= 7:
        priority = "medium"
    else:
        priority = "low"
    return {
        "cve_id": cve_id,
        "cvss": cvss,
        "epss": epss,
        "in_kev": in_kev,
        "priority": priority,
    }


class EpssClient:
    """Keyless client for FIRST.org EPSS exploit-probability scores."""

    API_URL = "https://api.first.org/data/v1/epss"
    BATCH_SIZE = 100  # FIRST.org accepts comma-joined CVEs; keep batches modest.

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._client = httpx.AsyncClient(
            timeout=timeout, headers={"User-Agent": USER_AGENT}
        )

    async def scores(self, cve_ids: list[str]) -> dict[str, dict[str, float]]:
        """Fetch EPSS scores for the given CVEs, batching to stay within limits."""
        results: dict[str, dict[str, float]] = {}
        for start in range(0, len(cve_ids), self.BATCH_SIZE):
            batch = cve_ids[start:start + self.BATCH_SIZE]
            payload = await self._request(batch)
            if payload:
                results.update(parse_epss(payload))
        return results

    async def _request(self, cve_ids: list[str]) -> dict[str, Any] | None:
        """GET one EPSS batch; returns None on any network/parse failure."""
        try:
            resp = await self._client.get(self.API_URL, params={"cve": ",".join(cve_ids)})
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return data
        except (httpx.HTTPError, ValueError) as e:
            logger.debug("epss_request_failed", error=str(e))
            return None

    async def close(self) -> None:
        await self._client.aclose()


class KevCatalog:
    """CISA Known Exploited Vulnerabilities catalog with a 24h local cache."""

    FEED_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    CACHE_NAME = "known_exploited_vulnerabilities.json"
    MAX_AGE_SECONDS = 24 * 60 * 60

    def __init__(
        self, cache_dir: Path | None = None, timeout: float = DEFAULT_TIMEOUT
    ) -> None:
        self.cache_dir = cache_dir or CACHE_ROOT
        self.cache_file = self.cache_dir / self.CACHE_NAME
        self._entries: dict[str, dict[str, Any]] = {}
        self._client = httpx.AsyncClient(
            timeout=timeout, headers={"User-Agent": USER_AGENT}
        )

    async def load(self, force: bool = False) -> None:
        """Populate the in-memory KEV map, refreshing the cache when stale.

        Call this before ``contains``/``entry``. Never raises: on download
        failure it falls back to any cached copy (even if stale).
        """
        payload: dict[str, Any] | None = None
        if not force and self._cache_fresh():
            payload = self._read_cache()
        if payload is None:
            payload = await self._download()
            if payload is not None:
                self._write_cache(payload)
        if payload is None:
            payload = self._read_cache()  # last resort: a stale cache
        self._entries = parse_kev(payload or {})

    def contains(self, cve_id: str) -> bool:
        """True if the CVE is in the loaded KEV catalog (case-insensitive)."""
        return cve_id.upper() in self._entries

    def entry(self, cve_id: str) -> dict[str, Any] | None:
        """Return the KEV entry for a CVE, or None if absent."""
        return self._entries.get(cve_id.upper())

    def _cache_fresh(self) -> bool:
        """True when a cached feed exists and is younger than MAX_AGE_SECONDS."""
        try:
            age = time.time() - self.cache_file.stat().st_mtime
        except OSError:
            return False
        return age < self.MAX_AGE_SECONDS

    def _read_cache(self) -> dict[str, Any] | None:
        try:
            with self.cache_file.open(encoding="utf-8") as fh:
                data: dict[str, Any] = json.load(fh)
                return data
        except (OSError, json.JSONDecodeError):
            return None

    def _write_cache(self, payload: dict[str, Any]) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            with self.cache_file.open("w", encoding="utf-8") as fh:
                json.dump(payload, fh)
        except OSError as e:
            logger.debug("kev_cache_write_failed", error=str(e))

    async def _download(self) -> dict[str, Any] | None:
        try:
            resp = await self._client.get(self.FEED_URL)
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return data
        except (httpx.HTTPError, ValueError) as e:
            logger.debug("kev_download_failed", error=str(e))
            return None

    async def close(self) -> None:
        await self._client.aclose()


class InternetDbClient:
    """Keyless, passive Shodan InternetDB client (queries Shodan, not the target)."""

    BASE_URL = "https://internetdb.shodan.io"

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._client = httpx.AsyncClient(
            timeout=timeout, headers={"User-Agent": USER_AGENT}
        )

    async def lookup(self, ip: str) -> dict[str, Any]:
        """Look up passive exposure data for an IP; empty dict means no data."""
        try:
            resp = await self._client.get(f"{self.BASE_URL}/{ip}")
            if resp.status_code == 404:
                return {}  # InternetDB has no record for this IP
            resp.raise_for_status()
            return parse_internetdb(resp.json())
        except (httpx.HTTPError, ValueError) as e:
            logger.debug("internetdb_lookup_failed", ip=ip, error=str(e))
            return {}

    async def close(self) -> None:
        await self._client.aclose()


async def enrich_cves(
    cve_ids: list[str],
    cvss_by_cve: dict[str, float],
    epss_client: EpssClient,
    kev_catalog: KevCatalog,
) -> dict[str, dict[str, Any]]:
    """Combine EPSS, CISA KEV, and priority for each CVE (never raises)."""
    epss_scores = await epss_client.scores(cve_ids)
    await kev_catalog.load()
    enriched: dict[str, dict[str, Any]] = {}
    for cve in cve_ids:
        metrics = epss_scores.get(cve, {})
        percentile = metrics.get("percentile", 0.0)
        cvss = cvss_by_cve.get(cve, 0.0)
        in_kev = kev_catalog.contains(cve)
        priority = prioritize(cve, cvss, percentile, in_kev)["priority"]
        enriched[cve] = {
            "cve_id": cve,
            "cvss": cvss,
            "epss": metrics.get("epss", 0.0),
            "percentile": percentile,
            "in_kev": in_kev,
            "kev_entry": kev_catalog.entry(cve),
            "priority": priority,
        }
    return enriched
