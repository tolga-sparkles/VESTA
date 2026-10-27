"""Bounded, cached enrichment from CISA KEV and NVD CVE API 2.0."""

from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone

import httpx

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
KEV_TTL = 12 * 3600
NVD_TTL = 24 * 3600
MAX_NVD_PER_REFRESH = 5

_kev_cache: dict[str, dict] = {}
_kev_cached_at = 0.0
_nvd_cache: dict[str, tuple[float, dict | None]] = {}
_nvd_calls: list[float] = []
_lock = asyncio.Lock()


def cve_ids(text: str) -> list[str]:
    return list(dict.fromkeys(match.upper() for match in CVE_PATTERN.findall(text)))


def _iso(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


async def get_kev(client: httpx.AsyncClient) -> tuple[dict[str, dict], bool]:
    """Return catalog entries and whether the current value came from a successful fetch."""
    global _kev_cache, _kev_cached_at
    if _kev_cached_at and time.monotonic() - _kev_cached_at < KEV_TTL:
        return _kev_cache, True
    async with _lock:
        if _kev_cached_at and time.monotonic() - _kev_cached_at < KEV_TTL:
            return _kev_cache, True
        try:
            response = await client.get(KEV_URL, timeout=5.0)
            response.raise_for_status()
            if len(response.content) > 4_000_000:
                raise ValueError("KEV yanıtı çok büyük.")
            payload = response.json()
            rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
            if not isinstance(rows, list):
                raise ValueError("KEV yanıtı geçersiz.")
            catalog = {
                row["cveID"].upper(): row
                for row in rows
                if isinstance(row, dict) and isinstance(row.get("cveID"), str)
                and CVE_PATTERN.fullmatch(row["cveID"])
            }
        except (httpx.HTTPError, ValueError, TypeError):
            return _kev_cache, False
        _kev_cache = catalog
        _kev_cached_at = time.monotonic()
        return catalog, True


def _parse_nvd(payload: object, cve_id: str) -> dict | None:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        return None
    for wrapper in payload["vulnerabilities"]:
        cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
        if not isinstance(cve, dict) or cve.get("id", "").upper() != cve_id:
            continue
        metrics = cve.get("metrics") or {}
        cvss = None
        for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
            entries = metrics.get(key) if isinstance(metrics, dict) else None
            if isinstance(entries, list) and entries:
                primary = next((row for row in entries if isinstance(row, dict) and row.get("type") == "Primary"), entries[0])
                data = primary.get("cvssData") if isinstance(primary, dict) else None
                score = data.get("baseScore") if isinstance(data, dict) else None
                if isinstance(score, (int, float)):
                    cvss = {"score": score, "version": version}
                    break
        products: list[str] = []
        for configuration in cve.get("configurations") or []:
            for node in configuration.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    criteria = match.get("criteria") if isinstance(match, dict) else None
                    if isinstance(criteria, str):
                        parts = criteria.split(":")
                        if len(parts) > 4:
                            name = f"{parts[3]} {parts[4]}".replace("_", " ")
                            if name not in products:
                                products.append(name)
                    if len(products) >= 8:
                        break
                if len(products) >= 8:
                    break
            if len(products) >= 8:
                break
        return {
            "published_at": _iso(cve.get("published")),
            "updated_at": _iso(cve.get("lastModified")),
            "cvss": cvss,
            "products": products,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
    return None


async def get_nvd(client: httpx.AsyncClient, ids: list[str]) -> dict[str, dict | None]:
    """Fetch at most five uncached records per refresh and five per rolling 30 seconds."""
    now = time.monotonic()
    result: dict[str, dict | None] = {}
    to_fetch: list[str] = []
    async with _lock:
        _nvd_calls[:] = [stamp for stamp in _nvd_calls if now - stamp < 30]
        budget = min(MAX_NVD_PER_REFRESH, max(0, 5 - len(_nvd_calls)))
        for cve_id in ids:
            cached = _nvd_cache.get(cve_id)
            if cached and now - cached[0] < NVD_TTL:
                result[cve_id] = cached[1]
            elif len(to_fetch) < budget:
                to_fetch.append(cve_id)
        _nvd_calls.extend([now] * len(to_fetch))

    async def fetch_one(cve_id: str) -> tuple[str, dict | None, bool]:
        try:
            response = await client.get(NVD_URL, params={"cveId": cve_id}, timeout=5.0)
            response.raise_for_status()
            if len(response.content) > 1_000_000:
                raise ValueError("NVD yanıtı çok büyük.")
            return cve_id, _parse_nvd(response.json(), cve_id), True
        except (httpx.HTTPError, ValueError, TypeError, AttributeError):
            return cve_id, None, False

    for cve_id, data, succeeded in await asyncio.gather(*(fetch_one(cve_id) for cve_id in to_fetch)):
        if succeeded:
            _nvd_cache[cve_id] = (time.monotonic(), data)
        result[cve_id] = data
    return result


async def enrich(client: httpx.AsyncClient, items: list[dict]) -> tuple[dict[str, dict], dict[str, dict | None], dict]:
    ids = list(dict.fromkeys(cve_id for item in items for cve_id in cve_ids(f"{item['title']} {item['summary']}")))
    if not ids:
        return {}, {}, {"kev_available": False, "kev_stale": False, "nvd_enriched": 0}
    kev_task = asyncio.create_task(get_kev(client))
    nvd = await get_nvd(client, ids)
    kev, fresh = await kev_task
    return kev, nvd, {"kev_available": fresh or bool(kev), "kev_stale": not fresh and bool(kev), "nvd_enriched": sum(value is not None for value in nvd.values())}
