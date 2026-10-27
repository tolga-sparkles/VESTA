"""VESTA's fixed, read-only news and official notice sources."""

from __future__ import annotations

import asyncio
import hashlib
import html
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

import httpx


@dataclass(frozen=True)
class FeedSource:
    id: str
    name: str
    category: str
    url: str


FEEDS = (
    FeedSource("siberguvenlikhaber", "Siber Güvenlik Haber", "news", "https://siberguvenlikhaber.com/rss.xml"),
    FeedSource("trsiber", "TRSiber", "news", "https://www.trsiber.net/rss.xml"),
    FeedSource("siberkapan-cve", "SiberKapan CVE", "cve", "https://siberkapan.org/rss/cve"),
    FeedSource("siberkapan-ioc", "SiberKapan IOC", "ioc", "https://siberkapan.org/rss/ioc"),
)

OFFICIAL_LINKS = (
    {"name": "Siber Güvenlik Başkanlığı", "description": "Güvenlik bildirimleri", "url": "https://siberguvenlik.gov.tr/guvenlik-bildirimleri"},
    {"name": "KVKK", "description": "Veri ihlali bildirimleri", "url": "https://www.kvkk.gov.tr/veri-ihlali-bildirimi"},
)

SGB_INCIDENTS = FeedSource(
    "sgb-bildirim", "Siber Güvenlik Başkanlığı", "official",
    "https://siberguvenlik.gov.tr/api/incident/index?language=tr&page=1",
)
KVKK_BREACHES = FeedSource(
    "kvkk-ihlaller", "KVKK", "privacy",
    "https://www.kvkk.gov.tr/veri-ihlali-bildirimi",
)

TURKISH_MONTHS = {
    "Ocak": 1, "Şubat": 2, "Mart": 3, "Nisan": 4, "Mayıs": 5, "Haziran": 6,
    "Temmuz": 7, "Ağustos": 8, "Eylül": 9, "Ekim": 10, "Kasım": 11, "Aralık": 12,
}

CACHE_SECONDS = 600
MAX_FEED_BYTES = 1_000_000
ITEMS_PER_SOURCE = 15
_cache: dict | None = None
_cached_at = 0.0
_refresh_lock = asyncio.Lock()
_last_success: dict[str, str] = {}
_last_item_date: dict[str, str | None] = {}


def _failure(status: dict, error: Exception) -> tuple[list[dict], dict]:
    if isinstance(error, httpx.HTTPStatusError):
        status["http_status"] = error.response.status_code
        status["error_kind"] = "http"
    elif isinstance(error, httpx.TimeoutException):
        status["error_kind"] = "timeout"
    elif isinstance(error, httpx.HTTPError):
        status["error_kind"] = "network"
    else:
        status["error_kind"] = "parse"
    return [], status


def _source_health(feeds: list[tuple[list[dict], dict]], cache_age: int) -> list[dict]:
    checked_at = datetime.now(timezone.utc).isoformat()
    statuses = []
    for articles, raw_status in feeds:
        status = dict(raw_status)
        source_id = status["id"]
        if status["status"] == "ok":
            _last_success[source_id] = checked_at
            latest = max((article.get("published_at") or "" for article in articles), default="")
            if latest:
                _last_item_date[source_id] = latest
        status["checked_at"] = checked_at
        status["last_success_at"] = _last_success.get(source_id)
        status["latest_item_published_at"] = _last_item_date.get(source_id)
        status["cache_age_seconds"] = cache_age
        status["expected_frequency"] = "daily" if status["category"] == "news" else "irregular" if status["category"] in {"cve", "ioc"} else None
        status.setdefault("http_status", 200 if status["status"] == "ok" else None)
        status.setdefault("error_kind", None)
        if status["status"] != "ok":
            status["health_state"] = "parse_error" if status["error_kind"] == "parse" else "unreachable"
        elif status["category"] != "news":
            status["health_state"] = "working"
        else:
            latest_date = _last_item_date.get(source_id)
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(latest_date)).total_seconds() if latest_date else None
            status["health_state"] = "stale" if age is not None and age > 7 * 86400 else "delayed" if age is not None and age > 2 * 86400 else "working"
        statuses.append(status)
    return statuses


def _cache_view(payload: dict, age: int) -> dict:
    return {**payload, "sources": [{**source, "cache_age_seconds": age} for source in payload["sources"]]}


def _plain_text(value: str | None, limit: int) -> str:
    text = html.unescape(re.sub(r"<[^>]*>", " ", value or ""))
    return " ".join(text.split())[:limit]


def _safe_url(value: str | None) -> str | None:
    if not value or len(value) > 1_000:
        return None
    url = value.strip()
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return None
    return url


def _published_at(value: str | None) -> str | None:
    if not value:
        return None
    try:
        date = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return date.astimezone(timezone.utc).isoformat()


def parse_feed(content: bytes, source: FeedSource) -> list[dict]:
    if len(content) > MAX_FEED_BYTES or b"<!DOCTYPE" in content.upper():
        raise ValueError("RSS yanıtı geçersiz.")
    root = ET.fromstring(content)
    if root.tag != "rss":
        raise ValueError("RSS biçimi tanınmadı.")
    articles: list[dict] = []
    for item in root.findall("./channel/item"):
        title = _plain_text(item.findtext("title"), 240)
        link = _safe_url(item.findtext("link"))
        if not title or not link:
            continue
        guid = item.findtext("guid") or link
        articles.append({
            "id": hashlib.sha256(f"{source.id}:{guid}".encode()).hexdigest()[:20],
            "source_id": source.id,
            "source": source.name,
            "category": source.category,
            "title": title,
            "summary": _plain_text(item.findtext("description"), 320),
            "url": link,
            "published_at": _published_at(item.findtext("pubDate")),
        })
        if len(articles) >= ITEMS_PER_SOURCE:
            break
    return articles


def parse_sgb_incidents(payload: object) -> list[dict]:
    if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
        raise ValueError("Bildirim yanıtı geçersiz.")
    articles: list[dict] = []
    for incident in payload["models"][:ITEMS_PER_SOURCE]:
        if not isinstance(incident, dict) or incident.get("active") is False:
            continue
        slug = incident.get("slug")
        if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9-]{1,120}", slug):
            continue
        raw_title = incident.get("title")
        if not isinstance(raw_title, str):
            continue
        title = _plain_text(raw_title, 240)
        if not title:
            continue
        published_at = None
        raw_date = incident.get("date")
        if isinstance(raw_date, str):
            try:
                published = datetime.fromisoformat(raw_date.replace(" ", "T"))
                if published.tzinfo is None:
                    published = published.replace(tzinfo=timezone.utc)
                published_at = published.astimezone(timezone.utc).isoformat()
            except ValueError:
                pass
        raw_summary = incident.get("desc")
        articles.append({
            "id": hashlib.sha256(f"{SGB_INCIDENTS.id}:{slug}".encode()).hexdigest()[:20],
            "source_id": SGB_INCIDENTS.id,
            "source": SGB_INCIDENTS.name,
            "category": SGB_INCIDENTS.category,
            "title": title,
            "summary": _plain_text(raw_summary if isinstance(raw_summary, str) else None, 320),
            "url": f"https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/{slug}",
            "published_at": published_at,
        })
    return articles


def parse_kvkk_listing(content: bytes) -> list[dict]:
    text = content.decode("utf-8", errors="replace")
    entries: list[dict] = []
    pattern = re.compile(
        r'<div\s+class="news__box-meta"[^>]*>\s*<a\s+href="([^"]+)"[^>]*>(.*?)</a>\s*'
        r'<p\s+class="date"[^>]*>(.*?)</p>', re.IGNORECASE | re.DOTALL,
    )
    for link, raw_title, raw_date in pattern.findall(text):
        title = _plain_text(raw_title, 240)
        url = _safe_url(html.unescape(link))
        if not title or not url:
            continue
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != "www.kvkk.gov.tr" or not re.fullmatch(
            r"/Icerik/\d+/[a-z0-9-]+", parsed.path, re.IGNORECASE
        ):
            continue
        date_match = re.search(r"(\d{1,2})\s+(\w+)\s+(\d{4})", _plain_text(raw_date, 80))
        published_at = None
        if date_match and date_match.group(2) in TURKISH_MONTHS:
            try:
                published_at = datetime(
                    int(date_match.group(3)), TURKISH_MONTHS[date_match.group(2)],
                    int(date_match.group(1)), tzinfo=timezone.utc,
                ).isoformat()
            except ValueError:
                pass
        entries.append({
            "id": hashlib.sha256(f"{KVKK_BREACHES.id}:{parsed.path}".encode()).hexdigest()[:20],
            "source_id": KVKK_BREACHES.id,
            "source": KVKK_BREACHES.name,
            "category": KVKK_BREACHES.category,
            "title": title,
            "summary": "",
            "url": url,
            "published_at": published_at,
            "date_only": True,
        })
    return entries


def parse_kvkk_summary(content: bytes) -> str:
    text = content.decode("utf-8", errors="replace")
    article = re.search(r'<div\s+class="news__detail-article[^\"]*"[^>]*>', text, re.IGNORECASE)
    if not article:
        return ""
    points = [
        _plain_text(point, 320)
        for point in re.findall(r"<li\b[^>]*>(.*?)</li>", text[article.end():], re.IGNORECASE | re.DOTALL)
    ]
    for point in points:
        if "etkilenen kişisel veri" in point.casefold():
            return point
    return points[0] if points else ""


async def _fetch_kvkk_breaches(client: httpx.AsyncClient) -> tuple[list[dict], dict]:
    source = KVKK_BREACHES
    status = {"id": source.id, "name": source.name, "category": source.category,
              "url": source.url, "status": "error", "count": 0}
    try:
        entries: list[dict] = []
        for page in (1, 2):
            response = await client.get(source.url, params={"page": page}, headers={"Accept": "text/html"})
            response.raise_for_status()
            if len(response.content) > MAX_FEED_BYTES:
                raise ValueError("KVKK yanıtı çok büyük.")
            page_entries = parse_kvkk_listing(response.content)
            if not page_entries:
                raise ValueError("KVKK kayıtları bulunamadı.")
            entries.extend(page_entries)
            if len(entries) >= ITEMS_PER_SOURCE:
                break
        entries = entries[:ITEMS_PER_SOURCE]
    except (httpx.HTTPError, ValueError, TypeError) as error:
        return _failure(status, error)

    semaphore = asyncio.Semaphore(4)

    async def add_summary(item: dict) -> dict:
        async with semaphore:
            try:
                response = await client.get(item["url"], headers={"Accept": "text/html"})
                response.raise_for_status()
                if len(response.content) <= MAX_FEED_BYTES:
                    item["summary"] = parse_kvkk_summary(response.content)
            except httpx.HTTPError:
                pass
        return item

    # The overview only shows three KVKK notices. Fetch their details now so the
    # entire news response does not wait for fifteen separate detail pages.
    await asyncio.gather(*(add_summary(item) for item in entries[:3]))
    articles = entries
    status["status"] = "ok"
    status["count"] = len(articles)
    return articles, status


async def _fetch_sgb_incidents(client: httpx.AsyncClient) -> tuple[list[dict], dict]:
    source = SGB_INCIDENTS
    status = {"id": source.id, "name": source.name, "category": source.category,
              "url": source.url, "status": "error", "count": 0}
    try:
        async with client.stream("GET", source.url, headers={"Accept": "application/json", "User-Agent": "VestaRSS/1.0"}) as response:
            response.raise_for_status()
            content = bytearray()
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content) > MAX_FEED_BYTES:
                    raise ValueError("Bildirim yanıtı çok büyük.")
        articles = parse_sgb_incidents(httpx.Response(200, content=bytes(content)).json())
    except (httpx.HTTPError, ValueError, TypeError) as error:
        return _failure(status, error)
    status["status"] = "ok"
    status["count"] = len(articles)
    return articles, status


async def _fetch_feed(client: httpx.AsyncClient, source: FeedSource) -> tuple[list[dict], dict]:
    status = {"id": source.id, "name": source.name, "category": source.category, "url": source.url, "status": "error", "count": 0}
    try:
        async with client.stream("GET", source.url, headers={"Accept": "application/rss+xml, application/xml, text/xml", "User-Agent": "VestaRSS/1.0"}) as response:
            response.raise_for_status()
            content = bytearray()
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content) > MAX_FEED_BYTES:
                    raise ValueError("RSS yanıtı çok büyük.")
        articles = parse_feed(bytes(content), source)
    except (httpx.HTTPError, ET.ParseError, ValueError, TypeError) as error:
        return _failure(status, error)
    status["status"] = "ok"
    status["count"] = len(articles)
    return articles, status


async def get_news(client: httpx.AsyncClient, fresh: bool = False) -> dict:
    global _cache, _cached_at
    now = time.monotonic()
    if _cache is not None and not fresh and now - _cached_at < CACHE_SECONDS:
        return _cache_view(_cache, int(now - _cached_at))
    async with _refresh_lock:
        now = time.monotonic()
        if _cache is not None and not fresh and now - _cached_at < CACHE_SECONDS:
            return _cache_view(_cache, int(now - _cached_at))
        feeds = await asyncio.gather(
            *(_fetch_feed(client, source) for source in FEEDS),
            _fetch_sgb_incidents(client),
            _fetch_kvkk_breaches(client),
        )
        unique: dict[str, dict] = {}
        for articles, _ in feeds:
            for article in articles:
                key = article["id"]
                previous = unique.get(key)
                if previous is None or (article["published_at"] or "") > (previous["published_at"] or ""):
                    unique[key] = article
        items = sorted(unique.values(), key=lambda item: item["published_at"] or "", reverse=True)
        sources = _source_health(feeds, 0 if items else int(now - _cached_at) if _cache is not None else 0)
        if items:
            _cache = {
                "items": items,
                "sources": sources,
                "official_links": list(OFFICIAL_LINKS),
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "stale": False,
            }
            _cached_at = time.monotonic()
            return _cache
        if not items and _cache is not None:
            # Tüm akışlar boş/hatalı: önbellekteki son başarılı veriyi eski işaretiyle döndür.
            previous = dict(_cache)
            previous["sources"] = sources
            previous["stale"] = True
            return previous
        return {
            "items": items,
            "sources": sources,
            "official_links": list(OFFICIAL_LINKS),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "stale": False,
        }
