from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import time
from collections import deque
from contextlib import asynccontextmanager, closing
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
from argon2 import PasswordHasher
from fastapi import Cookie, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from news import get_news
from tweets import load_tweets
from cve_enrichment import enrich as enrich_cves
from threat_engine import evaluate as evaluate_news, rank_items


ROOT = Path(__file__).resolve().parent
DATA = ROOT / ".data"
WEB_DIST = ROOT / "web" / "dist"
TWITTER_MEDIA_DIR = ROOT.parent / "twitter_pipeline" / "manuel" / "media"
SOURCES = ("abuseipdb", "otx", "virustotal", "threatfox", "urlhaus", "sgb", "internetdb", "mxtoolbox")
SCORE_WEIGHTS = {
    "ipv4": {"abuseipdb": 35, "virustotal": 25, "otx": 10, "threatfox": 10, "urlhaus": 7, "sgb": 5, "internetdb": 8, "mxtoolbox": 5},
    "ipv6": {"abuseipdb": 45, "virustotal": 30, "otx": 15, "sgb": 10},
    "domain": {"virustotal": 45, "otx": 20, "threatfox": 15, "urlhaus": 10, "sgb": 10, "mxtoolbox": 5},
}
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
PASSWORD_HASHER = PasswordHasher()
FAILED_LOGINS: deque[float] = deque()


def load_settings() -> dict[str, str]:
    values = dict(os.environ)
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line and not line.startswith("#") and "=" in line:
                name, value = line.split("=", 1)
                values[name] = value
    return values


SETTINGS = load_settings()
COOKIE_SECURE = SETTINGS.get("APP_LOCAL_ONLY", "1") != "1"


def normalize_indicator(raw: str) -> tuple[str, str]:
    value = raw.strip().rstrip(".")
    if not value or len(value) > 253 or any(c.isspace() for c in value):
        raise ValueError("Geçerli bir IP adresi veya alan adı girin.")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        if any(x in value for x in ("://", "/", "@", "?", "#", ":")):
            raise ValueError("URL değil, yalnızca alan adı girin.") from None
        try:
            domain = value.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError("Alan adı geçerli değil.") from None
        if len(domain) > 253:
            raise ValueError("Alan adı çok uzun.")
        labels = domain.split(".")
        if len(labels) < 2 or not all(DOMAIN_LABEL.fullmatch(label) for label in labels):
            raise ValueError("Alan adı geçerli değil.")
        if labels[-1] in {"local", "internal", "localhost", "test", "invalid"}:
            raise ValueError("Yerel alan adları dış servislere gönderilemez.")
        return domain, "domain"
    if not ip.is_global:
        raise ValueError("Yalnızca genel IP adresleri sorgulanabilir.")
    return ip.compressed, "ipv4" if ip.version == 4 else "ipv6"


async def resolve_domain(domain: str) -> dict:
    """Use the first public A record, falling back to the first public AAAA record."""
    had_response = False
    timed_out = False
    first_address: str | None = None
    for family, version in ((socket.AF_INET, 4), (socket.AF_INET6, 6)):
        try:
            records = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(domain, None, family=family, type=socket.SOCK_STREAM),
                timeout=1.5,
            )
        except asyncio.TimeoutError:
            timed_out = True
            continue
        except (socket.gaierror, OSError):
            continue
        had_response = True
        for record in records:
            try:
                address = ipaddress.ip_address(record[4][0])
            except (ValueError, IndexError, TypeError):
                continue
            if address.version != version:
                continue
            if first_address is None:
                first_address = address.compressed
            if address.is_global:
                selected = address.compressed
                return {"status": "ok", "addresses": [selected], "selected": selected}
    status = "no_public_ip" if had_response else "timeout" if timed_out else "error"
    return {"status": status, "addresses": [first_address] if first_address else [], "selected": None}


def session_signature(created: int, nonce: str) -> str:
    secret = SETTINGS.get("SESSION_SECRET", "")
    message = f"{created}.{nonce}".encode()
    return hmac.new(secret.encode(), message, "sha256").hexdigest()


def valid_session(cookie: str | None) -> bool:
    if not cookie or not SETTINGS.get("SESSION_SECRET"):
        return False
    try:
        stamp, nonce, signature = cookie.split(".", 2)
        created = int(stamp)
    except (ValueError, AttributeError):
        return False
    if created > time.time() + 60 or time.time() - created > 8 * 3600:
        return False
    return hmac.compare_digest(signature, session_signature(created, nonce))


def same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and urlsplit(origin).netloc != request.headers.get("host"):
        raise HTTPException(403, "Kaynak doğrulaması başarısız.")


def require_login(cookie: str | None) -> None:
    if not valid_session(cookie):
        raise HTTPException(401, "Önce giriş yapın.")


def reserve_virustotal_quota() -> bool:
    DATA.mkdir(mode=0o700, exist_ok=True)
    db_path = DATA / "quota.sqlite3"
    db = sqlite3.connect(db_path, timeout=5)
    os.chmod(db_path, 0o600)
    try:
        db.execute("CREATE TABLE IF NOT EXISTS vt_requests (at REAL NOT NULL)")
        db.execute("BEGIN IMMEDIATE")
        now = time.time()
        db.execute("DELETE FROM vt_requests WHERE at <= ?", (now - 86400,))
        minute = db.execute("SELECT COUNT(*) FROM vt_requests WHERE at > ?", (now - 60,)).fetchone()[0]
        day = db.execute("SELECT COUNT(*) FROM vt_requests").fetchone()[0]
        if minute >= 4 or day >= 500:
            db.commit()
            return False
        db.execute("INSERT INTO vt_requests(at) VALUES (?)", (now,))
        db.commit()
    finally:
        db.close()
    return True


def record_usage(source: str) -> None:
    """Count local searches and outgoing requests without storing indicators."""
    DATA.mkdir(mode=0o700, exist_ok=True)
    db_path = DATA / "usage.sqlite3"
    with closing(sqlite3.connect(db_path, timeout=5)) as db, db:
        os.chmod(db_path, 0o600)
        db.execute("CREATE TABLE IF NOT EXISTS usage_events (source TEXT NOT NULL, at REAL NOT NULL)")
        now = time.time()
        db.execute("DELETE FROM usage_events WHERE at <= ?", (now - 86400,))
        db.execute("INSERT INTO usage_events(source, at) VALUES (?, ?)", (source, now))


def usage_snapshot() -> dict:
    now = time.time()
    counts = {source: 0 for source in (*SOURCES, "search")}
    usage_db = DATA / "usage.sqlite3"
    abuse_today = 0
    if usage_db.exists():
        with closing(sqlite3.connect(usage_db, timeout=5)) as db:
            db.execute("CREATE TABLE IF NOT EXISTS usage_events (source TEXT NOT NULL, at REAL NOT NULL)")
            rows = db.execute("SELECT source, COUNT(*) FROM usage_events WHERE at > ? GROUP BY source", (now - 86400,)).fetchall()
            counts.update({source: count for source, count in rows if source in counts})
            abuse_today = db.execute("SELECT COUNT(*) FROM usage_events WHERE source = 'abuseipdb' AND at >= ?", (int(now // 86400) * 86400,)).fetchone()[0]
    minute = day = 0
    quota_db = DATA / "quota.sqlite3"
    if quota_db.exists():
        with closing(sqlite3.connect(quota_db, timeout=5)) as db:
            db.execute("CREATE TABLE IF NOT EXISTS vt_requests (at REAL NOT NULL)")
            minute = db.execute("SELECT COUNT(*) FROM vt_requests WHERE at > ?", (now - 60,)).fetchone()[0]
            day = db.execute("SELECT COUNT(*) FROM vt_requests WHERE at > ?", (now - 86400,)).fetchone()[0]
    counts["virustotal"] = day
    return {"searches_24h": counts.pop("search"), "requests_24h": counts, "abuseipdb_today_utc": abuse_today,
            "virustotal_minute": minute, "virustotal_24h": day}


def result(source: str, status: str, summary: str, details: object | None = None, link: str | None = None) -> dict:
    return {"source": source, "status": status, "summary": summary, "details": details, "link": link}


async def request_json(client: httpx.AsyncClient, method: str, url: str, *, source: str, **kwargs: object) -> dict:
    if source != "virustotal":
        record_usage(source)
    response = await client.request(method, url, **kwargs)
    if response.status_code == 429:
        raise RateLimited()
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict):
        raise ValueError("Beklenmeyen servis yanıtı")
    return body


class RateLimited(Exception):
    pass


async def abuseipdb(client: httpx.AsyncClient, indicator: str, kind: str) -> dict:
    source = "abuseipdb"
    if kind == "domain":
        return result(source, "unsupported", "AbuseIPDB yalnızca IP adreslerini sorgular.")
    key = SETTINGS.get("ABUSEIPDB_API_KEY")
    if not key:
        return result(source, "error", "API anahtarı yapılandırılmamış.")
    body = await request_json(client, "GET", "https://api.abuseipdb.com/api/v2/check", source=source, params={"ipAddress": indicator, "maxAgeInDays": 90}, headers={"Key": key, "Accept": "application/json"})
    data = body.get("data", {})
    score = int(data.get("abuseConfidenceScore") or 0)
    reports = int(data.get("totalReports") or 0)
    details = {name: data.get(name) for name in ("abuseConfidenceScore", "totalReports", "numDistinctUsers", "lastReportedAt", "isWhitelisted", "countryCode", "countryName", "isp", "domain", "usageType", "isTor", "hostnames")}
    status = "match" if score > 0 and not data.get("isWhitelisted") else "no_match"
    return result(source, status, f"Kötüye kullanım puanı {score}/100 · {reports} rapor", details, f"https://www.abuseipdb.com/check/{quote(indicator)}")


async def otx(client: httpx.AsyncClient, indicator: str, kind: str) -> dict:
    source = "otx"
    key = SETTINGS.get("OTX_API_KEY")
    if not key:
        return result(source, "error", "API anahtarı yapılandırılmamış.")
    name = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain"}[kind]
    body = await request_json(client, "GET", f"https://otx.alienvault.com/api/v1/indicators/{name}/{quote(indicator, safe='')}/general", source=source, headers={"X-OTX-API-KEY": key})
    pulses = body.get("pulse_info") or {}
    count = int(pulses.get("count") or 0)
    items = pulses.get("pulses") or []
    details = {"pulse_count": count, "pulses": [{"name": p.get("name"), "created": p.get("created"), "id": p.get("id")} for p in items[:10]], "country_name": body.get("country_name"), "country_code": body.get("country_code"), "region": body.get("region"), "city": body.get("city"), "latitude": body.get("latitude"), "longitude": body.get("longitude"), "asn": body.get("asn")}
    return result(source, "match" if count else "no_match", f"{count} Pulse kaydı", details, f"https://otx.alienvault.com/indicator/{name}/{quote(indicator, safe='')}")


async def virustotal(client: httpx.AsyncClient, indicator: str, kind: str) -> dict:
    source = "virustotal"
    key = SETTINGS.get("VIRUSTOTAL_API_KEY")
    if not key:
        return result(source, "error", "API anahtarı yapılandırılmamış.")
    if not reserve_virustotal_quota():
        return result(source, "rate_limited", "Ücretsiz VirusTotal kotası doldu; daha sonra yeniden deneyin.")
    section = "domains" if kind == "domain" else "ip_addresses"
    body = await request_json(client, "GET", f"https://www.virustotal.com/api/v3/{section}/{quote(indicator, safe='')}", source=source, headers={"x-apikey": key})
    attrs = (body.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    details = {"analysis_stats": stats, "reputation": attrs.get("reputation"), "last_analysis_date": attrs.get("last_analysis_date"), "categories": attrs.get("categories"), "as_owner": attrs.get("as_owner"), "asn": attrs.get("asn"), "country": attrs.get("country"), "network": attrs.get("network"), "regional_internet_registry": attrs.get("regional_internet_registry")}
    return result(source, "match" if malicious or suspicious else "no_match", f"{malicious} zararlı · {suspicious} şüpheli tespit", details, f"https://www.virustotal.com/gui/{'domain' if kind == 'domain' else 'ip-address'}/{quote(indicator, safe='')}")


async def threatfox(client: httpx.AsyncClient, indicator: str, kind: str) -> dict:
    source = "threatfox"
    if kind == "ipv6":
        return result(source, "unsupported", "ThreatFox IPv6 adresi için doğrudan IOC araması sunmuyor.")
    key = SETTINGS.get("ABUSECH_AUTH_KEY")
    if not key:
        return result(source, "error", "Auth-Key yapılandırılmamış.")
    body = await request_json(client, "POST", "https://threatfox-api.abuse.ch/api/v1/", source=source, headers={"Auth-Key": key}, json={"query": "search_ioc", "search_term": indicator, "exact_match": kind == "domain"})
    raw = body.get("data") if isinstance(body.get("data"), list) else []
    matches = []
    for entry in raw:
        ioc = str(entry.get("ioc") or "")
        host = ioc.rsplit(":", 1)[0] if kind == "ipv4" and ":" in ioc else ioc
        if host.lower().rstrip(".") == indicator.lower():
            matches.append({"ioc": ioc, "threat_type": entry.get("threat_type"), "malware": entry.get("malware"), "confidence_level": entry.get("confidence_level"), "first_seen": entry.get("first_seen_utc"), "last_seen": entry.get("last_seen_utc")})
    return result(source, "match" if matches else "no_match", f"{len(matches)} eşleşen IOC", matches[:20], "https://threatfox.abuse.ch/")


async def urlhaus(client: httpx.AsyncClient, indicator: str, kind: str) -> dict:
    source = "urlhaus"
    if kind == "ipv6":
        return result(source, "unsupported", "URLhaus host sorgusu IPv6 desteklemiyor.")
    key = SETTINGS.get("ABUSECH_AUTH_KEY")
    if not key:
        return result(source, "error", "Auth-Key yapılandırılmamış.")
    body = await request_json(client, "POST", "https://urlhaus-api.abuse.ch/v1/host/", source=source, headers={"Auth-Key": key}, data={"host": indicator})
    if body.get("query_status") not in ("ok", "no_results"):
        raise ValueError("URLhaus beklenmeyen sorgu durumu döndürdü")
    count = int(body.get("url_count") or 0)
    urls = body.get("urls") if isinstance(body.get("urls"), list) else []
    details = {"firstseen": body.get("firstseen"), "url_count": count, "blacklists": body.get("blacklists"), "urls": [{"url": item.get("url"), "url_status": item.get("url_status"), "date_added": item.get("date_added")} for item in urls[:20]]}
    return result(source, "match" if count else "no_match", f"{count} zararlı URL kaydı", details, f"https://urlhaus.abuse.ch/host/{quote(indicator, safe='')}/")


async def sgb(client: httpx.AsyncClient, indicator: str, kind: str) -> dict:
    source = "sgb"
    api_type = {"ipv4": "ip", "ipv6": "ip6", "domain": "domain"}[kind]
    matches = []
    total = 0
    for page in range(1, 4):
        body = await request_json(client, "GET", "https://siberguvenlik.gov.tr/api/address/index", source=source, params={"type": api_type, "q": indicator, "page": page, "per-page": 100})
        models = body.get("models") if isinstance(body.get("models"), list) else []
        total = int(body.get("totalCount") or 0)
        for entry in models:
            if str(entry.get("url") or "").lower().rstrip(".") == indicator.lower():
                matches.append({name: entry.get(name) for name in ("url", "type", "desc", "source", "date", "criticality_level", "connectiontype")})
        if page * 100 >= total:
            break
    if total > 300 and not matches:
        return result(source, "error", "Arama çok fazla kayıt döndürdü; kesin eşleşme doğrulanamadı.")
    return result(source, "match" if matches else "no_match", f"{len(matches)} kesin eşleşme", matches[:20], "https://siberguvenlik.gov.tr/zararli-baglantilar")


async def internetdb(client: httpx.AsyncClient, indicator: str, kind: str) -> dict:
    source = "internetdb"
    if kind != "ipv4":
        return result(source, "unsupported", "InternetDB bu panelde yalnızca IPv4 için sorgulanır.")
    body = await request_json(client, "GET", f"https://internetdb.shodan.io/{indicator}", source=source, timeout=3.0)
    ports = sorted({port for port in body.get("ports", []) if type(port) is int and 0 < port <= 65535})
    vulns = [v for v in body.get("vulns", []) if isinstance(v, str)]
    details = {"ports": ports, "vulns": vulns, "cpes": body.get("cpes") or [], "hostnames": body.get("hostnames") or [], "tags": body.get("tags") or []}
    return result(source, "match" if ports or vulns else "no_match", f"{len(ports)} açık port · {len(vulns)} olası zafiyet", details, f"https://internetdb.shodan.io/{indicator}")


async def mxtoolbox(client: httpx.AsyncClient, indicator: str, kind: str) -> dict:
    source = "mxtoolbox"
    if kind == "ipv6":
        return result(source, "unsupported", "MXToolbox bu panelde IPv6 için sorgulanmıyor.")
    key = SETTINGS.get("MXTOOLBOX_API_KEY")
    if not key:
        return result(source, "error", "API anahtarı yapılandırılmamış.")
    command = "mx" if kind == "domain" else "blacklist"
    url = f"https://api.mxtoolbox.com/api/v1/Lookup/{command}/{quote(indicator, safe='')}"
    try:
        body = await request_json(client, "GET", url, source=source, headers={"Authorization": key})
    except RateLimited:
        if kind == "domain":
            raise
        command = "ptr"
        body = await request_json(client, "GET", f"https://api.mxtoolbox.com/api/v1/Lookup/ptr/{quote(indicator, safe='')}", source=source, headers={"Authorization": key})
    if body.get("IsError"):
        raise ValueError("MXToolbox sorgusu tamamlanamadı")
    failed = [item for item in (body.get("Failed") or []) if isinstance(item, dict)]
    warnings = [item for item in (body.get("Warnings") or []) if isinstance(item, dict)]
    passed = [item for item in (body.get("Passed") or []) if isinstance(item, dict)]
    info = [item for item in (body.get("Information") or []) if isinstance(item, dict)]
    details = {"command": command,
               "records": [{"type": item.get("Type"), "hostname": item.get("Hostname"), "preference": item.get("Pref"), "ip": item.get("IP Address"), "ttl": item.get("TTL")} for item in info],
               "checks_passed": [item.get("Name") for item in passed],
               "warnings": [{"name": item.get("Name"), "info": item.get("Info")} for item in warnings],
               "failed": [{"name": item.get("Name"), "info": item.get("Info")} for item in failed]}
    link = f"https://mxtoolbox.com/SuperTool.aspx?action={command}%3a{quote(indicator, safe='')}"
    if failed or warnings:
        return result(source, "match", f"{len(failed)} sorun · {len(warnings)} uyarı · {len(passed)} kontrol geçti", details, link)
    return result(source, "no_match", f"DNS kaydı yayında · {len(passed)} kontrol geçti", details, link)


ADAPTERS = {"abuseipdb": abuseipdb, "otx": otx, "virustotal": virustotal, "threatfox": threatfox, "urlhaus": urlhaus, "sgb": sgb, "internetdb": internetdb, "mxtoolbox": mxtoolbox}


def score_snapshot(kind: str, results: dict[str, dict]) -> dict:
    weights = SCORE_WEIGHTS[kind]
    breakdown = []
    evaluated = 0
    total = 0
    for source, weight in weights.items():
        item = results.get(source)
        if not item or item["status"] not in ("match", "no_match"):
            breakdown.append({"source": source, "points": None, "max": weight})
            continue
        evaluated += 1
        details = item.get("details") or {}
        points = 0
        if source == "abuseipdb":
            points = round(weight * max(0, min(100, int(details.get("abuseConfidenceScore") or 0))) / 100)
        elif source == "virustotal":
            stats = details.get("analysis_stats") or {}
            points = min(weight, int(stats.get("malicious") or 0) * 4 + int(stats.get("suspicious") or 0) * 2)
        elif source == "otx":
            points = min(weight, int(details.get("pulse_count") or 0) * 2)
        elif source == "internetdb":
            points = min(weight, len(details.get("vulns") or []) * 4)
        elif source == "urlhaus":
            points = weight if int(details.get("url_count") or 0) > 0 else 0
        elif item["status"] == "match":
            points = weight
        points = max(0, points)
        total += points
        breakdown.append({"source": source, "points": points, "max": weight})
    return {"value": min(100, total) if evaluated else None, "evaluated": evaluated, "applicable": len(weights), "provisional": evaluated < len(weights), "breakdown": breakdown}


async def run_source(client: httpx.AsyncClient, source: str, indicator: str, kind: str) -> dict:
    started = time.monotonic()
    try:
        item = await ADAPTERS[source](client, indicator, kind)
    except RateLimited:
        item = result(source, "rate_limited", "Servis hız sınırına ulaştı; daha sonra yeniden deneyin.")
    except httpx.HTTPStatusError as error:
        if error.response.status_code == 404:
            item = result(source, "no_match", "Kayıt bulunamadı.", {"ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": []} if source == "internetdb" else None)
        elif error.response.status_code in (401, 403):
            item = result(source, "error", "Servis anahtarı reddetti.")
        else:
            item = result(source, "error", f"Servis HTTP {error.response.status_code} yanıtı verdi.")
    except httpx.TimeoutException:
        item = result(source, "error", "Servise erişim zaman aşımına uğradı.")
    except httpx.ConnectError:
        summary = "InternetDB'ye bu ağdan bağlantı kurulamadı." if source == "internetdb" else "Servise bağlantı kurulamadı."
        item = result(source, "error", summary)
    except httpx.NetworkError:
        item = result(source, "error", "Servis bağlantısı kesildi.")
    except (ValueError, TypeError, KeyError, httpx.HTTPError, sqlite3.Error):
        item = result(source, "error", "Servis yanıtı işlenemedi.")
    except Exception:
        item = result(source, "error", "Servis sorgusu tamamlanamadı.")
    item["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return item


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = httpx.AsyncClient(timeout=httpx.Timeout(9.0), follow_redirects=False)
    app.state.news_client = httpx.AsyncClient(timeout=httpx.Timeout(15.0), follow_redirects=True)
    yield
    await app.state.client.aclose()
    await app.state.news_client.aclose()


app = FastAPI(title="Vesta", docs_url=None, redoc_url=None, lifespan=lifespan)


class LoginInput(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class SearchInput(BaseModel):
    indicator: str = Field(min_length=1, max_length=253)


@app.get("/")
async def index() -> FileResponse:
    dist_index = WEB_DIST / "index.html"
    if not dist_index.exists():
        raise HTTPException(503, "Frontend derlenmemiş. web/ klasöründe 'npm run build' çalıştırın.")
    return FileResponse(dist_index, headers={"Cache-Control": "no-cache"})


@app.get("/api/session")
async def session(session: str | None = Cookie(default=None)) -> dict:
    return {"authenticated": valid_session(session)}


@app.get("/api/usage")
async def usage(session: str | None = Cookie(default=None)) -> dict:
    require_login(session)
    return usage_snapshot()


@app.get("/api/news")
async def news(
    request: Request, response: Response, session: str | None = Cookie(default=None),
    fresh: bool = False, q: str = Query(default="", max_length=120),
    category: str = "", source: str = "", content_type: str = "",
    priority: str = "", verification: str = "", region: str = "",
    active_exploitation: bool | None = None, from_date: str = "", to_date: str = "",
    sort: str = "recommended", page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=100),
) -> dict:
    require_login(session)
    response.headers["Cache-Control"] = "private, no-store"
    payload = dict(await get_news(request.app.state.news_client, fresh=fresh))
    tweets = load_tweets()
    kev, nvd, enrichment_status = await enrich_cves(request.app.state.news_client, payload["items"])
    intelligence = evaluate_news(payload["items"], tweets["tweets"], kev, nvd, kev_available=enrichment_status["kev_available"])
    items = intelligence["items"]
    needle = q.casefold().strip()
    if needle:
        items = [item for item in items if needle in " ".join((
            item["title"], item["summary"], item["source"],
            " ".join(item["evaluation"]["indicators"]["cves"] + item["evaluation"]["indicators"]["ips"] + item["evaluation"]["indicators"]["domains"]),
            " ".join(item["cve_data"]["products"]) if item["cve_data"] else "",
        )).casefold()]
    if category:
        items = [item for item in items if item["category"] == category]
    if source:
        items = [item for item in items if item["source_id"] == source]
    if content_type:
        items = [item for item in items if item["evaluation"]["content_type"] == content_type]
    if priority:
        items = [item for item in items if item["evaluation"]["priority"] == priority]
    if verification:
        items = [item for item in items if item["evaluation"]["verification"] == verification]
    if region:
        items = [item for item in items if item["evaluation"]["region"] == region]
    if active_exploitation is not None:
        items = [item for item in items if item["evaluation"]["active_exploitation"] == active_exploitation]
    if from_date:
        items = [item for item in items if (item["dates"]["published_at"] or "")[:10] >= from_date]
    if to_date:
        items = [item for item in items if (item["dates"]["published_at"] or "")[:10] <= to_date]
    items = rank_items(items, sort)
    total = len(items)
    visible = items[(page - 1) * page_size:page * page_size]
    visible_ids = {item["id"] for item in visible}
    payload["items"] = visible
    payload["events"] = [event for event in intelligence["events"] if any(item_id in visible_ids for item_id in event["item_ids"])]
    payload["cve_radar"] = {key: [item_id for item_id in ids if item_id in visible_ids] for key, ids in intelligence["cve_radar"].items()}
    social = intelligence["tweets"]
    if needle:
        social = [tweet for tweet in social if needle in str(tweet.get("text") or "").casefold() or needle in str(tweet.get("username") or "").casefold()]
    if category or source or (content_type and content_type != "social_claim") or region or active_exploitation is True:
        social = []
    if priority:
        social = [tweet for tweet in social if tweet["evaluation"]["priority"] == priority]
    if verification:
        social = [tweet for tweet in social if tweet["evaluation"]["verification"] == verification]
    if from_date:
        social = [tweet for tweet in social if (tweet.get("created_at") or "")[:10] >= from_date]
    if to_date:
        social = [tweet for tweet in social if (tweet.get("created_at") or "")[:10] <= to_date]
    payload["tweets"] = {**tweets, "tweets": social}
    payload["enrichment"] = enrichment_status
    payload["pagination"] = {"page": page, "page_size": page_size, "total": total}
    return payload


@app.get("/api/tweets/media/{account}/{filename}")
async def tweet_media(account: str, filename: str, session: str | None = Cookie(default=None)) -> FileResponse:
    require_login(session)
    if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", account):
        raise HTTPException(404, "Medya bulunamadı.")
    if not re.fullmatch(r"[0-9]+_\d+\.(jpg|jpeg|png|gif|webp|mp4)\Z", filename):
        raise HTTPException(404, "Medya bulunamadı.")
    media_root = TWITTER_MEDIA_DIR
    path = (media_root / account / filename).resolve()
    if not str(path).startswith(str(media_root.resolve()) + "/") or not path.is_file():
        raise HTTPException(404, "Medya bulunamadı.")
    return FileResponse(path, headers={"Cache-Control": "private, max-age=86400"})


@app.get("/api/map-tiles/{z}/{x}/{y}.png")
async def map_tile(z: int, x: int, y: int, request: Request, session: str | None = Cookie(default=None)) -> Response:
    require_login(session)
    if z < 0 or z > 20 or x < 0 or y < 0 or x >= 2 ** z or y >= 2 ** z:
        raise HTTPException(404, "Harita karosu bulunamadı.")
    key = SETTINGS.get("CARTO_BASEMAP_API_KEY")
    if not key:
        raise HTTPException(503, "Harita anahtarı yapılandırılmamış.")
    try:
        upstream = await request.app.state.client.get(
            f"https://basemaps.cartocdn.com/rastertiles/dark_all/{z}/{x}/{y}.png",
            params={"key": key},
        )
        upstream.raise_for_status()
    except httpx.HTTPError:
        raise HTTPException(502, "Harita karosu yüklenemedi.") from None
    if not upstream.headers.get("content-type", "").startswith("image/png") or len(upstream.content) > 1_000_000:
        raise HTTPException(502, "Harita karosu geçersiz.")
    return Response(
        content=upstream.content,
        media_type="image/png",
        headers={"Cache-Control": "private, max-age=86400", "X-Content-Type-Options": "nosniff"},
    )


@app.post("/api/login")
async def login(body: LoginInput, request: Request, response: Response) -> dict:
    same_origin(request)
    now = time.time()
    while FAILED_LOGINS and FAILED_LOGINS[0] < now - 900:
        FAILED_LOGINS.popleft()
    if len(FAILED_LOGINS) >= 10:
        raise HTTPException(429, "Çok fazla başarısız giriş. 15 dakika sonra deneyin.")
    stored_hash = SETTINGS.get("APP_PASSWORD_HASH", "")
    try:
        valid = PASSWORD_HASHER.verify(stored_hash, body.password)
    except Exception:
        valid = False
    if not valid:
        FAILED_LOGINS.append(now)
        raise HTTPException(401, "Parola yanlış.")
    FAILED_LOGINS.clear()
    created = int(time.time())
    nonce = secrets.token_hex(16)
    response.set_cookie("session", f"{created}.{nonce}.{session_signature(created, nonce)}", max_age=8 * 3600, secure=COOKIE_SECURE, httponly=True, samesite="strict", path="/")
    return {"authenticated": True}


@app.post("/api/logout")
async def logout(request: Request, response: Response) -> dict:
    same_origin(request)
    response.delete_cookie("session", path="/", secure=COOKIE_SECURE, httponly=True, samesite="strict")
    return {"authenticated": False}


@app.post("/api/search")
async def search(body: SearchInput, request: Request, session: str | None = Cookie(default=None)) -> StreamingResponse:
    require_login(session)
    same_origin(request)
    try:
        indicator, kind = normalize_indicator(body.indicator)
    except ValueError as error:
        raise HTTPException(422, str(error)) from None
    record_usage("search")

    async def stream():
        yield json.dumps({"event": "start", "indicator": indicator, "kind": kind, "sources": SOURCES}, ensure_ascii=False) + "\n"
        tasks: dict[asyncio.Task, tuple[str, str, str] | None] = {}
        if kind == "domain":
            tasks[asyncio.create_task(resolve_domain(indicator))] = None
        for source in SOURCES:
            tasks[asyncio.create_task(run_source(request.app.state.client, source, indicator, kind))] = (source, indicator, kind)
        completed: dict[str, dict[str, dict]] = {indicator: {}}
        try:
            while tasks:
                finished, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in finished:
                    subject = tasks.pop(task)
                    if subject is None:
                        dns = task.result()
                        yield json.dumps({"event": "dns", **dns}, ensure_ascii=False) + "\n"
                        selected = dns["selected"]
                        if selected:
                            ip_kind = "ipv4" if ipaddress.ip_address(selected).version == 4 else "ipv6"
                            completed[selected] = {}
                            for source in SOURCES:
                                tasks[asyncio.create_task(run_source(request.app.state.client, source, selected, ip_kind))] = (source, selected, ip_kind)
                        continue
                    _, subject_indicator, subject_kind = subject
                    item = task.result()
                    completed[subject_indicator][item["source"]] = item
                    yield json.dumps({"event": "result", "indicator": subject_indicator, "kind": subject_kind, **item}, ensure_ascii=False) + "\n"
                    yield json.dumps({"event": "score", "indicator": subject_indicator, "kind": subject_kind, **score_snapshot(subject_kind, completed[subject_indicator])}, ensure_ascii=False) + "\n"
            yield '{"event":"done"}\n'
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    return StreamingResponse(stream(), media_type="application/x-ndjson", headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@app.get("/{path:path}", include_in_schema=False)
async def spa_fallback(path: str) -> FileResponse:
    if path.startswith("api/"):
        raise HTTPException(404)
    if not WEB_DIST.exists():
        raise HTTPException(503, "Frontend derlenmemiş. web/ klasöründe 'npm run build' çalıştırın.")
    candidate = (WEB_DIST / path).resolve()
    if candidate.is_relative_to(WEB_DIST.resolve()) and candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(WEB_DIST / "index.html", headers={"Cache-Control": "no-cache"})
