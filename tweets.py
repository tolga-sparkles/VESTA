"""VESTA X (Twitter) tehdit istihbaratı akışı.

`twitter_pipeline` içindeki manuel çekilmiş JSON dosyalarını okur ve
Haberler sekmesi için tweet listesine dönüştürür. X API'sine doğrudan
istek atmaz; yalnızca diskteki çıktıları yorumlar.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TWITTER_DIR = ROOT.parent / "twitter_pipeline"
MANUEL_DIR = TWITTER_DIR / "manuel"
MEDIA_DIR = MANUEL_DIR / "media"

# Haberler sekmesinde gösterilecek X hesapları (tehdit istihbaratı).
# Yalnızca bu listedekiler okunur; manuel/ altındaki diğer JSON'lar yok sayılır.
X_ACCOUNTS: tuple[str, ...] = ("CyberPulse56",)

CACHE_SECONDS = 600
MAX_TWEETS_PER_ACCOUNT = 30
MEDIA_EXTENSIONS = {"photo": ".jpg", "video": ".mp4", "animated_gif": ".mp4"}

_cache: dict | None = None
_cached_at = 0.0


def _parse_twitter_date(value: object) -> str | None:
    """`Tue Oct 13 12:14:40 +0000 2026` biçimini ISO 8601 UTC'ye çevirir."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.strptime(value, "%a %b %d %H:%M:%S %z %Y")
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


def _as_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _media_entries(tweet: dict, username: str) -> list[dict]:
    entries: list[dict] = []
    for index, media in enumerate(tweet.get("media") or []):
        if not isinstance(media, dict):
            continue
        media_type = str(media.get("type") or "photo")
        extension = MEDIA_EXTENSIONS.get(media_type, ".bin")
        filename = f"{tweet.get('id')}_{index}{extension}"
        local_path = MEDIA_DIR / username / filename
        entries.append({
            "type": media_type,
            "url": media.get("url"),
            "local": f"/api/tweets/media/{username}/{filename}" if local_path.is_file() else None,
            "width": media.get("width"),
            "height": media.get("height"),
        })
    return entries


def _account_tweets(path: Path) -> dict:
    username = path.stem
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"username": username, "status": "error", "fetched_at": None, "tweets": []}
    meta = data.get("meta") or {}
    tweets: list[dict] = []
    for raw in (data.get("tweets") or [])[:MAX_TWEETS_PER_ACCOUNT]:
        if not isinstance(raw, dict) or not raw.get("id"):
            continue
        tweets.append({
            "id": str(raw.get("id")),
            "created_at": _parse_twitter_date(raw.get("created_at")),
            "text": raw.get("text") or "",
            "lang": raw.get("lang"),
            "favorite_count": _as_int(raw.get("favorite_count")),
            "retweet_count": _as_int(raw.get("retweet_count")),
            "reply_count": _as_int(raw.get("reply_count")),
            "quote_count": _as_int(raw.get("quote_count")),
            "view_count": _as_int(raw.get("view_count")),
            "username": raw.get("username") or username,
            "name": raw.get("name"),
            "media": _media_entries(raw, username),
        })
    return {
        "username": username,
        "status": meta.get("status"),
        "fetched_at": meta.get("fetched_at") or meta.get("updated_at"),
        "tweets": tweets,
    }


def load_tweets() -> dict:
    """Whitelist'teki hesapların tweet'lerini okur ve kısa süreliğine önbellekler."""
    global _cache, _cached_at
    now = time.monotonic()
    if _cache is not None and now - _cached_at < CACHE_SECONDS:
        return _cache

    accounts: list[dict] = []
    tweets: list[dict] = []
    if MANUEL_DIR.is_dir():
        for username in X_ACCOUNTS:
            path = MANUEL_DIR / f"{username}.json"
            if not path.is_file():
                continue
            account = _account_tweets(path)
            accounts.append({
                "username": account["username"],
                "status": account["status"],
                "fetched_at": account["fetched_at"],
                "count": len(account["tweets"]),
            })
            tweets.extend(account["tweets"])

    tweets.sort(key=lambda item: item["created_at"] or "", reverse=True)
    _cache = {
        "accounts": accounts,
        "tweets": tweets,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    _cached_at = now
    return _cache
