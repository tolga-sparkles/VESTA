"""Explainable evaluation of news, vulnerability records and social claims."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urlsplit

from cve_enrichment import cve_ids

IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_PATTERN = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?![\w:])", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?![\w.-])", re.IGNORECASE)
GUIDE_WORDS = ("nasıl", "rehber", "kurulum", "yapılandırma", "tutorial", "how to", "guide", "komutları")
INCIDENT_WORDS = ("ddos", "fidye", "ransomware", "veri ihlali", "sızıntı", "phishing", "oltalama", "breach", "attack campaign")
SECURITY_WORDS = ("güvenlik", "siber", "zafiyet", "vulnerability", "malware", "zararlı", "istismar", "exploit", "ioc", "tehdit")
EXPLOIT_WORDS = ("aktif istismar", "actively exploited", "in the wild", "istismar ediliyor")
DENIAL_WORDS = ("yalanladı", "asılsız", "iddiaları reddetti", "denied", "false claim")
ASSERTION_WORDS = ("saldırı gerçekleşti", "ihlali doğruladı", "attack confirmed", "breach confirmed")
PRIORITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "general": 1}


def _date(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _days_since(value: object, now: datetime) -> float | None:
    date = _date(value)
    return max(0, (now - date).total_seconds() / 86400) if date else None


def indicators(text: str) -> dict[str, list[str]]:
    ips: list[str] = []
    for match in IP_PATTERN.findall(text) + IPV6_PATTERN.findall(text):
        try:
            address = ipaddress.ip_address(match)
        except ValueError:
            continue
        if address.is_global and address.compressed not in ips:
            ips.append(address.compressed)
    domains: list[str] = []
    for match in DOMAIN_PATTERN.findall(text):
        domain = match.lower().rstrip(".")
        if domain not in domains and not domain.endswith((".local", ".invalid", ".test")):
            domains.append(domain)
    return {"cves": cve_ids(text), "ips": ips[:8], "domains": domains[:8]}


def _content_type(item: dict, markers: dict[str, list[str]]) -> str:
    category = item.get("category")
    if category == "cve":
        return "vulnerability"
    if category == "ioc":
        return "ioc"
    if category == "privacy":
        return "breach_notice"
    if category == "official":
        return "official_notice"
    text = f"{item.get('title', '')} {item.get('summary', '')}".casefold()
    if any(word in text for word in GUIDE_WORDS):
        return "technical_guide"
    if markers["cves"]:
        return "vulnerability"
    if any(word in text for word in ("veri ihlali", "data breach", "kişisel veri sızıntısı")):
        return "breach_notice"
    if any(word in text for word in INCIDENT_WORDS):
        return "incident_report"
    if any(word in text for word in ("araştırma", "research", "malware analysis", "teknik analiz")) and any(word in text for word in SECURITY_WORDS):
        return "threat_research"
    if any(word in text for word in SECURITY_WORDS):
        return "cyber_news"
    return "general_technology"


def evaluate_item(item: dict, kev: dict[str, dict], nvd: dict[str, dict | None], now: datetime, kev_available: bool = True) -> dict:
    enriched = dict(item)
    text = f"{item.get('title', '')} {item.get('summary', '')}"
    markers = indicators(text)
    content_type = _content_type(item, markers)
    cve_id = markers["cves"][0] if markers["cves"] else None
    nvd_record = nvd.get(cve_id) if cve_id else None
    kev_record = kev.get(cve_id) if cve_id else None
    is_kev = kev_record is not None
    rss_date = item.get("published_at")
    cve_published_at = nvd_record.get("published_at") if nvd_record else None
    published_at = cve_published_at if item.get("category") == "cve" else rss_date
    updated_at = nvd_record.get("updated_at") if nvd_record else None
    age = _days_since(rss_date, now)
    freshness = 18 if age is not None and age <= 2 else 12 if age is not None and age <= 7 else 5 if age is not None and age <= 30 else 0
    relevance = 20 if content_type in {"vulnerability", "ioc", "incident_report", "breach_notice", "official_notice", "threat_research"} else 12 if content_type == "cyber_news" else 2 if content_type == "technical_guide" else 0
    evidence = 35 if is_kev else 22 if item.get("category") in {"official", "privacy"} else 0
    official_urgency = item.get("category") == "official" and any(term in text.casefold() for term in ("acil", "urgent", "aktif istismar", "actively exploited"))
    urgency = 12 if content_type in {"incident_report", "breach_notice"} and age is not None and age <= 7 else 5 if content_type == "vulnerability" else 0
    score_parts = {"evidence": evidence, "relevance": relevance, "urgency": urgency, "freshness": freshness, "independent_support": 0}
    score = sum(score_parts.values())
    if content_type in {"technical_guide", "general_technology"}:
        priority = "general"
    elif is_kev and (age is None or age <= 30):
        priority = "critical"
    elif is_kev or ((official_urgency or item.get("category") == "privacy") and age is not None and age <= 30):
        priority = "high"
    elif content_type == "incident_report" and age is not None and age <= 7:
        priority = "medium"
    elif score >= 30:
        priority = "medium"
    else:
        priority = "low"
    verification = "official_publication" if item.get("category") in {"official", "privacy"} else "single_source"
    reasons: list[str] = []
    if is_kev:
        reasons.append("CISA KEV kataloğunda yer alıyor")
    elif any(word in text.casefold() for word in EXPLOIT_WORDS):
        reasons.append("Kaynak aktif istismar bildiriyor; bağımsız kanıt henüz doğrulanmadı")
    if item.get("category") in {"official", "privacy"}:
        reasons.append("Resmî kaynakta yayımlandı; aktarılan iddialar ayrıca doğrulanmış sayılmaz")
    if content_type == "technical_guide":
        reasons.append("Teknik rehber; olay bildirimi değil")
    if content_type == "general_technology":
        reasons.append("Doğrudan tehdit gelişmesi belirlenemedi")
    if item.get("category") == "cve" and not published_at:
        reasons.append("CVE'nin ilk yayın tarihi doğrulanamadı; RSS tarihi yeni keşif tarihi değildir")
    if cve_id and not kev_available:
        reasons.append("CISA KEV verisine erişilemedi; katalog eşleşmesi bilinmiyor")
    active_evidence = [{"type": "cisa_kev", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}] if is_kev else []
    enriched["evaluation"] = {
        "content_type": content_type,
        "priority": priority,
        "verification": verification,
        "relevance": relevance,
        "urgency": urgency,
        "rank_score": score,
        "rank_components": score_parts,
        "reasons": reasons,
        "indicators": markers,
        "active_exploitation": bool(active_evidence),
        "active_evidence": active_evidence,
        "region": "turkey" if item.get("source_id") in {"sgb-bildirim", "kvkk-ihlaller"} else "global" if item.get("category") in {"cve", "ioc"} else "unknown",
        "source_count": 1,
        "independent_source_count": 1,
    }
    enriched["dates"] = {"published_at": published_at, "updated_at": updated_at, "rss_added_at": rss_date}
    enriched["cve_data"] = {
        "id": cve_id,
        "published_at": cve_published_at,
        "updated_at": updated_at,
        "rss_added_at": rss_date,
        "cvss": nvd_record.get("cvss") if nvd_record else None,
        "products": nvd_record.get("products", []) if nvd_record else [],
        "kev": is_kev if kev_available else None,
        "kev_added_at": kev_record.get("dateAdded") if kev_record else None,
        "known_ransomware_use": kev_record.get("knownRansomwareCampaignUse") if kev_record else None,
        "sources": [item.get("url"), nvd_record.get("url") if nvd_record else None],
    } if cve_id else None
    return enriched


def _normalized(value: str) -> str:
    return " ".join(re.findall(r"[\w]+", value.casefold()))


def _similarity(left: str, right: str) -> float:
    return SequenceMatcher(None, _normalized(left), _normalized(right)).ratio()


def _related(left: dict, right: dict) -> bool:
    if left["id"] == right["id"]:
        return False
    left_markers = left["evaluation"]["indicators"]
    right_markers = right["evaluation"]["indicators"]
    left_date = _date(left.get("published_at")) or datetime.min.replace(tzinfo=timezone.utc)
    right_date = _date(right.get("published_at")) or datetime.min.replace(tzinfo=timezone.utc)
    days = abs((left_date - right_date).days)
    if days > 14:
        return False
    same_title = _similarity(left["title"], right["title"]) >= 0.86
    shared_cve = bool(set(left_markers["cves"]) & set(right_markers["cves"]))
    shared_ioc = bool((set(left_markers["ips"]) & set(right_markers["ips"])) or (set(left_markers["domains"]) & set(right_markers["domains"])))
    same_type = left["evaluation"]["content_type"] == right["evaluation"]["content_type"]
    if same_title and same_type:
        return True
    if shared_cve and same_type and _similarity(left["title"], right["title"]) >= 0.45:
        return True
    return shared_ioc and same_type and _similarity(left["title"], right["title"]) >= 0.65


def correlate(items: list[dict]) -> list[dict]:
    parents = list(range(len(items)))

    def root(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    for index, left in enumerate(items):
        for other in range(index + 1, len(items)):
            if _related(left, items[other]):
                parents[root(other)] = root(index)
    groups: dict[int, list[dict]] = {}
    for index, item in enumerate(items):
        groups.setdefault(root(index), []).append(item)
    events: list[dict] = []
    for members in groups.values():
        members.sort(key=lambda item: item.get("published_at") or "")
        event_id = hashlib.sha256("|".join(sorted(item["id"] for item in members)).encode()).hexdigest()[:20]
        fingerprints: list[dict] = []
        for member in members:
            host = urlsplit(member["url"]).hostname
            if not any(host == urlsplit(other["url"]).hostname or _similarity(member["title"], other["title"]) > 0.94 or _similarity(member["title"] + member["summary"], other["title"] + other["summary"]) > 0.84 for other in fingerprints):
                fingerprints.append(member)
        independent = len(fingerprints)
        contradiction = any(any(word in member["title"].casefold() for word in DENIAL_WORDS) for member in members) and any(any(word in member["title"].casefold() for word in ASSERTION_WORDS) for member in members)
        for member in members:
            evaluation = member["evaluation"]
            evaluation["source_count"] = len({entry["source_id"] for entry in members})
            evaluation["independent_source_count"] = independent
            if contradiction:
                evaluation["verification"] = "conflicting"
            elif independent >= 2 and evaluation["verification"] != "official_publication":
                evaluation["verification"] = "supported"
                evaluation["rank_components"]["independent_support"] = 12
                evaluation["rank_score"] += 12
                if evaluation["priority"] == "medium":
                    evaluation["priority"] = "high"
            member["event_id"] = event_id
        representative = max(members, key=lambda entry: (PRIORITY_ORDER[entry["evaluation"]["priority"]], entry["evaluation"]["rank_score"], entry.get("published_at") or ""))
        events.append({
            "id": event_id,
            "title": representative["title"],
            "item_ids": [member["id"] for member in members],
            "sources": [{"name": member["source"], "url": member["url"], "published_at": member.get("published_at")} for member in members],
            "timeline": [{"item_id": member["id"], "title": member["title"], "published_at": member.get("published_at"), "url": member["url"]} for member in members],
            "priority": representative["evaluation"]["priority"],
            "verification": representative["evaluation"]["verification"],
            "rank_score": representative["evaluation"]["rank_score"],
            "independent_source_count": independent,
        })
    return sorted(events, key=lambda event: (PRIORITY_ORDER[event["priority"]], event["rank_score"]), reverse=True)


def evaluate_tweets(tweets: list[dict], events: list[dict], items: list[dict]) -> list[dict]:
    by_id = {item["id"]: item for item in items}
    grouped: dict[str, str] = {}
    result: list[dict] = []
    for tweet in tweets:
        enriched = dict(tweet)
        markers = indicators(str(tweet.get("text") or ""))
        linked = None
        for event in events:
            matches = [by_id[item_id] for item_id in event["item_ids"]]
            if any(set(markers["cves"]) & set(member["evaluation"]["indicators"]["cves"]) for member in matches):
                linked = event["id"]
                break
        normalized_text = _normalized(str(tweet.get("text") or ""))[:90]
        group_key = f"{markers['cves'][0]}:{normalized_text}" if markers["cves"] else normalized_text or str(tweet.get("id"))
        enriched["group_id"] = grouped.setdefault(group_key, hashlib.sha256(group_key.encode()).hexdigest()[:16])
        enriched["linked_event_id"] = linked
        lowered = str(tweet.get("text") or "").casefold()
        claim_type = "ddos" if "ddos" in lowered else "breach" if any(word in lowered for word in ("veri ihlali", "breach", "sızıntı")) else "phishing" if any(word in lowered for word in ("phishing", "oltalama", "sahte site")) else "security_claim"
        enriched["evaluation"] = {
            "priority": "medium" if any(word in str(tweet.get("text") or "").casefold() for word in INCIDENT_WORDS) else "low",
            "verification": "unverified_claim",
            "label": "Doğrulanmamış sosyal medya bildirimi",
            "claim_type": claim_type,
            "account_identity": "unverified",
            "independent_confirmation": False,
            "indicators": markers,
        }
        result.append(enriched)
    return result


def rank_items(items: list[dict], mode: str = "recommended") -> list[dict]:
    if mode == "newest":
        return sorted(items, key=lambda item: item.get("published_at") or "", reverse=True)
    if mode == "critical":
        return sorted(items, key=lambda item: (PRIORITY_ORDER[item["evaluation"]["priority"]], item["evaluation"]["rank_score"], item.get("published_at") or ""), reverse=True)
    if mode == "official":
        return sorted(items, key=lambda item: (item["evaluation"]["verification"] == "official_publication", item["evaluation"]["rank_score"], item.get("published_at") or ""), reverse=True)
    return sorted(items, key=lambda item: (item["evaluation"]["rank_score"], item.get("published_at") or ""), reverse=True)


def evaluate(items: list[dict], tweets: list[dict], kev: dict[str, dict], nvd: dict[str, dict | None], now: datetime | None = None, kev_available: bool = True) -> dict:
    now = now or datetime.now(timezone.utc)
    evaluated = [evaluate_item(item, kev, nvd, now, kev_available) for item in items]
    events = correlate(evaluated)
    new_cves = sorted(
        (item for item in evaluated if item["cve_data"] and (age := _days_since(item["cve_data"]["published_at"], now)) is not None and age <= 30),
        key=lambda item: item["cve_data"]["published_at"], reverse=True,
    )
    active_cves = sorted((item for item in evaluated if item["cve_data"] and item["cve_data"]["kev"]), key=lambda item: item["cve_data"]["kev_added_at"] or "", reverse=True)
    return {"items": rank_items(evaluated), "events": events, "tweets": evaluate_tweets(tweets, events, evaluated), "cve_radar": {"new": [item["id"] for item in new_cves], "known_exploited": [item["id"] for item in active_cves]}}
