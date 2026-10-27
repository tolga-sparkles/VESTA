import unittest
from collections import Counter
from unittest.mock import patch

import httpx
from argon2 import PasswordHasher

import app as service
import news


def rss_xml(*items: tuple[str, str, str]) -> bytes:
    entries = "".join(
        f"<item><title>{title}</title><link>{link}</link><guid>{guid}</guid>"
        "<pubDate>Tue, 13 Oct 2026 08:00:00 +0300</pubDate>"
        "<description>&lt;b&gt;Kısa özet&lt;/b&gt;</description></item>"
        for title, link, guid in items
    )
    return f"<?xml version='1.0'?><rss version='2.0'><channel>{entries}</channel></rss>".encode()


def kvkk_html(count: int = 15) -> bytes:
    entries = "".join(
        f'<div class="news__box-meta"><a href="https://www.kvkk.gov.tr/Icerik/{9000+i}/'
        f'kamuoyu-duyurusu-{i}">Kamuoyu Duyurusu (Veri İhlali Bildirimi) – Kurum {i}</a>'
        '<p class="date">7 Ekim 2026, Çarşamba</p></div>'
        for i in range(count)
    )
    return entries.encode()


class ParseNewsTests(unittest.TestCase):
    def test_cve_items_with_same_destination_are_kept(self):
        source = news.FEEDS[2]
        content = rss_xml(
            ("CVE-2026-0001", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CVE-2026-0001"),
            ("CVE-2026-0002", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CVE-2026-0002"),
            ("Geçersiz bağlantı", "javascript:alert(1)", "unsafe"),
        )
        items = news.parse_feed(content, source)
        self.assertEqual(len(items), 2)
        self.assertNotEqual(items[0]["id"], items[1]["id"])
        self.assertEqual(items[0]["summary"], "Kısa özet")
        self.assertEqual(items[0]["published_at"], "2026-10-13T05:00:00+00:00")

    def test_sgb_incidents_are_mapped_to_official_items(self):
        items = news.parse_sgb_incidents({"models": [
            {"slug": "tr-26-1309", "title": "TR-26-1309 Güvenlik Bildirimi",
             "desc": "<p>Önemli <strong>zafiyet</strong></p>",
             "date": "2026-10-13 08:28:05.936943", "active": True},
            {"slug": "../unsafe", "title": "Geçersiz", "active": True},
        ]})
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["category"], "official")
        self.assertEqual(items[0]["summary"], "Önemli zafiyet")
        self.assertEqual(items[0]["published_at"], "2026-10-13T08:28:05.936943+00:00")
        self.assertEqual(items[0]["url"], "https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-1309")

    def test_kvkk_listing_and_detail_are_mapped_to_privacy_items(self):
        items = news.parse_kvkk_listing(kvkk_html(1))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["category"], "privacy")
        self.assertEqual(items[0]["published_at"], "2026-10-07T00:00:00+00:00")
        self.assertTrue(items[0]["date_only"])
        self.assertEqual(
            news.parse_kvkk_summary(
                '<div class="news__detail-article"><p>Boilerplate</p>'
                '<ul><li>Yetkisiz erişim sağlandı.</li>'
                '<li>İhlalden etkilenen kişisel veriler: kimlik bilgileri.</li></ul></div>'.encode()
            ),
            "İhlalden etkilenen kişisel veriler: kimlik bilgileri.",
        )


class NewsEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.original_settings = service.SETTINGS.copy()
        service.SETTINGS["APP_PASSWORD_HASH"] = PasswordHasher().hash("test-password")
        service.SETTINGS["SESSION_SECRET"] = "a" * 64
        self.cache_patch = patch.object(news, "_cache", None)
        self.cache_patch.start()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=service.app), base_url="https://testserver")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.cache_patch.stop()
        service.SETTINGS.clear()
        service.SETTINGS.update(self.original_settings)

    async def test_login_partial_failures_and_cache(self):
        self.assertEqual((await self.client.get("/api/news")).status_code, 401)
        await self.client.post("/api/login", json={"password": "test-password"})
        calls: Counter[str] = Counter()

        def handler(request: httpx.Request) -> httpx.Response:
            calls[request.url.host] += 1
            if request.url.host == "www.kvkk.gov.tr":
                if request.url.path == "/veri-ihlali-bildirimi":
                    return httpx.Response(200, content=kvkk_html())
                return httpx.Response(200, content=b'<div class="news__detail-article"><ul>'
                                                   b'<li>Yetkisiz erisim.</li></ul></div>')
            if request.url.path == "/api/incident/index":
                return httpx.Response(200, json={"models": [{
                    "slug": "tr-26-1309", "title": "Resmî güvenlik bildirimi",
                    "desc": "<p>Özet</p>", "date": "2026-10-13 08:28:05", "active": True,
                }]})
            if request.url.host == "siberkapan.org":
                return httpx.Response(503)
            return httpx.Response(200, content=rss_xml((request.url.host, f"https://{request.url.host}/story", request.url.host)))

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as upstream:
            service.app.state.news_client = upstream
            first = await self.client.get("/api/news")
            second = await self.client.get("/api/news")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json(), second.json())
        self.assertEqual(len(first.json()["items"]), 18)
        self.assertEqual(len([item for item in first.json()["items"] if item["category"] == "official"]), 1)
        self.assertEqual(len([item for item in first.json()["items"] if item["category"] == "privacy"]), 15)
        self.assertEqual(len([item for item in first.json()["items"] if item["category"] == "privacy" and item["summary"]]), 3)
        self.assertEqual(len([source for source in first.json()["sources"] if source["status"] == "error"]), 2)
        self.assertEqual(sum(calls.values()), 9)
        self.assertEqual(len(first.json()["sources"]), 6)
        self.assertNotIn("tabya", [source["id"] for source in first.json()["sources"]])
        self.assertEqual(len(first.json()["official_links"]), 2)
        filtered = await self.client.get("/api/news", params={"category": "privacy", "q": "Kurum 2", "sort": "newest"})
        self.assertEqual(filtered.status_code, 200)
        self.assertTrue(all(item["category"] == "privacy" and "Kurum 2" in item["title"] for item in filtered.json()["items"]))
        self.assertEqual(filtered.json()["pagination"]["total"], len(filtered.json()["items"]))
        self.assertEqual(len(filtered.json()["tweets"]["tweets"]), 0)

    async def test_stale_cache_when_all_feeds_fail(self):
        await self.client.post("/api/login", json={"password": "test-password"})

        def ok_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=rss_xml((request.url.host, f"https://{request.url.host}/story", request.url.host)))

        async with httpx.AsyncClient(transport=httpx.MockTransport(ok_handler)) as upstream:
            service.app.state.news_client = upstream
            first = await self.client.get("/api/news")
        self.assertEqual(first.status_code, 200)
        self.assertFalse(first.json().get("stale"))

        def fail_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        async with httpx.AsyncClient(transport=httpx.MockTransport(fail_handler)) as upstream:
            service.app.state.news_client = upstream
            stale = await self.client.get("/api/news", params={"fresh": "1"})
        self.assertEqual(stale.status_code, 200)
        self.assertTrue(stale.json()["stale"])
        self.assertEqual(len(stale.json()["items"]), len(first.json()["items"]))
        self.assertTrue(all(source["status"] == "error" for source in stale.json()["sources"]))
