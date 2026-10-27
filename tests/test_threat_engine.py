import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import httpx

import cve_enrichment
import news
from threat_engine import evaluate, evaluate_item, rank_items


NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)


def article(id, title, *, category="news", source="Source A", source_id="a", summary="", date="2026-10-13T10:00:00+00:00"):
    return {"id": id, "title": title, "category": category, "source": source,
            "source_id": source_id, "summary": summary, "published_at": date,
            "url": f"https://{source_id}.example/{id}"}


class EvaluationTests(unittest.TestCase):
    def test_old_cve_in_new_rss_is_not_new_but_kev_is_active(self):
        item = article("old", "CVE-2015-5477 - ISC BIND", category="cve")
        nvd = {"CVE-2015-5477": {"published_at": "2015-07-28T00:00:00+00:00", "updated_at": "2026-10-12T00:00:00+00:00", "cvss": {"score": 7.8, "version": "3.1"}, "products": ["ISC BIND"], "url": "https://nvd.nist.gov/vuln/detail/CVE-2015-5477"}}
        kev = {"CVE-2015-5477": {"dateAdded": "2026-10-12"}}
        result = evaluate([item], [], kev, nvd, NOW)
        self.assertEqual(result["cve_radar"]["new"], [])
        self.assertEqual(result["cve_radar"]["known_exploited"], ["old"])
        self.assertEqual(result["items"][0]["dates"]["rss_added_at"], item["published_at"])
        self.assertEqual(result["items"][0]["cve_data"]["published_at"], nvd["CVE-2015-5477"]["published_at"])
        self.assertTrue(result["items"][0]["evaluation"]["active_exploitation"])

    def test_single_x_claim_is_unverified(self):
        result = evaluate([], [{"id": "1", "text": "Fransa kurumuna DDoS saldırısı iddiası", "username": "CyberPulse56"}], {}, {}, NOW)
        self.assertEqual(result["tweets"][0]["evaluation"]["verification"], "unverified_claim")
        self.assertEqual(result["tweets"][0]["evaluation"]["label"], "Doğrulanmamış sosyal medya bildirimi")
        self.assertEqual(result["tweets"][0]["evaluation"]["claim_type"], "ddos")
        self.assertEqual(result["tweets"][0]["evaluation"]["account_identity"], "unverified")

    def test_syndication_does_not_count_as_independent(self):
        items = [article("a", "Kurumun veri ihlali duyurusu", summary="Aynı basın bülteni"),
                 article("b", "Kurumun veri ihlali duyurusu", source="Source B", source_id="b", summary="Aynı basın bülteni")]
        result = evaluate(items, [], {}, {}, NOW)
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["independent_source_count"], 1)
        self.assertEqual(result["events"][0]["sources"][0]["url"], items[0]["url"])
        self.assertEqual(result["items"][0]["evaluation"]["verification"], "single_source")

    def test_related_independent_articles_are_grouped_and_ranked(self):
        items = [article("a", "CVE-2026-12345 Apache servisinde aktif istismar", summary="Araştırma A"),
                 article("b", "CVE-2026-12345 Apache servisinde istismar", source="Source B", source_id="b", summary="Farklı gözlem ve teknik bulgular")]
        result = evaluate(items, [], {}, {}, NOW)
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["independent_source_count"], 2)
        self.assertEqual(result["items"][0]["evaluation"]["verification"], "supported")
        self.assertEqual(len(result["events"][0]["timeline"]), 2)

    def test_rank_changes_with_evidence_and_guide_stays_general(self):
        guide = article("guide", "Linux güvenlik yapılandırma rehberi")
        cve = article("cve", "CVE-2026-12345 Apache", category="cve")
        plain = evaluate([guide, cve], [], {}, {}, NOW)
        self.assertEqual(plain["items"][0]["id"], "cve")
        self.assertEqual(plain["items"][1]["evaluation"]["priority"], "general")
        promoted = evaluate([guide, cve], [], {"CVE-2026-12345": {"dateAdded": "2026-10-13"}}, {}, NOW)
        self.assertEqual(promoted["items"][0]["evaluation"]["priority"], "critical")
        self.assertGreater(promoted["items"][0]["evaluation"]["rank_score"], plain["items"][0]["evaluation"]["rank_score"])
        self.assertEqual(rank_items(promoted["items"], "official")[0]["id"], "cve")

    def test_unknown_cve_date_and_cvss_remain_unknown(self):
        item = evaluate_item(article("cve", "CVE-2026-12345", category="cve"), {}, {}, NOW)
        self.assertIsNone(item["cve_data"]["published_at"])
        self.assertIsNone(item["cve_data"]["cvss"])
        self.assertFalse(item["evaluation"]["active_exploitation"])

    def test_routine_official_notice_is_not_urgent(self):
        routine = evaluate_item(article("routine", "Haftalık bilgilendirme", category="official", source_id="sgb-bildirim"), {}, {}, NOW)
        urgent = evaluate_item(article("urgent", "Acil güvenlik uyarısı: aktif istismar", category="official", source_id="sgb-bildirim"), {}, {}, NOW)
        self.assertEqual(routine["evaluation"]["verification"], "official_publication")
        self.assertNotEqual(routine["evaluation"]["priority"], "high")
        self.assertEqual(urgent["evaluation"]["priority"], "high")

    def test_indicators_reject_private_addresses(self):
        item = evaluate_item(article("ioc", "192.168.1.1 ve 8.8.8.8 ve 2606:4700:4700::1111", category="ioc"), {}, {}, NOW)
        self.assertEqual(item["evaluation"]["indicators"]["ips"], ["8.8.8.8", "2606:4700:4700::1111"])

    def test_cache_age_and_irregular_publication_health(self):
        raw = {"id": "sgb-bildirim", "name": "SGB", "category": "official", "url": "https://example.org", "status": "ok", "count": 1}
        sources = news._source_health([([article("a", "Resmî duyuru", date="2020-01-01T00:00:00+00:00")], raw)], 540)
        self.assertEqual(sources[0]["health_state"], "working")
        self.assertEqual(sources[0]["cache_age_seconds"], 540)
        self.assertIsNone(sources[0]["expected_frequency"])
        cached = news._cache_view({"sources": sources}, 590)
        self.assertEqual(cached["sources"][0]["cache_age_seconds"], 590)


class EnrichmentTests(unittest.IsolatedAsyncioTestCase):
    async def test_nvd_parser_keeps_real_dates_and_score(self):
        payload = {"vulnerabilities": [{"cve": {"id": "CVE-2026-12345", "published": "2026-10-10T12:00:00.000", "lastModified": "2026-10-13T12:00:00.000", "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8}}]}}}]}
        parsed = cve_enrichment._parse_nvd(payload, "CVE-2026-12345")
        self.assertEqual(parsed["published_at"], "2026-10-10T12:00:00+00:00")
        self.assertEqual(parsed["cvss"], {"score": 9.8, "version": "3.1"})

    async def test_enrichment_skips_network_without_cves(self):
        def handler(request):
            self.fail("Unexpected network request")
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            kev, nvd, status = await cve_enrichment.enrich(client, [article("a", "Ordinary news")])
        self.assertEqual((kev, nvd), ({}, {}))
        self.assertEqual(status["nvd_enriched"], 0)

    async def test_nvd_request_budget_and_failure_isolation(self):
        calls = []
        def handler(request):
            calls.append(request.url.params["cveId"])
            return httpx.Response(503 if request.url.params["cveId"].endswith("0001") else 200,
                                  json={"vulnerabilities": []})
        ids = [f"CVE-2026-{number:04d}" for number in range(1, 8)]
        with patch.object(cve_enrichment, "_nvd_cache", {}), patch.object(cve_enrichment, "_nvd_calls", []):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                result = await cve_enrichment.get_nvd(client, ids)
        self.assertEqual(len(calls), 5)
        self.assertEqual(set(result), set(ids[:5]))
        self.assertIsNone(result[ids[0]])


if __name__ == "__main__":
    unittest.main()
