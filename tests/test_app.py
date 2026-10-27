import asyncio
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from argon2 import PasswordHasher

import app as service


class InputTests(unittest.TestCase):
    def test_public_addresses_and_domain(self):
        self.assertEqual(service.normalize_indicator("8.8.8.8"), ("8.8.8.8", "ipv4"))
        self.assertEqual(service.normalize_indicator("2606:4700:4700::1111"), ("2606:4700:4700::1111", "ipv6"))
        self.assertEqual(service.normalize_indicator("Example.COM."), ("example.com", "domain"))

    def test_reject_private_and_urls(self):
        for value in ("127.0.0.1", "192.168.1.2", "::1", "https://example.com/x", "abc.local", "a..com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                service.normalize_indicator(value)

    def test_quota_shared_under_concurrency(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(service, "DATA", Path(temp)):
            with ThreadPoolExecutor(max_workers=10) as pool:
                allowed = list(pool.map(lambda _: service.reserve_virustotal_quota(), range(10)))
            self.assertEqual(sum(allowed), 4)


class StreamTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_data = tempfile.TemporaryDirectory()
        self.data_patch = patch.object(service, "DATA", Path(self.temp_data.name))
        self.data_patch.start()
        self.original_settings = service.SETTINGS.copy()
        service.SETTINGS["APP_PASSWORD_HASH"] = PasswordHasher().hash("test-password")
        service.SETTINGS["SESSION_SECRET"] = "a" * 64
        service.app.state.client = None
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=service.app), base_url="https://testserver")

    async def asyncTearDown(self):
        await self.client.aclose()
        service.SETTINGS.clear()
        service.SETTINGS.update(self.original_settings)
        self.data_patch.stop()
        self.temp_data.cleanup()

    async def test_authentication_required_and_login(self):
        denied = await self.client.post("/api/search", json={"indicator": "8.8.8.8"})
        self.assertEqual(denied.status_code, 401)
        bad = await self.client.post("/api/login", json={"password": "wrong"})
        self.assertEqual(bad.status_code, 401)
        good = await self.client.post("/api/login", json={"password": "test-password"})
        self.assertEqual(good.status_code, 200)
        self.assertIn("HttpOnly", good.headers["set-cookie"])
        self.assertEqual("Secure" in good.headers["set-cookie"], service.COOKIE_SECURE)
        session = await self.client.get("/api/session")
        self.assertTrue(session.json()["authenticated"])

    async def test_map_tiles_keep_key_on_server(self):
        service.SETTINGS["CARTO_BASEMAP_API_KEY"] = "test-carto-key"
        denied = await self.client.get("/api/map-tiles/3/4/2.png")
        self.assertEqual(denied.status_code, 401)
        await self.client.post("/api/login", json={"password": "test-password"})

        def handler(request):
            self.assertEqual(request.url.params["key"], "test-carto-key")
            self.assertEqual(request.url.path, "/rastertiles/dark_all/3/4/2.png")
            return httpx.Response(200, content=b"\x89PNG\r\n\x1a\n", headers={"content-type": "image/png"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as upstream:
            service.app.state.client = upstream
            tile = await self.client.get("/api/map-tiles/3/4/2.png")
        self.assertEqual(tile.status_code, 200)
        self.assertEqual(tile.headers["content-type"], "image/png")
        self.assertNotIn("test-carto-key", str(tile.headers) + tile.text)
        invalid = await self.client.get("/api/map-tiles/3/8/2.png")
        self.assertEqual(invalid.status_code, 404)

    async def test_out_of_order_results_and_partial_error(self):
        await self.client.post("/api/login", json={"password": "test-password"})

        async def fake_source(client, source, indicator, kind):
            await asyncio.sleep(0.03 if source == "abuseipdb" else 0.001)
            return service.result(source, "error" if source == "otx" else "no_match", "test")

        with patch.object(service, "run_source", fake_source):
            response = await self.client.post("/api/search", json={"indicator": "8.8.8.8"})
        self.assertEqual(response.status_code, 200)
        events = [json.loads(line) for line in response.text.splitlines()]
        self.assertEqual(events[0]["event"], "start")
        self.assertEqual(events[-1]["event"], "done")
        self.assertEqual(len([event for event in events if event["event"] == "result"]), 8)
        self.assertEqual(len([event for event in events if event["event"] == "score"]), 8)
        self.assertNotEqual(events[1]["source"], "abuseipdb")
        self.assertEqual(next(event for event in events if event.get("source") == "otx")["status"], "error")

    async def test_dns_resolver_stops_at_first_public_ipv4(self):
        records = [
            (2, 1, 6, "", ("192.168.1.5", 0)),
            (2, 1, 6, "", ("8.8.8.8", 0)),
            (2, 1, 6, "", ("1.1.1.1", 0)),
        ]
        loop = asyncio.get_running_loop()
        lookup = AsyncMock(return_value=records)
        with patch.object(loop, "getaddrinfo", new=lookup):
            dns = await service.resolve_domain("example.com")
        self.assertEqual(dns, {"status": "ok", "addresses": ["8.8.8.8"], "selected": "8.8.8.8"})
        self.assertEqual(lookup.await_count, 1)

    async def test_dns_resolver_ipv6_only_and_failure_states(self):
        loop = asyncio.get_running_loop()
        cases = [
            ([[], [(10, 1, 6, "", ("2606:4700:4700::1111", 0, 0, 0))]], "ok", "2606:4700:4700::1111"),
            ([[(2, 1, 6, "", ("10.0.0.5", 0))], [(10, 1, 6, "", ("::1", 0, 0, 0))]], "no_public_ip", None),
        ]
        for records, status, selected in cases:
            with self.subTest(status=status), patch.object(loop, "getaddrinfo", new=AsyncMock(side_effect=records)):
                dns = await service.resolve_domain("example.com")
            self.assertEqual((dns["status"], dns["selected"]), (status, selected))
            if status == "no_public_ip":
                self.assertEqual(dns["addresses"], ["10.0.0.5"])
        with patch.object(loop, "getaddrinfo", new=AsyncMock(side_effect=OSError("DNS failed"))):
            self.assertEqual((await service.resolve_domain("example.com"))["status"], "error")
        with patch.object(loop, "getaddrinfo", new=AsyncMock(side_effect=asyncio.TimeoutError)):
            self.assertEqual((await service.resolve_domain("example.com"))["status"], "timeout")

    async def test_domain_and_resolved_ip_have_separate_results_and_scores(self):
        await self.client.post("/api/login", json={"password": "test-password"})
        calls = []

        async def fake_source(client, source, indicator, kind):
            calls.append((source, indicator, kind))
            return service.result(source, "no_match", indicator)

        with patch.object(service, "resolve_domain", new=AsyncMock(return_value={"status": "ok", "addresses": ["8.8.8.8"], "selected": "8.8.8.8"})), patch.object(service, "run_source", fake_source):
            response = await self.client.post("/api/search", json={"indicator": "example.com"})
        events = [json.loads(line) for line in response.text.splitlines()]
        self.assertEqual(events[-1]["event"], "done")
        self.assertEqual(len([event for event in events if event["event"] == "dns"]), 1)
        self.assertEqual(len([event for event in events if event["event"] == "result"]), 16)
        self.assertEqual(len([event for event in events if event["event"] == "score"]), 16)
        self.assertEqual(len([call for call in calls if call[1] == "example.com"]), 8)
        self.assertEqual(len([call for call in calls if call[1] == "8.8.8.8"]), 8)
        self.assertEqual({event["kind"] for event in events if event["event"] == "score"}, {"domain", "ipv4"})
        self.assertTrue(all(event["indicator"] in {"example.com", "8.8.8.8"} for event in events if event["event"] in {"result", "score"}))

    async def test_dns_failure_keeps_domain_analysis(self):
        await self.client.post("/api/login", json={"password": "test-password"})

        async def fake_source(client, source, indicator, kind):
            self.assertEqual((indicator, kind), ("example.com", "domain"))
            return service.result(source, "no_match", "none")

        with patch.object(service, "resolve_domain", new=AsyncMock(return_value={"status": "timeout", "addresses": [], "selected": None})), patch.object(service, "run_source", fake_source):
            response = await self.client.post("/api/search", json={"indicator": "example.com"})
        events = [json.loads(line) for line in response.text.splitlines()]
        self.assertEqual(events[-1]["event"], "done")
        self.assertEqual(len([event for event in events if event["event"] == "result"]), 8)

    async def test_internetdb_ports_and_score(self):
        async def handler(request):
            return httpx.Response(200, json={"ip": "8.8.8.8", "ports": [443, 53, 443], "vulns": ["CVE-2025-0001"], "hostnames": ["dns.google"], "cpes": [], "tags": []})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as upstream:
            item = await service.internetdb(upstream, "8.8.8.8", "ipv4")
        self.assertEqual(item["details"]["ports"], [53, 443])
        self.assertEqual(item["status"], "match")
        self.assertEqual(service.usage_snapshot()["requests_24h"]["internetdb"], 1)
        snapshot = service.score_snapshot("ipv4", {"internetdb": item})
        self.assertEqual(snapshot["value"], 4)
        self.assertTrue(snapshot["provisional"])
        self.assertEqual(snapshot["evaluated"], 1)
        self.assertEqual(service.score_snapshot("domain", {})["value"], None)

    async def test_internetdb_connection_failure_is_not_reported_as_timeout(self):
        def handler(request):
            self.assertEqual(request.extensions["timeout"]["connect"], 3.0)
            raise httpx.ConnectError("connection reset", request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as upstream:
            item = await service.run_source(upstream, "internetdb", "8.8.8.8", "ipv4")
        self.assertEqual(item["status"], "error")
        self.assertEqual(item["summary"], "InternetDB'ye bu ağdan bağlantı kurulamadı.")

    async def test_mxtoolbox_lookup(self):
        async def handler(request):
            self.assertEqual(request.headers["Authorization"], "test-key")
            path = request.url.path
            if "blacklist/" in path:
                return httpx.Response(429, json={"message": "API limit exceeded"})
            if "ptr/" in path:
                return httpx.Response(200, json={
                    "IsError": False,
                    "Passed": [{"Name": "DNS Record Published", "Info": "DNS Record found"}],
                    "Warnings": [], "Failed": [],
                    "Information": [{"Type": "PTR", "Hostname": "dns.google"}],
                })
            return httpx.Response(200, json={
                "IsError": False,
                "Passed": [{"Name": "DNS Record Published", "Info": "DNS Record found"}],
                "Warnings": [{"Name": "DMARC Quarantine/Reject policy not enabled", "Info": "x"}],
                "Failed": [],
                "Information": [{"Pref": "10", "Hostname": "mail.example.com", "IP Address": "1.2.3.4", "TTL": "5 min"}],
            })

        original = service.SETTINGS.get("MXTOOLBOX_API_KEY")
        service.SETTINGS["MXTOOLBOX_API_KEY"] = "test-key"
        try:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as upstream:
                domain_item = await service.mxtoolbox(upstream, "example.com", "domain")
                ip_item = await service.mxtoolbox(upstream, "8.8.8.8", "ipv4")
        finally:
            if original is None:
                service.SETTINGS.pop("MXTOOLBOX_API_KEY", None)
            else:
                service.SETTINGS["MXTOOLBOX_API_KEY"] = original
        self.assertEqual(domain_item["status"], "match")
        self.assertEqual(domain_item["details"]["records"][0]["hostname"], "mail.example.com")
        self.assertEqual(len(domain_item["details"]["warnings"]), 1)
        self.assertEqual(ip_item["status"], "no_match")
        self.assertEqual(ip_item["details"]["command"], "ptr")
        self.assertEqual(ip_item["details"]["records"][0]["type"], "PTR")
        snapshot = service.score_snapshot("domain", {"mxtoolbox": domain_item})
        self.assertEqual(snapshot["value"], 5)
        unsupported = await service.mxtoolbox(None, "::1", "ipv6")
        self.assertEqual(unsupported["status"], "unsupported")

    async def test_cross_origin_rejected(self):
        response = await self.client.post("/api/login", json={"password": "test-password"}, headers={"Origin": "https://another-host"})
        self.assertEqual(response.status_code, 403)

    async def test_usage_is_authenticated_and_counts_requests(self):
        denied = await self.client.get("/api/usage")
        self.assertEqual(denied.status_code, 401)
        await self.client.post("/api/login", json={"password": "test-password"})
        service.record_usage("search")
        service.record_usage("internetdb")
        self.assertTrue(service.reserve_virustotal_quota())
        response = await self.client.get("/api/usage")
        self.assertEqual(response.status_code, 200)
        usage = response.json()
        self.assertEqual(usage["searches_24h"], 1)
        self.assertEqual(usage["requests_24h"]["internetdb"], 1)
        self.assertEqual(usage["virustotal_minute"], 1)
        self.assertEqual(usage["virustotal_24h"], 1)


class SpaServingTests(unittest.TestCase):
    def test_index_assets_and_fallback_serve_dist(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(service, "WEB_DIST", Path(temp)):
            (Path(temp) / "index.html").write_text("SPA")
            (Path(temp) / "assets").mkdir()
            (Path(temp) / "assets" / "app.js").write_text("console.log(1)")

            async def run():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=service.app), base_url="https://testserver") as client:
                    index = await client.get("/")
                    asset = await client.get("/assets/app.js")
                    route = await client.get("/kaynaklar")
                    missing = await client.get("/api/unknown")
                    return index, asset, route, missing

            index, asset, route, missing = asyncio.run(run())
        self.assertEqual(index.status_code, 200)
        self.assertEqual(index.text, "SPA")
        self.assertEqual(asset.text, "console.log(1)")
        self.assertEqual(route.text, "SPA")
        self.assertEqual(missing.status_code, 404)


if __name__ == "__main__":
    unittest.main()
