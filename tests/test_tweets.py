import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import tweets


class TweetParseTests(unittest.TestCase):
    def test_parse_twitter_date(self):
        self.assertEqual(
            tweets._parse_twitter_date("Tue Oct 13 12:14:40 +0000 2026"),
            "2026-10-13T12:14:40+00:00",
        )
        self.assertEqual(tweets._parse_twitter_date("Tue Oct 13 15:22:04 +0300 2026"), "2026-10-13T12:22:04+00:00")
        self.assertIsNone(tweets._parse_twitter_date(None))
        self.assertIsNone(tweets._parse_twitter_date("geçersiz tarih"))

    def test_as_int_coerces_string_counts(self):
        self.assertEqual(tweets._as_int("64"), 64)
        self.assertEqual(tweets._as_int(7), 7)
        self.assertEqual(tweets._as_int("abc"), 0)
        self.assertEqual(tweets._as_int(None), 0)

    def test_media_entries_maps_local_path_only_when_file_exists(self):
        with tempfile.TemporaryDirectory() as temp:
            media_root = Path(temp)
            with patch.object(tweets, "MEDIA_DIR", media_root):
                (media_root / "CyberPulse56").mkdir()
                (media_root / "CyberPulse56" / "123_0.jpg").write_bytes(b"img")
                raw = {
                    "id": "123",
                    "media": [
                        {"type": "photo", "url": "https://pbs.twimg.com/x.jpg", "width": 100, "height": 200},
                        {"type": "photo", "url": "https://pbs.twimg.com/y.jpg"},
                    ],
                }
                entries = tweets._media_entries(raw, "CyberPulse56")
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["local"], "/api/tweets/media/CyberPulse56/123_0.jpg")
        self.assertIsNone(entries[1]["local"])
        self.assertEqual(entries[0]["width"], 100)


class LoadTweetsTests(unittest.TestCase):
    def setUp(self):
        self.cache_patch = patch.object(tweets, "_cache", None)
        self.cache_patch.start()

    def tearDown(self):
        self.cache_patch.stop()

    def test_load_tweets_only_reads_whitelisted_accounts(self):
        with tempfile.TemporaryDirectory() as temp:
            manuel = Path(temp)
            payload = {
                "meta": {"username": "CyberPulse56", "status": "completed", "fetched_at": "2026-10-13T15:22:04+03:00"},
                "tweets": [
                    {
                        "id": "2109981140388069888",
                        "created_at": "Tue Oct 13 12:14:40 +0000 2026",
                        "text": "DDoS CLAIM",
                        "lang": "en",
                        "favorite_count": 0,
                        "retweet_count": "1",
                        "reply_count": 0,
                        "quote_count": 0,
                        "view_count": "64",
                        "username": "CyberPulse56",
                        "name": "CyberPulse",
                        "media": [],
                    }
                ],
            }
            (manuel / "CyberPulse56.json").write_text(json.dumps(payload), encoding="utf-8")
            # Whitelist dışındaki hesap yok sayılmalı.
            (manuel / "RTErdogan.json").write_text(json.dumps(payload), encoding="utf-8")

            with patch.object(tweets, "MANUEL_DIR", manuel):
                result = tweets.load_tweets()

        self.assertEqual([account["username"] for account in result["accounts"]], ["CyberPulse56"])
        self.assertEqual(len(result["tweets"]), 1)
        self.assertEqual(result["tweets"][0]["retweet_count"], 1)
        self.assertEqual(result["tweets"][0]["view_count"], 64)
        self.assertEqual(result["tweets"][0]["created_at"], "2026-10-13T12:14:40+00:00")

    def test_load_tweets_without_directory_returns_empty(self):
        with patch.object(tweets, "MANUEL_DIR", Path("/nonexistent/xyz")):
            result = tweets.load_tweets()
        self.assertEqual(result["accounts"], [])
        self.assertEqual(result["tweets"], [])


if __name__ == "__main__":
    unittest.main()
