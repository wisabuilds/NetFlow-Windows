"""
Integration tests for Netflow APIServer endpoints.
"""

import json
import os
import tempfile
import time
import unittest
import urllib.request

from netflow_backend.api_server import APIServer
from netflow_backend.bandwidth_tracker import BandwidthTracker
from netflow_backend.config import NetflowConfig
from netflow_backend.storage import NetflowStorage


class TestAPIServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = os.path.join(cls.temp_dir.name, "api_test.db")
        cls.config = NetflowConfig(
            api_host="127.0.0.1",
            api_port=9295,
            db_path=cls.db_path,
        )
        cls.config.ensure_directories()
        cls.storage = NetflowStorage(cls.config.db_path)
        cls.tracker = BandwidthTracker(cls.config, cls.storage)
        cls.tracker.tick()

        cls.server = APIServer(cls.tracker, cls.storage, cls.config)
        cls.server.start()
        time.sleep(0.3)

        # Empty proxy handler to bypass sandbox environment proxy variables
        cls.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.storage.close()
        cls.temp_dir.cleanup()

    def _get(self, path: str):
        url = f"http://127.0.0.1:9295{path}"
        req = urllib.request.Request(url)
        with self.opener.open(req, timeout=5) as resp:
            return json.loads(resp.read())

    def _post(self, path: str, payload: dict):
        url = f"http://127.0.0.1:9295{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with self.opener.open(req, timeout=5) as resp:
            return json.loads(resp.read())

    def test_get_web_dashboard(self):
        url = "http://127.0.0.1:9295/"
        req = urllib.request.Request(url)
        with self.opener.open(req, timeout=5) as resp:
            content = resp.read().decode("utf-8")
            self.assertEqual(resp.status, 200)
            self.assertIn("<title>NetFlow Linux", content)
            self.assertIn("trafficCanvas", content)

    def test_get_realtime_stats(self):
        data = self._get("/api/stats/realtime")
        self.assertIn("total_rx_speed_bps", data)
        self.assertIn("total_tx_speed_bps", data)
        self.assertIn("total_rx_speed_human", data)
        self.assertIn("interfaces", data)

    def test_get_history(self):
        data = self._get("/api/stats/history?seconds=30")
        self.assertIn("points", data)
        self.assertIn("count", data)

    def test_get_netstat(self):
        data = self._get("/api/netstat")
        self.assertIn("sockets", data)
        self.assertIn("total", data)

    def test_data_plan_get_and_post(self):
        # Configure plan
        payload = {
            "period": "monthly",
            "limit_bytes": 50 * 1024 * 1024 * 1024,
            "reset_day": 15,
            "warning_pct": 85,
        }
        res = self._post("/api/plan", payload)
        self.assertEqual(res["status"], "updated")
        self.assertTrue(res["plan"]["configured"])
        self.assertEqual(res["plan"]["limit_bytes"], 50 * 1024 * 1024 * 1024)

        # Retrieve plan
        status = self._get("/api/plan")
        self.assertTrue(status["configured"])
    def test_export_json(self):
        data = self._get("/api/export/json")
        self.assertIn("daily", data)
        self.assertIn("top_processes", data)
        self.assertIn("plan", data)
        self.assertIn("forecast", data)
        self.assertIn("exported_at", data)
        self.assertIsInstance(data["exported_at"], (int, float))

    def test_export_csv(self):
        url = "http://127.0.0.1:9295/api/export/csv?type=daily"
        req = urllib.request.Request(url)
        with self.opener.open(req, timeout=5) as resp:
            content = resp.read().decode("utf-8")
            self.assertEqual(resp.status, 200)
            self.assertIn("Date,Download_Bytes,Upload_Bytes,Total_Bytes", content)

    def test_incognito_toggle(self):
        # Check initial status
        status = self._get("/api/monitor/status")
        self.assertIn("incognito", status)

        # Enable incognito
        res = self._post("/api/monitor/incognito", {"enabled": True})
        self.assertTrue(res["incognito"])

        # Check status reflects change
        status = self._get("/api/monitor/status")
        self.assertTrue(status["incognito"])

        # Disable incognito
        res = self._post("/api/monitor/incognito", {"enabled": False})
        self.assertFalse(res["incognito"])

    def test_cors_headers(self):
        url = "http://127.0.0.1:9295/api/stats/realtime"
        # Request with localhost origin should get Access-Control-Allow-Origin
        req = urllib.request.Request(url, headers={"Origin": "http://127.0.0.1:9095"})
        with self.opener.open(req, timeout=5) as resp:
            self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "http://127.0.0.1:9095")

        # Request with untrusted external origin should NOT get Access-Control-Allow-Origin
        req2 = urllib.request.Request(url, headers={"Origin": "https://evil-site.com"})
        with self.opener.open(req2, timeout=5) as resp2:
            self.assertIsNone(resp2.headers.get("Access-Control-Allow-Origin"))

    def test_plan_input_validation(self):
        # Negative limit_bytes should be clamped to 0
        res = self._post("/api/plan", {"period": "invalid_period", "limit_bytes": -500, "reset_day": 99, "warning_pct": 200})
        self.assertEqual(res["status"], "updated")
        self.assertEqual(res["plan"]["period"], "monthly")
        self.assertEqual(res["plan"]["warning_pct"], 100)


if __name__ == "__main__":
    unittest.main()
