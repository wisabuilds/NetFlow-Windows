"""
Unit tests for NetflowStorage: time-series queries, data plan quotas, and cleanup.
"""

import os
import tempfile
import time
import unittest

from netflow_backend.storage import NetflowStorage


class TestNetflowStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_netflow.db")
        self.storage = NetflowStorage(self.db_path)

    def tearDown(self):
        self.storage.close()
        self.temp_dir.cleanup()

    def test_record_and_get_speeds(self):
        now = int(time.time())
        self.storage.record_interface_snapshot(
            timestamp=now - 10,
            interface="eth0",
            rx_bytes=1000,
            tx_bytes=500,
            rx_speed=100.0,
            tx_speed=50.0,
        )
        self.storage.record_interface_snapshot(
            timestamp=now,
            interface="eth0",
            rx_bytes=2000,
            tx_bytes=1000,
            rx_speed=200.0,
            tx_speed=100.0,
        )

        speeds = self.storage.get_recent_speeds(seconds=30)
        self.assertGreaterEqual(len(speeds), 2)
        total_rx = sum(p["rx_bytes"] for p in speeds)
        self.assertEqual(total_rx, 3000)

    def test_daily_usage(self):
        now = int(time.time())
        self.storage.record_interface_snapshot(
            timestamp=now,
            interface="wlan0",
            rx_bytes=5000,
            tx_bytes=2500,
            rx_speed=50.0,
            tx_speed=25.0,
        )
        daily = self.storage.get_daily_usage(days=7)
        self.assertGreaterEqual(len(daily), 1)
        self.assertEqual(daily[0]["total_bytes"], 7500)

    def test_top_processes(self):
        now = int(time.time())
        self.storage.record_process_snapshot(
            timestamp=now,
            process_name="firefox",
            pid=1234,
            rx_bytes=5000,
            tx_bytes=1000,
            active_connections=4,
        )
        self.storage.record_process_snapshot(
            timestamp=now,
            process_name="curl",
            pid=5678,
            rx_bytes=20000,
            tx_bytes=500,
            active_connections=1,
        )

        top = self.storage.get_top_processes(period_seconds=3600, limit=5)
        self.assertEqual(len(top), 2)
        # curl should be first because total_bytes is 20500 > 6000
        self.assertEqual(top[0]["process_name"], "curl")
        self.assertEqual(top[1]["process_name"], "firefox")

    def test_data_plan_status(self):
        now = int(time.time())
        limit = 10000  # 10 KB limit
        self.storage.update_data_plan(period="monthly", limit_bytes=limit, warning_pct=80)

        # Record usage: 9000 bytes (90% -> should trigger warning)
        self.storage.record_interface_snapshot(
            timestamp=now,
            interface="eth0",
            rx_bytes=6000,
            tx_bytes=3000,
            rx_speed=600.0,
            tx_speed=300.0,
        )

        status = self.storage.get_data_plan_status()
        self.assertTrue(status["configured"])
        self.assertEqual(status["used_bytes"], 9000)
        self.assertEqual(status["remaining_bytes"], 1000)
        self.assertEqual(status["percentage"], 90.0)
        self.assertTrue(status["warning_triggered"])
        self.assertFalse(status["exceeded"])


if __name__ == "__main__":
    unittest.main()
