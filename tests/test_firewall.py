import json
import os
import tempfile
import time
import unittest
import urllib.request

from netflow_backend.bandwidth_tracker import BandwidthTracker
from netflow_backend.config import NetflowConfig
from netflow_backend.firewall import FirewallEngine
from netflow_backend.proc_reader import SocketInfo
from netflow_backend.storage import NetflowStorage
from netflow_backend.api_server import APIServer


class TestFirewall(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_netflow.db")
        self.config = NetflowConfig(db_path=self.db_path, api_port=19096)
        self.storage = NetflowStorage(self.db_path)
        self.firewall = FirewallEngine(self.storage)

    def tearDown(self):
        self.storage.close()
        self.temp_dir.cleanup()

    def test_block_and_unblock_persistence(self):
        self.assertFalse(self.firewall.is_app_blocked("spotify"))

        # Block app
        self.firewall.block_app("spotify")
        self.assertTrue(self.firewall.is_app_blocked("spotify"))
        self.assertTrue(self.firewall.is_app_blocked("/usr/bin/spotify"))

        # Check storage persistence
        blocked_set = self.storage.get_blocked_processes()
        self.assertIn("spotify", blocked_set)

        # Unblock app
        self.firewall.unblock_app("spotify")
        self.assertFalse(self.firewall.is_app_blocked("spotify"))
        self.assertNotIn("spotify", self.storage.get_blocked_processes())

    def test_firewall_enforce_and_event_logging(self):
        self.firewall.block_app("bad_actor")

        mock_sockets = [
            SocketInfo(
                protocol="tcp",
                local_ip="192.168.1.10",
                local_port=54321,
                remote_ip="203.0.113.5",
                remote_port=443,
                state="ESTABLISHED",
                inode=99999,
                uid=1000,
                pid=4321,
                process_name="bad_actor",
                cmdline="/usr/bin/bad_actor --connect",
            ),
            SocketInfo(
                protocol="tcp",
                local_ip="192.168.1.10",
                local_port=54322,
                remote_ip="1.1.1.1",
                remote_port=53,
                state="ESTABLISHED",
                inode=99998,
                uid=1000,
                pid=1234,
                process_name="good_browser",
                cmdline="good_browser",
            ),
        ]

        events = self.firewall.enforce(mock_sockets, [])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["process_name"], "bad_actor")
        self.assertEqual(events[0]["action"], "BLOCKED")

        logged = self.storage.get_firewall_events()
        self.assertEqual(len(logged), 1)
        self.assertEqual(logged[0]["process_name"], "bad_actor")

    def test_firewall_api_endpoints(self):
        tracker = BandwidthTracker(self.config, self.storage)
        server = APIServer(tracker, self.storage, self.config)
        server.start()
        time.sleep(0.1)

        try:
            # 1. GET /api/firewall/status
            url = f"http://127.0.0.1:{self.config.api_port}/api/firewall/status"
            with urllib.request.urlopen(url) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertTrue(data["enabled"])
                self.assertEqual(data["blocked_count"], 0)

            # 2. POST /api/firewall/block
            block_url = f"http://127.0.0.1:{self.config.api_port}/api/firewall/block"
            req = urllib.request.Request(
                block_url,
                data=json.dumps({"process_name": "telegram", "blocked": True}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["status"], "blocked")

            # Verify blocked
            self.assertTrue(tracker.firewall.is_app_blocked("telegram"))

            # 3. POST /api/firewall/toggle
            toggle_url = f"http://127.0.0.1:{self.config.api_port}/api/firewall/toggle"
            req = urllib.request.Request(
                toggle_url,
                data=json.dumps({"enabled": False}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertFalse(data["enabled"])

            # 4. POST /api/firewall/clear
            clear_url = f"http://127.0.0.1:{self.config.api_port}/api/firewall/clear"
            req = urllib.request.Request(clear_url, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode())
                self.assertEqual(data["status"], "all_unblocked")

        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
