import json
import os
import shutil
import tempfile
import time
import unittest

from netflow_backend.config import NetflowConfig
from netflow_backend.dns_resolver import DNSResolver, get_dns_resolver
from netflow_backend.firewall import FirewallEngine
from netflow_backend.proc_reader import SocketInfo
from netflow_backend.storage import NetflowStorage


class TestAdvancedFeatures(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_netflow.db")
        self.storage = NetflowStorage(self.db_path)
        self.firewall = FirewallEngine(self.storage)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_dns_resolver_ip_classification(self):
        self.assertEqual(DNSResolver.classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(DNSResolver.classify_ip("::1"), "loopback")
        self.assertEqual(DNSResolver.classify_ip("192.168.1.1"), "lan")
        self.assertEqual(DNSResolver.classify_ip("10.0.4.12"), "lan")
        self.assertEqual(DNSResolver.classify_ip("172.16.0.1"), "lan")
        self.assertEqual(DNSResolver.classify_ip("8.8.8.8"), "wan")
        self.assertEqual(DNSResolver.classify_ip("1.1.1.1"), "wan")

        self.assertTrue(DNSResolver.is_lan_or_local("127.0.0.1"))
        self.assertTrue(DNSResolver.is_lan_or_local("192.168.1.100"))
        self.assertFalse(DNSResolver.is_lan_or_local("140.82.121.4"))

    def test_lan_only_firewall_policy(self):
        # Set policy to lan_only
        self.firewall.set_app_policy("test_streamer", "lan_only")
        rules = self.storage.get_firewall_rules()
        app_rule = next((r for r in rules if r["process_name"] == "test_streamer"), None)
        self.assertIsNotNone(app_rule)
        self.assertEqual(app_rule["policy"], "lan_only")

        # Socket to local LAN
        local_socket = SocketInfo(
            protocol="tcp",
            local_ip="192.168.1.10",
            local_port=50000,
            remote_ip="192.168.1.50",
            remote_port=8080,
            state="ESTABLISHED",
            inode=1001,
            uid=1000,
            pid=9999,
            process_name="test_streamer",
        )

        # Socket to public Internet (WAN)
        wan_socket = SocketInfo(
            protocol="tcp",
            local_ip="192.168.1.10",
            local_port=50001,
            remote_ip="93.184.216.34",  # example.com
            remote_port=443,
            state="ESTABLISHED",
            inode=1002,
            uid=1000,
            pid=9999,
            process_name="test_streamer",
        )


        # Enforce
        interceptions = self.firewall.enforce([local_socket, wan_socket], [{"name": "test_streamer", "pid": 9999}])
        
        # Local socket should be permitted, WAN socket should be intercepted
        self.assertEqual(len(interceptions), 1)
        self.assertEqual(interceptions[0]["process_name"], "test_streamer")
        self.assertEqual(interceptions[0]["action"], "BLOCKED_WAN")

    def test_first_seen_application_tracking(self):
        is_first = self.storage.mark_or_check_first_seen("new_daemon", "/usr/bin/new_daemon")
        self.assertTrue(is_first)

        # Second time seeing it
        is_second = self.storage.mark_or_check_first_seen("new_daemon", "/usr/bin/new_daemon")
        self.assertFalse(is_second)

        apps = self.storage.get_seen_applications()
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0]["process_name"], "new_daemon")

    def test_budget_forecast_calculations(self):
        # Configure a 10 GB limit with reset day = 1
        limit_bytes = 10 * (1024 ** 3)
        self.storage.update_data_plan("monthly", limit_bytes, reset_day=1, warning_pct=80)

        # Add fake interface history usage
        now = int(time.time())
        self.storage.record_interface_snapshot(now, "eth0", 2 * (1024 ** 3), 1 * (1024 ** 3), 1000.0, 1000.0)

        forecast = self.storage.get_budget_forecast()
        self.assertTrue(forecast["configured"])
        self.assertEqual(forecast["limit_bytes"], limit_bytes)
        self.assertGreater(forecast["used_bytes"], 0)
        self.assertGreater(forecast["remaining_bytes"], 0)
        self.assertIn("burn_status", forecast)
        self.assertIn("recommended_daily_budget_bytes", forecast)

    def test_csv_export(self):
        # Insert test daily history
        now = int(time.time())
        self.storage.record_interface_snapshot(now, "eth0", 1000000, 500000, 10000.0, 5000.0)
        self.storage.record_process_snapshot(now, "curl", 1234, 1000000, 500000, 2)

        daily_csv = self.storage.export_daily_csv()
        self.assertIn("Date,Download_Bytes,Upload_Bytes,Total_Bytes", daily_csv)

        procs_csv = self.storage.export_processes_csv()
        self.assertIn("Process_Name,Download_Bytes,Upload_Bytes,Total_Bytes", procs_csv)

    def test_prune_old_records(self):
        now = int(time.time())
        old_timestamp = now - (100 * 86400)  # 100 days old
        recent_timestamp = now - (10 * 86400)  # 10 days old

        self.storage.record_interface_snapshot(old_timestamp, "eth0", 100, 100, 10.0, 10.0)
        self.storage.record_interface_snapshot(recent_timestamp, "eth0", 200, 200, 20.0, 20.0)
        self.storage.record_process_snapshot(old_timestamp, "old_proc", 100, 50, 50, 1)
        self.storage.record_process_snapshot(recent_timestamp, "new_proc", 200, 50, 50, 1)

        deleted = self.storage.prune_old_records(retention_days=90)
        self.assertEqual(deleted, 2)  # 1 interface record + 1 process record

    def test_billing_bounds_calculator(self):
        from datetime import datetime
        # Daily period
        test_now = datetime(2026, 5, 15, 14, 30, 0)
        start, end = NetflowStorage._calculate_billing_bounds(period="daily", reset_day=1, now=test_now)
        self.assertEqual(start, datetime(2026, 5, 15, 0, 0, 0))
        self.assertEqual(end, datetime(2026, 5, 16, 0, 0, 0))

        # Monthly period (after reset day)
        start_m, end_m = NetflowStorage._calculate_billing_bounds(period="monthly", reset_day=10, now=test_now)
        self.assertEqual(start_m, datetime(2026, 5, 10, 0, 0, 0))
        self.assertEqual(end_m, datetime(2026, 6, 10, 0, 0, 0))

        # Monthly period (before reset day)
        early_now = datetime(2026, 5, 5, 10, 0, 0)
        start_early, end_early = NetflowStorage._calculate_billing_bounds(period="monthly", reset_day=10, now=early_now)
        self.assertEqual(start_early, datetime(2026, 4, 10, 0, 0, 0))
        self.assertEqual(end_early, datetime(2026, 5, 10, 0, 0, 0))

    def test_mac_vendor_lookup(self):
        from netflow_backend.diagnostics import lookup_mac_vendor
        self.assertEqual(lookup_mac_vendor("b8:27:eb:12:34:56"), "Raspberry Pi")
        self.assertEqual(lookup_mac_vendor("f0:18:98:aa:bb:cc"), "Apple")
        self.assertEqual(lookup_mac_vendor("bc:d0:74:00:11:22"), "Google")
        self.assertEqual(lookup_mac_vendor("ff:ff:ff:11:22:33"), "Unknown Vendor")

    def test_notifications_helper(self):
        from netflow_backend.notifications import send_desktop_notification
        # Test that calling notification helper does not raise any exception
        res = send_desktop_notification("Test Title", "Test Message")
        self.assertIsInstance(res, bool)


if __name__ == "__main__":
    unittest.main()
