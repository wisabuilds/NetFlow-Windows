"""
Unit tests for proc_reader: hex IP/port decoding, /proc/net/dev parsing, and socket structures.
"""

import tempfile
import unittest

from netflow_backend.proc_reader import (
    ProcReader,
    decode_ipv4_hex,
    decode_ipv6_hex,
    parse_ip_port,
)


class TestProcReader(unittest.TestCase):
    def test_decode_ipv4_hex(self):
        # 0100007F in little endian is 127.0.0.1
        self.assertEqual(decode_ipv4_hex("0100007F"), "127.0.0.1")
        # 00000000 is 0.0.0.0
        self.assertEqual(decode_ipv4_hex("00000000"), "0.0.0.0")
        # 08080808 is 8.8.8.8
        self.assertEqual(decode_ipv4_hex("08080808"), "8.8.8.8")

    def test_parse_ip_port(self):
        # 0100007F:1F90 -> 127.0.0.1:8080 (0x1F90 = 8080)
        ip, port = parse_ip_port("0100007F:1F90")
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(port, 8080)

        # 00000000:0050 -> 0.0.0.0:80
        ip, port = parse_ip_port("00000000:0050")
        self.assertEqual(ip, "0.0.0.0")
        self.assertEqual(port, 80)

    def test_decode_ipv6_hex(self):
        # ::1 in Linux /proc/net/tcp6 format: 00000000000000000000000001000000
        # 4 words of 8 chars: 00000000 00000000 00000000 01000000
        # The last word 01000000 in host order is 00 00 00 01 = ::1
        ip = decode_ipv6_hex("00000000000000000000000001000000")
        self.assertEqual(ip, "::1")

    def test_read_interface_stats(self):
        sample_proc_dev = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567       10    0    0    0     0          0         0  1234567       10    0    0    0     0       0          0
  eth0: 9876543       50    1    2    0     0          0         0  5432100       40    0    0    0     0       0          0
"""
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(sample_proc_dev)
            temp_path = f.name

        reader = ProcReader()
        stats = reader.read_interface_stats(proc_net_dev=temp_path)

        self.assertIn("lo", stats)
        self.assertIn("eth0", stats)

        lo = stats["lo"]
        self.assertEqual(lo.rx_bytes, 1234567)
        self.assertEqual(lo.tx_bytes, 1234567)

        eth0 = stats["eth0"]
        self.assertEqual(eth0.rx_bytes, 9876543)
        self.assertEqual(eth0.tx_bytes, 5432100)
        self.assertEqual(eth0.rx_errs, 1)
        self.assertEqual(eth0.rx_drop, 2)


if __name__ == "__main__":
    unittest.main()
