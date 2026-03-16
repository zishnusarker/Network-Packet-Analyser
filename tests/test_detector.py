"""
test_detector.py - Unit Tests for Threat Detection Engine
==========================================================

Tests each detection module with simulated packet data.
These tests verify detection logic WITHOUT requiring actual
network capture (no root privileges needed).

RUN TESTS:
    python3 -m pytest tests/test_detector.py -v
    OR
    python3 tests/test_detector.py

WHY TESTING MATTERS IN SECURITY TOOLS:
- False negatives (missed attacks) = security breach
- False positives (false alarms) = alert fatigue → analysts ignore real alerts
- Threshold tuning requires reproducible test scenarios
- Regression testing ensures updates don't break existing detection
"""

import sys
import os
import time
import unittest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.detector import ThreatDetector
from modules.utils import calculate_entropy, is_suspicious_domain


class TestEntropy(unittest.TestCase):
    """Test Shannon entropy calculation used in DGA detection."""

    def test_empty_string(self):
        """Empty string should have zero entropy."""
        self.assertEqual(calculate_entropy(""), 0.0)

    def test_single_char(self):
        """Repeated single character = zero entropy (completely predictable)."""
        self.assertEqual(calculate_entropy("aaaaaaa"), 0.0)

    def test_low_entropy(self):
        """Normal words should have moderate entropy."""
        entropy = calculate_entropy("google")
        self.assertGreater(entropy, 1.0)
        self.assertLess(entropy, 3.0)

    def test_high_entropy(self):
        """Random strings should have high entropy (DGA-like)."""
        entropy = calculate_entropy("xk4mq9v2a3b7z8")
        self.assertGreater(entropy, 3.0)

    def test_domain_names(self):
        """Normal domains should have lower entropy than DGA domains."""
        normal = calculate_entropy("google")
        dga = calculate_entropy("xk4mq9v2a3")
        self.assertLess(normal, dga)


class TestSuspiciousDomain(unittest.TestCase):
    """Test domain analysis for DGA and tunneling indicators."""

    def test_normal_domain(self):
        """Normal domains should not be flagged."""
        suspicious, reasons = is_suspicious_domain("www.google.com")
        self.assertFalse(suspicious)

    def test_long_subdomain(self):
        """Very long subdomains suggest DNS tunneling."""
        # Simulate encoded data in subdomain
        long_domain = "a" * 60 + ".evil.com"
        suspicious, reasons = is_suspicious_domain(long_domain)
        self.assertTrue(suspicious)
        self.assertTrue(any("Long subdomain" in r for r in reasons))

    def test_high_entropy_domain(self):
        """High-entropy domains suggest DGA."""
        suspicious, reasons = is_suspicious_domain(
            "xk4mq9v2a3b7.evil.com",
            entropy_threshold=3.0
        )
        self.assertTrue(suspicious)

    def test_normal_subdomain(self):
        """Normal subdomains should pass."""
        suspicious, reasons = is_suspicious_domain("mail.google.com")
        self.assertFalse(suspicious)


class TestPortScanDetection(unittest.TestCase):
    """Test port scan detection logic."""

    def setUp(self):
        """Create a detector with low thresholds for testing."""
        self.config = {
            "detection": {
                "port_scan": {
                    "enabled": True,
                    "threshold": 5,      # Low threshold for testing
                    "time_window": 60
                },
                "arp_spoof": {"enabled": False},
                "dns_analysis": {"enabled": False},
                "brute_force": {"enabled": False},
                "data_exfiltration": {"enabled": False},
                "icmp_anomaly": {"enabled": False}
            }
        }
        self.detector = ThreatDetector(self.config)

    def _make_tcp_packet(self, src_ip, dst_ip, dst_port, flags="SYN"):
        """Create a simulated parsed TCP packet."""
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "layers": ["Ethernet", "IP", "TCP"],
            "size": 60,
            "ip": {"src": src_ip, "dst": dst_ip},
            "transport": {
                "type": "TCP",
                "src_port": 45000,
                "dst_port": dst_port,
                "flags": flags,
                "payload_size": 0
            },
            "application": {}
        }

    def test_no_alert_below_threshold(self):
        """Fewer ports than threshold should not trigger alert."""
        for port in range(1, 4):  # 3 ports, threshold is 5
            packet = self._make_tcp_packet("10.0.0.1", "192.168.1.1", port)
            alerts = self.detector.analyze(packet)
            self.assertEqual(len(alerts), 0)

    def test_alert_above_threshold(self):
        """More ports than threshold should trigger alert."""
        alerts_found = []
        for port in range(1, 10):  # 9 ports, threshold is 5
            packet = self._make_tcp_packet("10.0.0.1", "192.168.1.1", port)
            alerts = self.detector.analyze(packet)
            alerts_found.extend(alerts)
        
        self.assertTrue(len(alerts_found) > 0)
        self.assertEqual(alerts_found[0]["type"], "PORT_SCAN")
        self.assertEqual(alerts_found[0]["severity"], "HIGH")

    def test_different_sources_independent(self):
        """Port scans from different sources should be tracked independently."""
        # Source A: scans 3 ports (below threshold)
        for port in range(1, 4):
            packet = self._make_tcp_packet("10.0.0.1", "192.168.1.1", port)
            self.detector.analyze(packet)
        
        # Source B: scans 3 ports (below threshold)
        alerts_found = []
        for port in range(1, 4):
            packet = self._make_tcp_packet("10.0.0.2", "192.168.1.1", port)
            alerts = self.detector.analyze(packet)
            alerts_found.extend(alerts)
        
        # Neither should trigger (both below threshold of 5)
        self.assertEqual(len(alerts_found), 0)


class TestARPSpoofDetection(unittest.TestCase):
    """Test ARP spoofing detection logic."""

    def setUp(self):
        self.config = {
            "detection": {
                "port_scan": {"enabled": False},
                "arp_spoof": {
                    "enabled": True,
                    "trusted_mappings": {
                        "192.168.1.1": "aa:bb:cc:dd:ee:ff"
                    }
                },
                "dns_analysis": {"enabled": False},
                "brute_force": {"enabled": False},
                "data_exfiltration": {"enabled": False},
                "icmp_anomaly": {"enabled": False}
            }
        }
        self.detector = ThreatDetector(self.config)

    def _make_arp_reply(self, sender_ip, sender_mac):
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "layers": ["Ethernet", "ARP"],
            "size": 42,
            "arp": {
                "operation": "reply",
                "op_code": 2,
                "sender_ip": sender_ip,
                "sender_mac": sender_mac,
                "target_ip": "192.168.1.100",
                "target_mac": "11:22:33:44:55:66"
            }
        }

    def test_normal_arp(self):
        """First ARP reply for an IP should not trigger alert."""
        packet = self._make_arp_reply("192.168.1.50", "ab:cd:ef:12:34:56")
        alerts = self.detector.analyze(packet)
        self.assertEqual(len(alerts), 0)

    def test_trusted_mapping_violation(self):
        """ARP reply contradicting trusted mapping should trigger CRITICAL alert."""
        # Attacker claims to be gateway (192.168.1.1) with different MAC
        packet = self._make_arp_reply("192.168.1.1", "66:77:88:99:aa:bb")
        alerts = self.detector.analyze(packet)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "ARP_SPOOF")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_mac_change_detection(self):
        """MAC address change for known IP should trigger alert."""
        # First, establish normal mapping
        packet1 = self._make_arp_reply("192.168.1.50", "ab:cd:ef:12:34:56")
        self.detector.analyze(packet1)
        
        # Now, different MAC claims same IP = spoofing
        packet2 = self._make_arp_reply("192.168.1.50", "99:88:77:66:55:44")
        alerts = self.detector.analyze(packet2)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "ARP_SPOOF")


class TestBruteForceDetection(unittest.TestCase):
    """Test brute force login detection."""

    def setUp(self):
        self.config = {
            "detection": {
                "port_scan": {"enabled": False},
                "arp_spoof": {"enabled": False},
                "dns_analysis": {"enabled": False},
                "brute_force": {
                    "enabled": True,
                    "threshold": 5,
                    "time_window": 60,
                    "monitored_ports": [22, 3389]
                },
                "data_exfiltration": {"enabled": False},
                "icmp_anomaly": {"enabled": False}
            }
        }
        self.detector = ThreatDetector(self.config)

    def _make_syn_packet(self, src_ip, dst_ip, dst_port):
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "layers": ["Ethernet", "IP", "TCP"],
            "size": 60,
            "ip": {"src": src_ip, "dst": dst_ip},
            "transport": {
                "type": "TCP",
                "src_port": 50000,
                "dst_port": dst_port,
                "flags": "SYN",
                "payload_size": 0
            },
            "application": {}
        }

    def test_ssh_brute_force(self):
        """Multiple SSH connection attempts should trigger alert."""
        alerts_found = []
        for i in range(8):  # 8 attempts, threshold is 5
            packet = self._make_syn_packet("10.0.0.1", "192.168.1.1", 22)
            alerts = self.detector.analyze(packet)
            alerts_found.extend(alerts)
        
        self.assertTrue(len(alerts_found) > 0)
        self.assertEqual(alerts_found[0]["type"], "BRUTE_FORCE")

    def test_non_monitored_port(self):
        """Connections to non-monitored ports should not trigger."""
        for i in range(10):
            packet = self._make_syn_packet("10.0.0.1", "192.168.1.1", 80)
            alerts = self.detector.analyze(packet)
            self.assertEqual(len(alerts), 0)


class TestICMPDetection(unittest.TestCase):
    """Test ICMP anomaly detection."""

    def setUp(self):
        self.config = {
            "detection": {
                "port_scan": {"enabled": False},
                "arp_spoof": {"enabled": False},
                "dns_analysis": {"enabled": False},
                "brute_force": {"enabled": False},
                "data_exfiltration": {"enabled": False},
                "icmp_anomaly": {
                    "enabled": True,
                    "flood_threshold": 10,
                    "flood_window": 10,
                    "max_packet_size": 500
                }
            }
        }
        self.detector = ThreatDetector(self.config)

    def _make_icmp_packet(self, src_ip, payload_size=64):
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "layers": ["Ethernet", "IP", "ICMP"],
            "size": 84,
            "ip": {"src": src_ip, "dst": "192.168.1.1"},
            "icmp": {
                "type": 8,
                "code": 0,
                "type_name": "Echo Request",
                "payload_size": payload_size
            }
        }

    def test_oversized_icmp(self):
        """Oversized ICMP packets should trigger alert."""
        packet = self._make_icmp_packet("10.0.0.1", payload_size=1000)
        alerts = self.detector.analyze(packet)
        
        oversized_alerts = [a for a in alerts if a["type"] == "ICMP_OVERSIZED"]
        self.assertTrue(len(oversized_alerts) > 0)

    def test_normal_icmp(self):
        """Normal-sized ICMP should not trigger oversized alert."""
        packet = self._make_icmp_packet("10.0.0.1", payload_size=64)
        alerts = self.detector.analyze(packet)
        
        oversized_alerts = [a for a in alerts if a["type"] == "ICMP_OVERSIZED"]
        self.assertEqual(len(oversized_alerts), 0)


# ──────────────────────────────────────────────────────────
# RUN TESTS
# ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  Network Packet Analyzer - Unit Tests")
    print("  Testing threat detection engine...")
    print("=" * 60 + "\n")
    
    unittest.main(verbosity=2)
