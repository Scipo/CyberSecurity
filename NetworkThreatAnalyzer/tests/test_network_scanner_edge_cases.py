"""
Edge case tests for Network Scanner
"""

import unittest
import logging
import ipaddress
from unittest.mock import patch
from src.network_scanner import NetworkScanner

class TestNetworkScannerEdgeCases(unittest.TestCase):

    def setUp(self):
        self.logger = logging.getLogger()

    def test_ip_validation_edge_cases(self):
        """Test IP validation with edge cases."""
        scanner = NetworkScanner(self.logger)

        # All these should be VALID IP addresses
        valid_ips = [
            '8.8.8.8',           # public
            '1.1.1.1',           # public
            '192.168.1.1',       # private but VALID
            '10.0.0.1',          # private but VALID
            '172.16.0.1',        # private but VALID
            '127.0.0.1',         # localhost but VALID
            '255.255.255.255',   # broadcast but VALID
            '0.0.0.0',           # unspecified but VALID
        ]

        # All these should be INVALID IP addresses
        invalid_ips = [
            '999.999.999.999',   # out of range
            '192.168.1.256',     # out of range
            '10.0.0.',           # incomplete
            '192.168.1',         # incomplete
            'not.an.ip.at.all',  # not an IP
            '',                  # empty
            '192.168.1.1.1',     # too many octets
            '192.168.1.',        # trailing dot
        ]

        # Test valid IPs
        for ip in valid_ips:
            with self.subTest(ip=ip, expected=True):
                result = scanner._is_valid_ip(ip)
                self.assertTrue(result, f"IP: {ip} should be valid")

        # Test invalid IPs
        for ip in invalid_ips:
            with self.subTest(ip=ip, expected=False):
                result = scanner._is_valid_ip(ip)
                self.assertFalse(result, f"IP: {ip} should be invalid")

    def test_private_ip_detection_reliable(self):
        """Test private IP detection with reliable test cases."""
        scanner = NetworkScanner(self.logger)

        # Private IP addresses (should return True for _is_private_ip)
        private_ips = [
            '10.0.0.1',
            '10.255.255.255',
            '172.16.0.1',
            '172.31.255.255',
            '192.168.1.1',
            '192.168.255.255',
            '127.0.0.1',
            '169.254.0.1',
        ]

        # Well-known public IP addresses (should return False for _is_private_ip)
        public_ips = [
            '8.8.8.8',           # Google DNS
            '1.1.1.1',           # Cloudflare DNS
            '208.67.222.222',    # OpenDNS
            '9.9.9.9',           # Quad9 DNS
            '64.6.64.6',         # Verisign DNS
        ]

        # Test private IPs
        for ip in private_ips:
            with self.subTest(ip=ip, expected_private=True):
                result = scanner._is_private_ip(ip)
                self.assertTrue(result, f"IP: {ip} should be detected as private")

        # Test public IPs
        for ip in public_ips:
            with self.subTest(ip=ip, expected_private=False):
                result = scanner._is_private_ip(ip)
                self.assertFalse(result, f"IP: {ip} should be detected as public")

    def test_extract_public_ips_functionality(self):
        """Test the main functionality - extracting public IPs from mixed data."""
        scanner = NetworkScanner(self.logger)

        network_data = {
            '192.168.1.1': [{'protocol': 'tcp'}],      # private
            '10.0.0.1': [{'protocol': 'tcp'}],         # private
            '172.16.0.1': [{'protocol': 'tcp'}],       # private
            '8.8.8.8': [{'protocol': 'tcp'}],          # public
            '1.1.1.1': [{'protocol': 'tcp'}],          # public
            '127.0.0.1': [{'protocol': 'tcp'}],        # localhost (private)
        }

        public_ips = scanner.extract_public_ips(network_data)

        # Should only contain the public IPs
        self.assertEqual(len(public_ips), 2)
        self.assertIn('8.8.8.8', public_ips)
        self.assertIn('1.1.1.1', public_ips)
        self.assertNotIn('192.168.1.1', public_ips)
        self.assertNotIn('10.0.0.1', public_ips)
        self.assertNotIn('172.16.0.1', public_ips)
        self.assertNotIn('127.0.0.1', public_ips)

if __name__ == '__main__':
    unittest.main()