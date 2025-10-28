"""
Mock tests for Network Scanner functionality
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import platform
from src.network_scanner import NetworkScanner
import logging


class TestNetworkScanner(unittest.TestCase):

    def setUp(self):
        self.logger = logging.getLogger()
        self.scanner = NetworkScanner(self.logger)

    def test_initialization(self):
        """Test scanner initializes with correct OS detection."""
        self.assertEqual(self.scanner.system, platform.system().lower())
        self.assertIsNotNone(self.scanner.logger)

    def test_is_valid_ip(self):
        """Test IP address validation."""
        # Valid IPv4 addresses
        self.assertTrue(self.scanner._is_valid_ip('8.8.8.8'))
        self.assertTrue(self.scanner._is_valid_ip('192.168.1.1'))
        self.assertTrue(self.scanner._is_valid_ip('1.1.1.1'))

        # Valid IPv6 addresses
        self.assertTrue(self.scanner._is_valid_ip('2001:db8::'))
        self.assertTrue(self.scanner._is_valid_ip('::1'))

        # Invalid IP addresses
        self.assertFalse(self.scanner._is_valid_ip('invalid'))
        self.assertFalse(self.scanner._is_valid_ip('256.256.256.256'))
        self.assertFalse(self.scanner._is_valid_ip('192.168.1.256'))
        self.assertFalse(self.scanner._is_valid_ip(''))
        self.assertFalse(self.scanner._is_valid_ip(None))

    def test_is_private_ip(self):
        """Test private IP address detection."""
        # Private IP ranges
        self.assertTrue(self.scanner._is_private_ip('10.0.0.1'))
        self.assertTrue(self.scanner._is_private_ip('172.16.0.1'))
        self.assertTrue(self.scanner._is_private_ip('192.168.1.1'))
        self.assertTrue(self.scanner._is_private_ip('127.0.0.1'))
        self.assertTrue(self.scanner._is_private_ip('169.254.0.1'))

        # Public IP addresses
        self.assertFalse(self.scanner._is_private_ip('8.8.8.8'))
        self.assertFalse(self.scanner._is_private_ip('1.1.1.1'))
        self.assertFalse(self.scanner._is_private_ip('208.67.222.222'))

    def test_extract_public_ips(self):
        """Test extraction of public IPs from network data."""
        test_data = {
            '192.168.1.1': [{'protocol': 'tcp', 'source': 'test'}],  # private
            '10.0.0.1': [{'protocol': 'tcp', 'source': 'test'}],  # private
            '172.16.0.1': [{'protocol': 'tcp', 'source': 'test'}],  # private
            '8.8.8.8': [{'protocol': 'tcp', 'source': 'test'}],  # public
            '1.1.1.1': [{'protocol': 'tcp', 'source': 'test'}],  # public
            '208.67.222.222': [{'protocol': 'tcp', 'source': 'test'}]  # public
        }

        public_ips = self.scanner.extract_public_ips(test_data)

        self.assertEqual(len(public_ips), 3)
        self.assertIn('8.8.8.8', public_ips)
        self.assertIn('1.1.1.1', public_ips)
        self.assertIn('208.67.222.222', public_ips)
        self.assertNotIn('192.168.1.1', public_ips)
        self.assertNotIn('10.0.0.1', public_ips)
        self.assertNotIn('172.16.0.1', public_ips)

    def test_extract_public_ips_empty_data(self):
        """Test extraction with empty network data."""
        public_ips = self.scanner.extract_public_ips({})
        self.assertEqual(len(public_ips), 0)

    def test_extract_public_ips_only_private(self):
        """Test extraction when only private IPs are present."""
        test_data = {
            '192.168.1.1': [{'protocol': 'tcp'}],
            '10.0.0.1': [{'protocol': 'tcp'}],
            '172.16.0.1': [{'protocol': 'tcp'}]
        }

        public_ips = self.scanner.extract_public_ips(test_data)
        self.assertEqual(len(public_ips), 0)

    @patch('subprocess.run')
    def test_windows_scan_success(self, mock_subprocess):
        """Test Windows network scanning with successful command execution."""
        # Mock Windows netstat output
        mock_output = """
    Active Connections

      Proto  Local Address          Foreign Address        State           PID
      TCP    192.168.1.10:49685     8.8.8.8:443           ESTABLISHED     1234
      TCP    192.168.1.10:49686     93.184.216.34:80      ESTABLISHED     1235
      TCP    192.168.1.10:49687     192.168.1.1:443       ESTABLISHED     1236
      UDP    0.0.0.0:123            *:*                                    789
    """
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = mock_output

        with patch('platform.system', return_value='Windows'):
            scanner = NetworkScanner(self.logger)
            results = scanner._scan_windows()

        # The scanner should collect ALL IPs initially
        self.assertIn('8.8.8.8', results)
        self.assertIn('93.184.216.34', results)
        self.assertIn('192.168.1.1', results)  # This SHOULD be included in raw scan results

        # Verify connection details
        self.assertEqual(len(results['8.8.8.8']), 1)
        self.assertEqual(results['8.8.8.8'][0]['protocol'], 'TCP')
        self.assertEqual(results['8.8.8.8'][0]['state'], 'ESTABLISHED')

        # Test that extract_public_ips filters private IPs correctly
        public_ips = scanner.extract_public_ips(results)
        self.assertIn('8.8.8.8', public_ips)
        self.assertIn('93.184.216.34', public_ips)
        self.assertNotIn('192.168.1.1', public_ips)  # This should be filtered out here

    @patch('subprocess.run')
    def test_windows_scan_timeout(self, mock_subprocess):
        """Test Windows scanning handles timeout gracefully."""
        mock_subprocess.side_effect = TimeoutError("Command timed out")

        with patch('platform.system', return_value='Windows'):
            scanner = NetworkScanner(self.logger)
            results = scanner._scan_windows()

        self.assertEqual(results, {})

    @patch('subprocess.run')
    def test_linux_scan_success(self, mock_subprocess):
        """Test Linux network scanning with successful command execution."""
        mock_output = """
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 192.168.1.10:45678      8.8.8.8:443             ESTABLISHED
tcp        0      0 192.168.1.10:45679      1.1.1.1:80              ESTABLISHED
udp        0      0 0.0.0.0:68              0.0.0.0:*                          
"""
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = mock_output

        with patch('platform.system', return_value='Linux'):
            scanner = NetworkScanner(self.logger)
            results = scanner._scan_linux()

        self.assertIn('8.8.8.8', results)
        self.assertIn('1.1.1.1', results)
        self.assertEqual(results['8.8.8.8'][0]['protocol'], 'tcp')
        self.assertEqual(results['8.8.8.8'][0]['state'], 'ESTABLISHED')

    @patch('subprocess.run')
    def test_macos_scan_success(self, mock_subprocess):
        """Test macOS network scanning with successful command execution."""
        mock_output = """
Active Internet connections
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.1.10.63102     8.8.8.8.443            ESTABLISHED
tcp4       0      0  192.168.1.10.63103     1.1.1.1.80             ESTABLISHED
"""
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = mock_output

        with patch('platform.system', return_value='Darwin'):
            scanner = NetworkScanner(self.logger)
            results = scanner._scan_macos()

        self.assertIn('8.8.8.8', results)
        self.assertIn('1.1.1.1', results)

    @patch('subprocess.run')
    def test_unsupported_os(self, mock_subprocess):
        """Test behavior with unsupported operating system."""
        with patch('platform.system', return_value='FreeBSD'):
            scanner = NetworkScanner(self.logger)
            results = scanner.get_network_info()

        self.assertEqual(results, {})

    def test_gaget_network_info_exception_handling(self):
        """Test that exceptions during network scanning are properly handled."""
        with patch.object(NetworkScanner, '_scan_windows', side_effect=Exception("Scan failed")):
            with patch('platform.system', return_value='Windows'):
                scanner = NetworkScanner(self.logger)
                results = scanner.get_network_info()

        self.assertEqual(results, {})

    @patch('subprocess.run')
    @patch('os.path.exists')
    def test_linux_log_parsing_with_mock_files(self, mock_exists, mock_subprocess):
        """Test Linux log parsing with mocked file existence."""
        # Mock that all log files exist
        mock_exists.return_value = True

        # Mock grep output
        mock_grep_output = """
    Jan 1 10:00:00 host sshd[1234]: Connection from 8.8.8.8 port 22
    Jan 1 10:01:00 host kernel: [123] connect to 1.1.1.1:80 ESTABLISHED
    Jan 1 10:02:00 host app[5678]: Failed to connect to 192.168.1.100:443
    """
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = mock_grep_output

        connections = {}
        with patch('platform.system', return_value='Linux'):
            scanner = NetworkScanner(self.logger)
            scanner._get_linux_logs(connections)

        self.assertIn('8.8.8.8', connections)
        self.assertIn('1.1.1.1', connections)
        # Private IP should be filtered out
        self.assertNotIn('192.168.1.100', connections)

    @patch('subprocess.run')
    def test_macos_log_parsing_with_mock_files(self, mock_subprocess):
        """Test macOS log parsing with mocked commands."""

        # Mock log command output with IP addresses
        mock_log_output = """
    2023-01-01 10:00:00.000000-0800 0x12345  Default 0x0 1234 0 kernel: (network) IP packet: 8.8.8.8 -> 192.168.1.10
    2023-01-01 10:01:00.000000-0800 0x12346  Default 0x0 5678 0 syslog: Network connection established to 1.1.1.1:443
    2023-01-01 10:02:00.000000-0800 0x12347  Default 0x0 9101 0 firewall: Blocked connection from 208.67.222.222
    2023-01-01 10:03:00.000000-0800 0x12348  Default 0x0 1121 0 application: Connected to internal server 10.0.0.1
    """

        # Configure the mock to return our test data for ALL subprocess calls
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout=mock_log_output
        )

        connections = {}
        with patch('platform.system', return_value='Darwin'):
            scanner = NetworkScanner(self.logger)
            scanner._get_macos_logs(connections)

        # Debug: print what was found
        print(f"Connections found: {connections}")

        # Should find public IPs
        self.assertIn('8.8.8.8', connections, "8.8.8.8 should be found in macOS logs")
        self.assertIn('1.1.1.1', connections, "1.1.1.1 should be found in macOS logs")
        self.assertIn('208.67.222.222', connections, "208.67.222.222 should be found in macOS logs")
        # Private IP should be filtered out
        self.assertNotIn('10.0.0.1', connections, "10.0.0.1 (private) should be filtered out")

if __name__ == '__main__':
    unittest.main()