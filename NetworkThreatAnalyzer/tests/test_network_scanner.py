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

    @patch('builtins.open')
    def test_linux_scan_success(self, mock_file):
        """Test Linux network scanning using /proc filesystem."""
        # Mock /proc/net/tcp content
        mock_tcp_content = """
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0A00000A:8E0C 443D07C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 20 4 30 10 -1
   3: 0A00000A:8E0D 560708C0:0050 01 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 20 4 30 10 -1
"""
        # Mock /proc/net/udp content
        mock_udp_content = """
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12349 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0277 00000000:0000 07 00000000:00000000 00:00000000 00000000   102        0 12350 1 0000000000000000 100 0 0 10 0
"""

        # Configure mock to return different content based on filename
        def mock_open_side_effect(filename, *args, **kwargs):
            if filename == '/proc/net/tcp':
                return mock_open(read_data=mock_tcp_content).return_value
            elif filename == '/proc/net/udp':
                return mock_open(read_data=mock_udp_content).return_value
            elif filename in ['/proc/net/tcp6', '/proc/net/udp6']:
                return mock_open(read_data="").return_value  # Empty for IPv6
            else:
                raise FileNotFoundError(f"File not found: {filename}")

        mock_file.side_effect = mock_open_side_effect

        with patch('platform.system', return_value='Linux'):
            scanner = NetworkScanner(self.logger)
            results = scanner._scan_linux()

        # Should find the established connections from /proc/net/tcp
        # 443D07C0:01BB -> 192.7.61.68:443 (C07D4328 in little-endian -> 192.7.61.68)
        # 560708C0:0050 -> 192.8.7.86:80 (C0070856 in little-endian -> 192.8.7.86)
        self.assertIn('192.7.61.68', results)
        self.assertIn('192.8.7.86', results)

        # Verify connection details
        self.assertEqual(len(results['192.7.61.68']), 1)
        self.assertEqual(results['192.7.61.68'][0]['protocol'], 'tcp')
        self.assertEqual(results['192.7.61.68'][0]['state'], 'ESTABLISHED')

    @patch('builtins.open')
    def test_linux_scan_file_not_found(self, mock_file):
        """Test Linux scanning handles missing /proc files gracefully."""
        mock_file.side_effect = FileNotFoundError("File not found")

        with patch('platform.system', return_value='Linux'):
            scanner = NetworkScanner(self.logger)
            results = scanner._scan_linux()

        self.assertEqual(results, {})

    @patch('builtins.open')
    def test_linux_scan_parsing_error(self, mock_file):
        """Test Linux scanning handles parsing errors gracefully."""
        # Mock malformed /proc content
        mock_file.return_value.__enter__.return_value.readlines.return_value = [
            "malformed line without enough parts",
            "another bad line"
        ]

        with patch('platform.system', return_value='Linux'):
            scanner = NetworkScanner(self.logger)
            results = scanner._scan_linux()

        # Should return empty dict when no valid connections found
        self.assertEqual(results, {})

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

    def test_get_network_info_exception_handling(self):
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

    def test_hex_to_ip_port_conversion(self):
        """Test hexadecimal to IP address and port conversion."""
        # Test IPv4 conversion
        result = self.scanner._hex_to_ip_port('0100007F:0016')
        self.assertEqual(result['ip'], '127.0.0.1')
        self.assertEqual(result['port'], '22')  # 0x0016 = 22

        # Test another IPv4
        result = self.scanner._hex_to_ip_port('443D07C0:01BB')
        self.assertEqual(result['ip'], '192.7.61.68')  # C07D4328 in little-endian
        self.assertEqual(result['port'], '443')  # 0x01BB = 443

    def test_hex_to_ip_port_invalid(self):
        """Test hexadecimal conversion with invalid input."""
        result = self.scanner._hex_to_ip_port('invalid')
        self.assertIsNone(result)

        result = self.scanner._hex_to_ip_port('0100007F')  # Missing port
        self.assertIsNone(result)

    def test_get_connection_state(self):
        """Test connection state conversion from hexadecimal."""
        # Test various TCP states
        self.assertEqual(self.scanner._get_connection_state('01'), 'ESTABLISHED')
        self.assertEqual(self.scanner._get_connection_state('0A'), 'LISTEN')
        self.assertEqual(self.scanner._get_connection_state('06'), 'TIME_WAIT')
        self.assertEqual(self.scanner._get_connection_state('FF'), 'UNKNOWN(FF)')  # Unknown state

    @patch('builtins.open')
    def test_linux_scan_with_ipv6(self, mock_file):
        """Test Linux scanning includes IPv6 connections."""
        # Mock /proc/net/tcp6 content with CORRECT IPv6 hex format
        mock_tcp6_content = """
      sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
       0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
       1: 00000000000000000000000001000000:8E0C 20010DB8000000000000000000000001:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 4 30 10 -1
    """

        # Mock other proc files as empty
        def mock_open_side_effect(filename, *args, **kwargs):
            if filename == '/proc/net/tcp':
                return mock_open(read_data="").return_value
            elif filename == '/proc/net/tcp6':
                return mock_open(read_data=mock_tcp6_content).return_value
            elif filename in ['/proc/net/udp', '/proc/net/udp6']:
                return mock_open(read_data="").return_value
            else:
                raise FileNotFoundError(f"File not found: {filename}")

        mock_file.side_effect = mock_open_side_effect

        with patch('platform.system', return_value='Linux'):
            scanner = NetworkScanner(self.logger)
            results = scanner._scan_linux()

        # Should find IPv6 connection (20010DB8000000000000000000000001 -> 2001:db8::1)
        ipv6_key = '2001:db8::1'
        self.assertIn(ipv6_key, results)
        self.assertEqual(results[ipv6_key][0]['protocol'], 'tcp6')
        self.assertEqual(results[ipv6_key][0]['state'], 'ESTABLISHED')

    @patch('builtins.open')
    def test_linux_scan_multiple_protocols(self, mock_file):
        """Test Linux scanning across multiple protocol files."""

        # Mock different content for each protocol file with CORRECT hex IPs
        def mock_open_side_effect(filename, *args, **kwargs):
            if filename == '/proc/net/tcp':
                return mock_open(read_data="""
      sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
       0: 0100007F:0016 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 20 4 30 10 -1
    """).return_value
            elif filename == '/proc/net/udp':
                return mock_open(read_data="""
      sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
       0: 0100007F:0035 01010101:0050 07 00000000:00000000 00:00000000 00000000   101        0 12348 1 0000000000000000 100 0 0 10 0
    """).return_value
            elif filename in ['/proc/net/tcp6', '/proc/net/udp6']:
                return mock_open(read_data="").return_value
            else:
                raise FileNotFoundError(f"File not found: {filename}")

        mock_file.side_effect = mock_open_side_effect

        with patch('platform.system', return_value='Linux'):
            scanner = NetworkScanner(self.logger)
            results = scanner._scan_linux()

        # Should find connections from both TCP and UDP
        self.assertIn('8.8.8.8', results)  # From TCP (08080808 -> 8.8.8.8)
        self.assertIn('1.1.1.1', results)  # From UDP (01010101 -> 1.1.1.1)

        # Verify protocol differentiation
        tcp_conn = results['8.8.8.8'][0]
        udp_conn = results['1.1.1.1'][0]

        self.assertEqual(tcp_conn['protocol'], 'tcp')
        self.assertEqual(udp_conn['protocol'], 'udp')
        self.assertEqual(tcp_conn['state'], 'ESTABLISHED')
        self.assertEqual(udp_conn['state'], 'CLOSE')  # UDP state 07

    def test_hex_conversion_debug(self):
        """Debug method to test hexadecimal conversion."""
        test_cases = [
            # IPv4 cases
            ('08080808:01BB', '8.8.8.8:443'),
            ('01010101:0050', '1.1.1.1:80'),
            ('443D07C0:01BB', '192.7.61.68:443'),  # C0 07 3D 44 -> 192.7.61.68
            ('560708C0:0050', '192.8.7.86:80'),  # C0 08 07 56 -> 192.8.7.86

            # IPv6 cases
            ('20010DB8000000000000000000000001:01BB', '2001:db8::1:443'),
            ('00000000000000000000000000000000:0016', ':::22'),
            ('00000000000000000000000001000000:8E0C', '::1:36364'),
        ]

        print("\n=== Hex Conversion Debug ===")
        for hex_str, expected in test_cases:
            result = self.scanner._hex_to_ip_port(hex_str)
            if result:
                actual = f"{result['ip']}:{result['port']}"
                status = "✓" if actual == expected else "✗"
                print(f"{status} {hex_str} -> {actual} (expected: {expected})")
            else:
                print(f"✗ {hex_str} -> None (expected: {expected})")

if __name__ == '__main__':
    unittest.main()