"""
Network scanner
"""
import json
import os
import re
import platform
import ipaddress
import subprocess
from collections import defaultdict


class NetworkScanner:
    def __init__(self, logger):
        self.logger = logger
        self.system = platform.system().lower()

    def get_network_info(self):
        try:
            if self.system == 'windows':
                return self._scan_windows()
            elif self.system == 'darwin':
                return self._scan_macos()
            elif self.system == 'linux':
                return self._scan_linux()
            else:
                self.logger.error(f"Unsupported operating system: {self.system}")
                return {}
        except Exception as e:
            self.logger.error(f"Error gathering network info: {str(e)}")
            return {}

    def _scan_windows(self):
        """Information for Windows"""
        connection = defaultdict(list)
        try:
            res = subprocess.run(
                ['netstat', '-n', '-o'],
                capture_output=True, text=True, timeout=30
            )
            if res.returncode == 0:
                for line in res.stdout.split('\n'):
                    if 'ESTABLISHED' in line or 'LISTENING' in line:
                        # Parce the output
                        parts = line.split()
                        if len(parts) >= 4:
                            proto = parts[0]
                            local_addr = parts[1]
                            foreign_addr = parts[2]
                            state = parts[3] if len(parts) >= 3 else 'UNKNOWN'

                            # Extract Ip from address(IP:PORT)
                            foreign_ip = foreign_addr.split(":")[0]
                            if self._is_valid_ip(foreign_ip):
                                connection[foreign_ip].append(
                                    {
                                        'protocol': proto,
                                        'local_address': local_addr,
                                        'foreign_address': foreign_addr,
                                        'state': state,
                                        'source': 'netstat'
                                    }
                                )
            self._get_windows_logs(connection)
        except subprocess.TimeoutExpired:
            self.logger.warning("Netstat command timed out")
        except Exception as e:
            self.logger.error(f"Windows scan error: {str(e)}")

        return dict(connection)

    def _scan_macos(self):
        """Collect information for MACOS"""
        connection = defaultdict(list)
        try:
            res = subprocess.run(
                ['netstat', '-n', '-p', 'tcp'],
                capture_output=True, text=True, timeout=30
            )
            if res.returncode == 0:
                for line in res.stdout.split('\n'):
                    if 'ESTABLISHED' in line:
                        # Parce the output
                        parts = line.split()
                        if len(parts) >= 4:
                            proto = 'tcp'
                            local_addr = parts[3]
                            foreign_addr = parts[4]

                            # Extract Ip from address(IP:PORT)
                            foreign_ip = foreign_addr.split(".")[:4]
                            foreign_ip = '.'.join(foreign_ip) if len(foreign_ip) == 4 else foreign_addr
                            if self._is_valid_ip(foreign_ip):
                                connection[foreign_ip].append(
                                    {
                                        'protocol': proto,
                                        'local_address': local_addr,
                                        'foreign_address': foreign_addr,
                                        'state': 'ESTABLISHED',
                                        'source': 'netstat'
                                    }
                                )
            self._get_macos_lsof(connection)
            self._get_macos_logs(connection)
        except Exception as e:
            self.logger.error(f"MACOS scan error: {str(e)}")

        return dict(connection)

    # Scan for Linux using /proc filesystem
    def _scan_linux(self):

        connections = defaultdict(list)

        try:
            # Parse TCP connections (IPv4)
            self._parse_proc_net_file('/proc/net/tcp', 'tcp', connections)

            # Parse TCP connections (IPv6)
            self._parse_proc_net_file('/proc/net/tcp6', 'tcp6', connections)

            # Parse UDP connections (IPv4)
            self._parse_proc_net_file('/proc/net/udp', 'udp', connections)

            # Parse UDP connections (IPv6)
            self._parse_proc_net_file('/proc/net/udp6', 'udp6', connections)

            # Get additional logs if needed
            self._get_linux_logs(connections)

        except Exception as e:
            self.logger.error(f"Linux scan error: {str(e)}")

        return dict(connections)

    # Parse /proc/net files for network connections
    def _parse_proc_net_file(self, filename, protocol, connections):
        try:
            if not os.path.exists(filename):
                self.logger.debug(f"File not found: {filename}")
                return

            with open(filename, 'r') as f:
                lines = f.readlines()

            # Skip the header line
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) >= 10:
                    # Extract connection information
                    local_addr_hex = parts[1]  # local_address:port in hex
                    remote_addr_hex = parts[2]  # remote_address:port in hex
                    state_hex = parts[3]  # connection state in hex
                    uid = parts[7]  # user ID
                    inode = parts[9]  # inode number

                    # Convert hex addresses to IP:port format
                    local_info = self._hex_to_ip_port(local_addr_hex)
                    remote_info = self._hex_to_ip_port(remote_addr_hex)
                    state = self._get_connection_state(state_hex)

                    if (remote_info and local_info and
                            self._is_valid_ip(remote_info['ip']) and
                            state in ['ESTABLISHED', 'LISTEN']):
                        connections[remote_info['ip']].append({
                            'protocol': protocol,
                            'local_address': f"{local_info['ip']}:{local_info['port']}",
                            'foreign_address': f"{remote_info['ip']}:{remote_info['port']}",
                            'state': state,
                            'uid': uid,
                            'inode': inode,
                            'source': filename
                        })

        except Exception as e:
            self.logger.error(f"Error parsing {filename}: {str(e)}")

    # Convert hex string to IP address and port
    def _hex_to_ip_port(self, hex_str):
        try:
            if ':' not in hex_str:
                return None

            hex_addr, hex_port = hex_str.split(':')

            # Handle IPv4 addresses (8 characters)
            if len(hex_addr) == 8:
                # Convert little-endian hex to IP address
                ip_parts = []
                for i in range(0, 8, 2):
                    hex_byte = hex_addr[i:i + 2]
                    ip_parts.append(str(int(hex_byte, 16)))
                ip = '.'.join(reversed(ip_parts))

            # Handle IPv6 addresses (32 characters)
            elif len(hex_addr) == 32:
                # For IPv6 in /proc, it's stored as 8 groups of 4 hex chars
                # The format is big-endian per 16-bit word
                ip_parts = []
                for i in range(0, 32, 4):
                    hex_word = hex_addr[i:i + 4]
                    # Convert the 4-character hex to a 16-bit integer
                    word_value = int(hex_word, 16)
                    # Convert back to hex without leading zeros
                    if word_value == 0:
                        ip_parts.append('0')
                    else:
                        ip_parts.append(hex(word_value)[2:])

                ip = ':'.join(ip_parts)
                ip = self._compress_ipv6_simple(ip)

            else:
                return None

            # Convert port from hex to decimal
            port = str(int(hex_port, 16))

            return {'ip': ip, 'port': port}

        except Exception as e:
            self.logger.debug(f"Error converting hex {hex_str}: {str(e)}")
            return None

    def _compress_ipv6_simple(self, ipv6):
        if ipv6 == '0:0:0:0:0:0:0:0':
            return '::'

        # Handle all zeros case
        parts = ipv6.split(':')

        # Find the longest consecutive sequence of '0'
        max_start = -1
        max_length = 0
        current_start = -1
        current_length = 0

        for i, part in enumerate(parts):
            if part == '0':
                if current_start == -1:
                    current_start = i
                current_length += 1
            else:
                if current_length > max_length:
                    max_start = current_start
                    max_length = current_length
                current_start = -1
                current_length = 0

        # Check if the sequence continues to the end
        if current_length > max_length:
            max_start = current_start
            max_length = current_length

        # Compress the longest sequence of zeros
        if max_length > 1:
            if max_start == 0 and max_length == 8:
                return '::'
            elif max_start == 0:
                # Leading zeros: ::1:2:3:4:5:6:7
                return '::' + ':'.join(parts[max_length:])
            elif max_start + max_length == 8:
                # Trailing zeros: 1:2:3:4:5:6:7::
                return ':'.join(parts[:max_start]) + '::'
            else:
                # Middle zeros: 1:2::5:6:7:8
                return ':'.join(parts[:max_start]) + '::' + ':'.join(parts[max_start + max_length:])

        return ipv6

    def _get_connection_state(self, state_hex):
        state_map = {
            '01': 'ESTABLISHED',
            '02': 'SYN_SENT',
            '03': 'SYN_RECV',
            '04': 'FIN_WAIT1',
            '05': 'FIN_WAIT2',
            '06': 'TIME_WAIT',
            '07': 'CLOSE',
            '08': 'CLOSE_WAIT',
            '09': 'LAST_ACK',
            '0A': 'LISTEN',
            '0B': 'CLOSING'
        }
        return state_map.get(state_hex.upper(), f'UNKNOWN({state_hex})')



    # Getting Windows, MACOS and Linux logs
    # Windows
    def _get_windows_logs(self, connections):
        """Getting Windows logs for network connection"""
        try:
            res = subprocess.run(
                ['powershell',
                 'Get-NetTCPConnection | Select-Object LocalAddress,RemoteAddress,State | ConvertTo-Json'],
                capture_output=True,
                text=True,
                timeout=20
            )
            if res.returncode == 0 and res.stdout.strip():
                try:
                    data = json.loads(res.stdout)
                    for con in data:
                        remote_ip = con.get('RemoteAddress', '')
                        if remote_ip and self._is_valid_ip(remote_ip):
                            connections[remote_ip].append(
                                {
                                    'protocol': 'tcp',
                                    'local_address': con.get('LocalAddress', ''),
                                    'foreign_address': remote_ip,
                                    'state': con.get('State', 'UNKNOWN'),
                                    'source': 'powershell'
                                }
                            )
                except json.JSONDecodeError:
                    pass

        except Exception as e:
            self.logger.debug(f"Could not get Windows logs: {str(e)}")

    # MAC OS
    def _get_macos_lsof(self, connections):
        """Get network connection for macOS."""
        try:
            result = subprocess.run(
                ['lsof', '-i', '-n', '-P'],
                capture_output=True, text=True, timeout=20
            )

            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 9 and '->' in parts[8]:
                        # Parse lsof output: process -> IP:PORT->IP:PORT
                        connection = parts[8]
                        if '->' in connection:
                            _, remote_part = connection.split('->', 1)
                            remote_ip = remote_part.split(':')[0]

                            if self._is_valid_ip(remote_ip):
                                connections[remote_ip].append({
                                    'protocol': parts[7],
                                    'process': parts[0],
                                    'pid': parts[1],
                                    'foreign_address': remote_part,
                                    'source': 'lsof'
                                })
        except Exception as e:
            self.logger.debug(f"Could not get lsof info: {str(e)}")

    def _get_macos_logs(self, connections):
        """Parsing MACOS logs for network connection"""
        log_commands = [
            # Try log command for recent network activity
            ['log', 'show', '--predicate', 'subsystem == "network"', '--last', '1h', '--info'],
            # Try system.log files
            ['grep', '-E', '(network|connection|connect|ESTABLISHED)', '/var/log/system.log'],
            # Try application firewall logs
            ['grep', '-E', '(allow|deny|block)', '/var/log/appfirewall.log'],
        ]

        for cmd in log_commands:
            try:
                res = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=15
                )

                if res.returncode == 0 and res.stdout.strip():
                    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                    ips = re.findall(ip_pattern, res.stdout)
                    for ip in set(ips):
                        if self._is_valid_ip(ip) and not self._is_private_ip(ip):
                            if ip not in connections:
                                connections[ip] = []
                            connections[ip].append({
                                'protocol': 'unknown',
                                'source': f'macos_log:{cmd[0]}',
                                'timestamp': 'recent',
                                'log_context': 'found in macOS system logs'
                            })
            except subprocess.TimeoutExpired:
                self.logger.debug(f"Log command timed out: {cmd[0]}")
                continue
            except FileNotFoundError:
                self.logger.debug(f"Log command not available: {cmd[0]}")
            except Exception as e:
                self.logger.debug(f"Could not read macOS logs with {cmd[0]}: {str(e)}")
                continue

    def _get_linux_logs(self, connections):
        """Parsing Linux system logs for network connection"""

        log_files = [
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/auth.log'
        ]
        for log in log_files:
            try:
                res = subprocess.run(
                    ['test', '-f', log],
                    capture_output=True,
                    timeout=5
                )
                if res.returncode != 0:
                    continue

                res = subprocess.run(
                    ['grep', '-E', '(Connection|connect|ESTABLISHED|Failed)', log],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if res.returncode == 0:
                    # ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                    ips = re.findall(ip_pattern, res.stdout)

                    for ip in set(ips):
                        if self._is_valid_ip(ip) and not self._is_private_ip(ip):
                            if ip not in connections:
                                connections[ip] = []
                            connections[ip].append({
                                'protocol': 'unknown',
                                'source': f'log:{log}',
                                'timestamp': 'various',
                                'log_context': 'found in system logs'
                            })
            except  subprocess.TimeoutExpired:
                self.logger.debug(f"Log check timed out for {log}")
                continue
            except Exception as e:
                self.logger.debug(f"Could not read log file {log}: {str(e)}")
                continue

    # Extract public IPs
    def extract_public_ips(self, network_data):
        """Extract public Ips from network"""
        public_ip = set()
        for ip in network_data.keys():
            if self._is_valid_ip(ip) and not self._is_private_ip(ip):
                public_ip.add(ip)
        return list(public_ip)

    def _is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_private_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
