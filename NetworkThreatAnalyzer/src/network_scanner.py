"""
Network scanner
"""
import json
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
        except Exception as e:
            self.logger.error(f"Windows scan error: {str(e)}")

        return dict(connection)

    def _scan_linux(self):
        """Collect information for Linux"""
        connection = defaultdict(list)

        try:
            res = subprocess.run(
                ['netstat', '-tun', '-n'],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if res.returncode == 0:
                for line in res.stdout.split('\n'):
                    if 'ESTABLISHED' in line or 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            proto = parts[0]
                            local_addr = parts[3]
                            foreign_addr = parts[4]
                            state = parts[5] if len(parts) >= 5 else 'UNKNOWN'

                            foreign_ip = foreign_addr.split(':')[0]

                            if self._is_valid_ip(foreign_ip):
                                connection[foreign_ip].append({
                                    'protocol': proto,
                                    'local_address': local_addr,
                                    'foreign_address': foreign_ip,
                                    'state': state,
                                    'source': 'netstat'
                                })
            # Check /var/log for connection logs
            self._get_linux_logs(connection)

        except Exception as e:
            self.logger.error(f"Linux scan error: {str(e)}")

        return dict(connection)

    # Getting Windows, MACOS and Linux logs
    # Windows
    def _get_windows_logs(self, connections):
        """Getting Windows logs for network connection"""
        try:
            res = subprocess.run(
                ['powershell','Get-NetTCPConnection | Select-Object LocalAddress,RemoteAddress,State | ConvertTo-Json'],
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
                    ['grep', '-E', '(Connection|connect|ESTABLISHED)', log],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if res.returncode == 0:
                    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    ips = re.findall(ip_pattern, res.stdout)

                    for ip in ips:
                        if self._is_valid_ip(ip) and not self._is_private_ip(ip):
                            connections[ip].append({
                                'protocol': 'unknown',
                                'source': f'log:{log}',
                                'timestamp': 'various'
                            })
            except  Exception:
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
