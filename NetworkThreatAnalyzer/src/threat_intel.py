"""
Threat Intelligence Module - Check IPs against various threat intelligence feeds
"""

import os
import requests
import time
from urllib.parse import urlencode


class ThreatIntelligence:
    """Threat intelligence checker using multiple free APIs."""

    def __init__(self, logger, api_key=None):
        self.logger = logger
        self.api_key = api_key or os.getenv('ABUSEIPDB_API_KEY')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'NetworkThreatAnalyzer/1.0',
            'Accept': 'application/json'
        })

    def check_ips(self, ips):
        """Check list of IPs against threat intelligence feeds."""
        results = {}

        for ip in ips:
            self.logger.debug(f"Checking IP: {ip}")
            result = {
                'ip': ip,
                'checks_performed': [],
                'is_malicious': False,
                'threat_level': 'low',
                'details': {}
            }

            # Check AbuseIPDB if API key is available
            if self.api_key:
                abuse_result = self._check_abuseipdb(ip)
                result['checks_performed'].append('abuseipdb')
                result['details']['abuseipdb'] = abuse_result

                if abuse_result.get('abuseConfidenceScore', 0) > 25:
                    result['is_malicious'] = True
                    result['threat_level'] = 'medium' if abuse_result['abuseConfidenceScore'] <= 75 else 'high'

            # Check FireHOL IP blocklist
            firehol_result = self._check_firehol(ip)
            result['checks_performed'].append('firehol')
            result['details']['firehol'] = firehol_result

            if firehol_result.get('listed', False):
                result['is_malicious'] = True
                result['threat_level'] = 'high'

            results[ip] = result

            time.sleep(0.5)

        return results

    # Check IP against AbuseIPDB.
    def _check_abuseipdb(self, ip):
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }

            response = self.session.get(url, params=params, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuseConfidenceScore': data.get('abuseConfidenceScore', 0),
                    'totalReports': data.get('totalReports', 0),
                    'lastReportedAt': data.get('lastReportedAt'),
                    'countryCode': data.get('countryCode'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain')
                }
            else:
                self.logger.warning(f"AbuseIPDB API returned status {response.status_code}")
                return {'error': f"API returned status {response.status_code}"}

        except Exception as e:
            self.logger.error(f"AbuseIPDB check failed for {ip}: {str(e)}")
            return {'error': str(e)}

    # Check Ip against FireHOL blocklists
    def _check_firehol(self, ip):
        try:
            # FireHOL provides various blocklists - we'll check a subset
            blocklists = [
                'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
                'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset'
            ]

            for list_url in blocklists:
                response = self.session.get(list_url, timeout=15)
                if response.status_code == 200:
                    if ip in response.text:
                        return {
                            'listed': True,
                            'blocklist': list_url.split('/')[-1],
                            'description': 'IP found in FireHOL blocklist'
                        }

            return {'listed': False}

        except Exception as e:
            self.logger.error(f"FireHOL check failed for {ip}: {str(e)}")
            return {'error': str(e)}

