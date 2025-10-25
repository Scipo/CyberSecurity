"""
    Checking the IPs for threats with AbuseIPDB and FireHOL
"""

import os
import time
import requests
from urllib.parse import urlencode


class ThreatIntelligence:
    """Checking IPs for threat using different APIs"""

    def __init__(self, logger, api_key=None):
        self.logger = logger
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update(
            {
                'User-Agent': 'NetworkThreatAnalyzer/1.0',
                'Accept': 'application/json'
            }
        )

    # Checking IPs
    def check_ips(self, ips):
        result = {}
        for ip in ips:
            self.logger.debug(f"Checking IP: {ip}")
            res = {
                'ip': ip,
                'checks_performed': [],
                'is_malicious': False,
                'threat_level': 'low',
                'details': {}
            }

            # checking with AbuseIPDB
            if self.api_key:
                abuse_result = self._check_abuseipdb(ip)
                res['checks_performed'].append('abuseipdb')
                res['details']['abuseipdb'] = abuse_result

                if abuse_result.get('abuseConfidenceScore', 0) > 25:
                    res['is_malicious'] = True
                    res['threat_level'] = 'medium' if abuse_result['abuseConfidenceScore'] <= 75 else 'high'

            # checking FireHOL Ip black list
            firehol_res = self._check_firehol(ip)
            res['checks_performed'].append('firehol')
            res['details']['firehol'] = firehol_res

            if firehol_res.get('listed', False):
                res['is_malicious'] = True
                res['threat_level'] = 'high'

            result[ip] = res

            time.sleep(0.5)

        return result

    #  Check Ip against AbuseIPDB
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
                return {
                    'error': f"API returned status {response.status_code}"
                }
        except Exception as e:
            self.logger.error(f"AbuseIPDB check failed for {ip}: {str(e)}")
            return {'error': str(e)}

    # Check Ip against FireHOL black list
    def _check_firehol(self, ip):
        try:
            blocklist = [
                'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
                'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset'
            ]

            for lists in blocklist:
                resource = self.session.get(lists, timeout=15)
                if resource.status_code == 200:
                    if ip in resource.text:
                        return {
                            'listed': True,
                            'blocklist': lists.split('/')[-1],
                            'description': 'IP found in FireHOL blocklist'
                        }

            return {'listed': False}

        except Exception as e:
            self.logger.error(f"FireHOL check failed for {ip}: {str(e)}")
            return {'error': str(e)}
