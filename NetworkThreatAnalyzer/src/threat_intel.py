"""
Threat Intelligence Module - Check IPs against various threat intelligence feeds with async support
"""

import time
import asyncio
import aiohttp
from config.settings import get_api_key


class ThreatIntelligence:
    """Threat intelligence checker using multiple free APIs with async support."""

    def __init__(self, logger, api_key=None, use_cache=True):
        self.logger = logger
        self.api_key = api_key or get_api_key()
        self.timeout = aiohttp.ClientTimeout(total=10)
        self.use_cache = use_cache
        if use_cache:
            from cache import cache
            self.cache = cache

    async def check_ips_async(self, ips):
        """Check list of IPs against threat intelligence feeds asynchronously."""
        results = {}

        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(5)  # Limit to 5 concurrent requests

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            tasks = []
            for ip in ips:
                task = self._check_ip_async(session, semaphore, ip)
                tasks.append(task)

            # Gather all results
            ip_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for ip, result in zip(ips, ip_results):
                if isinstance(result, Exception):
                    self.logger.error(f"Error checking IP {ip}: {str(result)}")
                    results[ip] = {
                        'ip': ip,
                        'is_malicious': False,
                        'threat_level': 'low',
                        'checks_performed': [],
                        'details': {'error': str(result)}
                    }
                else:
                    results[ip] = result

        return results

    async def _check_ip_async(self, session, semaphore, ip):
        """Check a single IP asynchronously."""
        # check cache first
        if self.use_cache:
            cached_result = self.cache.get_cache(ip)
            if cached_result:
                self.logger.debug(f"Using cached result for {ip}")
                return cached_result

        async with semaphore:
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
                abuse_result = await self._check_abuseipdb_async(session, ip)
                result['checks_performed'].append('abuseipdb')
                result['details']['abuseipdb'] = abuse_result

                if abuse_result.get('abuseConfidenceScore', 0) > 25:
                    result['is_malicious'] = True
                    result['threat_level'] = 'medium' if abuse_result['abuseConfidenceScore'] <= 75 else 'high'

            # Check FireHOL IP blocklist
            firehol_result = await self._check_firehol_async(session, ip)
            result['checks_performed'].append('firehol')
            result['details']['firehol'] = firehol_result

            if firehol_result.get('listed', False):
                result['is_malicious'] = True
                result['threat_level'] = 'high'

            # cache the result
            if self.use_cache:
                self.cache.set_cache(ip, result)

            # Small delay to be nice to APIs
            await asyncio.sleep(0.1)

            return result

    async def _check_abuseipdb_async(self, session, ip):
        """Check IP against AbuseIPDB asynchronously."""
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

            async with session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'abuseConfidenceScore': data.get('data', {}).get('abuseConfidenceScore', 0),
                        'totalReports': data.get('data', {}).get('totalReports', 0),
                        'lastReportedAt': data.get('data', {}).get('lastReportedAt'),
                        'countryCode': data.get('data', {}).get('countryCode'),
                        'isp': data.get('data', {}).get('isp'),
                        'domain': data.get('data', {}).get('domain')
                    }
                else:
                    self.logger.warning(f"AbuseIPDB API returned status {response.status}")
                    return {'error': f"API returned status {response.status}"}

        except asyncio.TimeoutError:
            return {'error': 'Request timeout'}
        except Exception as e:
            self.logger.error(f"AbuseIPDB check failed for {ip}: {str(e)}")
            return {'error': str(e)}

    async def _check_firehol_async(self, session, ip):
        """Check IP against FireHOL blocklists asynchronously."""
        try:
            blocklists = [
                'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
                'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset'
            ]

            for list_url in blocklists:
                async with session.get(list_url) as response:
                    if response.status == 200:
                        text = await response.text()
                        if ip in text:
                            return {
                                'listed': True,
                                'blocklist': list_url.split('/')[-1],
                                'description': 'IP found in FireHOL blocklist'
                            }

            return {'listed': False}

        except Exception as e:
            self.logger.error(f"FireHOL check failed for {ip}: {str(e)}")
            return {'error': str(e)}

    # Keep synchronous version for backward compatibility
    def check_ips(self, ips):
        """Synchronous wrapper for async IP checking."""
        try:
            # Try to use existing event loop, create new one if none exists
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            if loop.is_running():
                # If loop is already running, use synchronous fallback
                self.logger.warning("Event loop already running, using synchronous mode")
                return self._check_ips_sync(ips)
            else:
                # Use async version
                return loop.run_until_complete(self.check_ips_async(ips))
        except Exception as e:
            self.logger.error(f"Async operation failed, falling back to sync: {str(e)}")
            return self._check_ips_sync(ips)

    def _check_ips_sync(self, ips):
        """Synchronous fallback for IP checking."""
        import requests
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
                abuse_result = self._check_abuseipdb_sync(ip)
                result['checks_performed'].append('abuseipdb')
                result['details']['abuseipdb'] = abuse_result

                if abuse_result.get('abuseConfidenceScore', 0) > 25:
                    result['is_malicious'] = True
                    result['threat_level'] = 'medium' if abuse_result['abuseConfidenceScore'] <= 75 else 'high'

            # Check FireHOL IP blocklist
            firehol_result = self._check_firehol_sync(ip)
            result['checks_performed'].append('firehol')
            result['details']['firehol'] = firehol_result

            if firehol_result.get('listed', False):
                result['is_malicious'] = True
                result['threat_level'] = 'high'

            results[ip] = result
            time.sleep(0.5)  # Rate limiting

        return results

    def _check_abuseipdb_sync(self, ip):
        """Synchronous fallback for AbuseIPDB."""
        import requests
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

            response = requests.get(url, params=params, headers=headers, timeout=10)

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

    def _check_firehol_sync(self, ip):
        """Synchronous fallback for FireHOL."""
        import requests
        try:
            blocklists = [
                'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
                'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset'
            ]

            for list_url in blocklists:
                response = requests.get(list_url, timeout=15)
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
