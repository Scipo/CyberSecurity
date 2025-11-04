"""
 Caching
"""

import json
import time
import hashlib
import os
from opcode import opname
from pathlib import Path
from functools import lru_cache
from datetime import datetime, timedelta




class ThreatIntelligenceCache:

    def __init__(self, cache_dir=None, ttl_hours=24):
        self.cache_dir = cache_dir or Path.home() / '.network_threat_analyzer' / 'cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600

    # Generate cache key for IP
    def _get_cache_key(self, ip):
        return hashlib.md5(ip.encode()).hexdigest()

    # Get cache file path for IP
    def _get_cache_file(self, ip):
        cache_key = self._get_cache_key(ip)
        return self.cache_dir / f"{cache_key}.json"

    # Get cache result for IP
    def get_cache_result_ip(self, ip):
        cache_file = self._get_cache_file(ip)

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)

            # chacking if the cache is still valid
            cache_time = datetime.fromtimestamp(cache_data['timestamp'])
            if (datetime.now() - cache_time).total_seconds() > self.ttl_seconds:
                # cache expired
                cache_file.unlink()
                return None
            return cache_data['data']
        except (json.JSONDecodeError, KeyError, IOError):
            # Corrupted cache file, remove it
            if cache_file.exists():
                cache_file.unlink()
            return None

    # Cache result for IP
    def set_cache_result_ip(self, ip, data):
        cache_file = self._get_cache_file(ip)
        try:
            cache_data = {
                'timestamp': datetime.now().isoformat(),
                'data': data
            }

            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)

            return True
        except IOError:
            return False

    # clear expired cache entries
    def clear_expired(self):
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r') as f:
                        cached_data = json.load(f)

                    cached_time = datetime.fromisoformat(cached_data['timestamp'])
                    if (datetime.now() - cached_time).total_seconds() > self.ttl_seconds:
                        cache_file.unlink()
                except (json.JSONDecodeError, KeyError, IOError):
                    # remove the corrupt file
                    cache_file.unlink()
        except Exception as e:
            print(f"Error clearing expired cache: {e}")


    def clear_all(self):
        # clear all cache entries
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
            return True
        except Exception as e:
            print(f"Error clearing cache: {e}")
            return False


# Global cache instance
cache = ThreatIntelligenceCache
