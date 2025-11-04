"""
Caching module for threat intelligence results
"""

import json
import hashlib
from pathlib import Path
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

    # Get cached result for IP.
    def get_cache(self, ip):
        cache_file = self._get_cache_file(ip)

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)

            # Check if cache is still valid
            cache_time = datetime.fromisoformat(cached_data['timestamp'])
            if (datetime.now() - cache_time).total_seconds() > self.ttl_seconds:
                # Cache expired
                cache_file.unlink()
                return None

            return cached_data['data']

        except (json.JSONDecodeError, KeyError, IOError):
            # Corrupted cache file, remove it
            if cache_file.exists():
                cache_file.unlink()
            return None
    # Cache result for IP.
    def set_cache(self, ip, data):

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

    # Clear expired cache entries
    def clear_expired(self):
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r') as f:
                        cached_data = json.load(f)

                    cache_time = datetime.fromisoformat(cached_data['timestamp'])
                    if (datetime.now() - cache_time).total_seconds() > self.ttl_seconds:
                        cache_file.unlink()

                except (json.JSONDecodeError, KeyError, IOError):
                    # Corrupted file, remove it
                    cache_file.unlink()
        except Exception as e:
            print(f"Error clearing expired cache: {e}")

    # Clear all cache entries
    def clear_all(self):

        try:
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
            return True
        except Exception as e:
            print(f"Error clearing cache: {e}")
            return False

# Global cache instance
cache = ThreatIntelligenceCache()

