"""
Configuration settings for Network Threat Analyzer
"""

# API Configuration

# AbuseIPDB
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

# Firehol
FIREHOL_BLOCKLISTS = [
    'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
    'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset',
    'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset'
]

# Application Settings
SCAN_TIMEOUT = 30
API_RATE_LIMIT_DELAY = 0.5  # seconds between API calls
MAX_IPS_TO_CHECK = 100

# Logging Configuration
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
