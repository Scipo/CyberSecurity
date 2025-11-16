"""
Enhanced configuration settings for Network Threat Analyzer
"""

import os
import json
import yaml
from pathlib import Path

# Default configuration
DEFAULT_CONFIG = {
    'ABUSEIPDB_API_KEY': '',
    'SCAN_TIMEOUT': 30,
    'API_RATE_LIMIT_DELAY': 0.5,
    'MAX_IPS_TO_CHECK': 100,
    'USE_CACHE': True,
    'CACHE_TTL_HOURS': 24,
    'ENABLE_RICH_OUTPUT': True,
    'ASYNC_MODE': True,
    'CONCURRENT_REQUESTS': 5,
    'LOG_LEVEL': 'INFO',
    'OUTPUT_FORMATS': ['json', 'console'],
    'AUTO_BLOCK_THRESHOLD': 80,
    'NOTIFICATION_EMAIL': '',
    'SCAN_SCHEDULE': 'daily'
}

DEFAULT_CONFIG.update({
    # Web interface settings
    'WEB_HOST': '127.0.0.1',
    'WEB_PORT': 5000,
    'WEB_DEBUG': False,

    # Reporting settings
    'REPORT_FORMATS': ['json', 'html', 'csv'],
    'AUTO_GENERATE_REPORTS': True,
    'REPORT_OUTPUT_DIR': 'reports',

    # Notification settings
    'ENABLE_NOTIFICATIONS': False,
    'NOTIFICATION_EMAILS': [],
    'SLACK_WEBHOOK_URL': '',
    'WEBHOOK_URL': '',

    # SMTP settings for email notifications
    'SMTP': {
        'server': '',
        'port': 587,
        'username': '',
        'password': '',
        'tls': True
    },

    # Alert thresholds
    'ALERT_THRESHOLD_HIGH': 75,
    'ALERT_THRESHOLD_MEDIUM': 25,
    'ALERT_ON_HIGH_THREAT': True,
    'ALERT_ON_MEDIUM_THREAT': False
})

def get_config_dir():
    """Get the configuration directory path."""
    config_dir = Path.home() / '.NetworkThreatAnalyzer'
    config_dir.mkdir(exist_ok=True)
    return config_dir

def get_config_file(formats='json'):
    """Get the configuration file path."""
    config_dir = get_config_dir()
    if formats == 'yaml':
        return config_dir / 'config.yaml'
    else:
        return config_dir / 'config.json'

def load_config():
    """Load configuration from file (supports JSON and YAML)."""
    config_file_json = get_config_file('json')
    config_file_yaml = get_config_file('yaml')

    config = DEFAULT_CONFIG.copy()

    # Try YAML first, then JSON
    if config_file_yaml.exists():
        try:
            with open(config_file_yaml, 'r') as f:
                yaml_config = yaml.safe_load(f)
                if yaml_config:
                    config.update(yaml_config)
                    return config
        except (yaml.YAMLError, IOError) as e:
            print(f"Warning: Could not load YAML configuration: {e}")

    if config_file_json.exists():
        try:
            with open(config_file_json, 'r') as f:
                json_config = json.load(f)
                config.update(json_config)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load JSON configuration: {e}")

    return config

def save_config(config_updates, formats='json'):
    """Save configuration updates to file."""
    try:
        config_file = get_config_file(formats)

        # Load existing config or create new
        existing_config = load_config()

        # Update configuration
        existing_config.update(config_updates)

        # Save to file
        if formats == 'yaml':
            with open(config_file, 'w') as f:
                yaml.dump(existing_config, f, indent=2, default_flow_style=False)
        else:
            with open(config_file, 'w') as f:
                json.dump(existing_config, f, indent=2)

        return True
    except Exception as e:
        print(f"Error saving configuration: {e}")
        return False

def validate_config(config):
    """Validate configuration values."""
    errors = []

    if config.get('MAX_IPS_TO_CHECK', 0) <= 0:
        errors.append("MAX_IPS_TO_CHECK must be positive")

    if config.get('CONCURRENT_REQUESTS', 0) <= 0:
        errors.append("CONCURRENT_REQUESTS must be positive")

    if config.get('AUTO_BLOCK_THRESHOLD', 0) < 0 or config.get('AUTO_BLOCK_THRESHOLD', 0) > 100:
        errors.append("AUTO_BLOCK_THRESHOLD must be between 0 and 100")

    if config.get('CACHE_TTL_HOURS', 0) <= 0:
        errors.append("CACHE_TTL_HOURS must be positive")

    return errors

def export_config(formats='json'):
    """Export current configuration to string."""
    config = load_config()

    if formats == 'yaml':
        return yaml.dump(config, indent=2, default_flow_style=False)
    else:
        return json.dumps(config, indent=2)

def get_api_key():
    """Get the AbuseIPDB API key from configuration or environment."""
    # First check environment variable
    env_key = os.getenv('ABUSEIPDB_API_KEY')
    if env_key:
        return env_key

    # Then check config file
    config = load_config()
    return config.get('ABUSEIPDB_API_KEY', '')

def get_setting(key, default=None):
    """Get a specific setting value."""
    config = load_config()
    return config.get(key, default)

# API Configuration
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
FIREHOL_BLOCKLISTS = [
    'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
    'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset',
    'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset'
]

# Application Settings (now configurable)
def get_scan_timeout():
    return get_setting('SCAN_TIMEOUT', 30)

def get_api_rate_limit():
    return get_setting('API_RATE_LIMIT_DELAY', 0.5)

def get_max_ips_to_check():
    return get_setting('MAX_IPS_TO_CHECK', 100)

def should_use_cache():
    return get_setting('USE_CACHE', True)

def get_cache_ttl():
    return get_setting('CACHE_TTL_HOURS', 24)

def enable_rich_output():
    return get_setting('ENABLE_RICH_OUTPUT', True)

def use_async_mode():
    return get_setting('ASYNC_MODE', True)

def get_concurrent_requests():
    return get_setting('CONCURRENT_REQUESTS', 5)