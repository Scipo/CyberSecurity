"""
Configuration settings for Network Threat Analyzer
"""
import os
import json
from pathlib import Path

# Default configuration
DEFAULT_CONFIG = {
    'ABUSEIPDB_API_KEY': '',
    'SCAN_TIMEOUT': 30,
    'API_RATE_LIMIT_DELAY': 0.5,
    'MAX_IPS_TO_CHECK': 100
}

def get_config_dir():
    """Get the configuration directory path."""
    config_dir = Path.home() / '.NetworkThreatAnalyzer'
    config_dir.mkdir(exist_ok=True)
    return config_dir

def get_config_file():
    """Get the configuration file path."""
    return get_config_dir() / 'config.json'


def load_config():
    """Load configuration from file."""
    config_file = get_config_file()

    if not config_file.exists():
        # Create default config file
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)

        # Ensure all default keys are present
        for key, value in DEFAULT_CONFIG.items():
            if key not in config:
                config[key] = value

        return config
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Could not load configuration: {e}")
        return DEFAULT_CONFIG.copy()
def save_config(config_updates):
    """Save configuration updates to file."""
    try:
        config_file = get_config_file()

        # Load existing config or create new
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = json.load(f)
        else:
            config = DEFAULT_CONFIG.copy()

        # Update configuration
        config.update(config_updates)

        # Save to file
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

        return True
    except Exception as e:
        print(f"Error saving configuration: {e}")
        return False


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
