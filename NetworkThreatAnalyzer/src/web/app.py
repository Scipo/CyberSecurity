import os
import sys
import json
import asyncio
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, Response

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.network_scanner import NetworkScanner
from src.threat_intel import ThreatIntelligence
from src.utils import setup_logging, save_results
from src.config.settings import load_config, get_api_key

app = Flask(__name__)
app.config['SECRET_KEY'] = 'network-threat-analyzer-secret-key'

# Global variables for scan results
scan_results = {}
scan_history = {}


# Scanner wrapper for web interface
class WebScanner:
    def __init__(self):
        self.logger = setup_logging(False)
        self.apy_key = get_api_key()
        self.scanner = NetworkScanner(self.logger)
        self.threat_intel = ThreatIntelligence(self.logger, self.apy_key)

    def run_scan(self):
        try:
            network_data = self.scanner.get_network_info()
            if not network_data:
                return {'error': 'No network data collected'}
            public_ips = self.scanner.extract_public_ips(network_data)
            if not public_ips:
                return {'network_data': network_data, 'threat_results': {}}
            # Check IPs against threat intelligence
            threat_results = self.threat_intel.check_ips(public_ips)
            return {
                'network_data': network_data,
                'threat_result': threat_results,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}


web_scanner = WebScanner()


@app.route('/')
# Main dashboard page
def index():
    config = load_config()
    return render_template(
        'index.html',
        config=config,
        has_api_key=bool(get_api_key())
    )


