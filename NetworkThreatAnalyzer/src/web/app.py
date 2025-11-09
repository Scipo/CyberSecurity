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
scan_history = []


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


# Global web instance
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


@app.route('/api/scan', methods=['POST'])
# API endpoint to run a network scan
def api_scan():
    global scan_results, scan_history

    try:
        results = web_scanner.run_scan()
        if 'error' in results:
            return jsonify({'success': False, 'error': results['error']})

        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_results[scan_id] = results
        scan_history.append({
            'id': scan_id,
            'timestamp': results['timestamp'],
            'total_ips': len(results.get('threat_results', {})),
            'malicious_ips': sum(1 for r in results.get('threat_results', {}).values() if r.get('is_malicious', False))
        })

        # TO DO Check more than 10 records in the future
        scan_history = scan_history[-10:]

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'results': results
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api.results/<scan_id>')
# Get specific scan results
def get_results(scan_id):
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    else:
        return jsonify({'error': 'Scan not found'}), 404


@app.route('/api/history')
# Get scan history
def get_history():
    return jsonify(scan_history)


@app.route('/api/export/<scan_id>')
# Export Scan results in Json
def export_results(scan_id):
    if scan_id in scan_results:
        filename = f"threat_scan_{scan_id}.json"
        filepath = os.path.join('/tmp', filename)

        with open(filepath, 'w') as f:
            json.dump(scan_results[scan_id], f, indent=2)
        return send_file(filepath, as_attachment=True, download_name=filename)
    else:
        return jsonify({'error': 'Scan not found'}), 404


@app.route('/api/config', methods=['GET', 'POST'])
# Get update configuration
def handle_config():
    if request.method == 'GET':
        config = load_config()
        if config.get('ABUSEIPDB_API_KEY'):
            config['ABUSEIPDB_API_KEY'] = '***' + config['ABUSEIPDB_API_KEY'][-4:]
        return jsonify(config)
    else:  # POST
        try:
            new_config = request.json
            from src.config.settings import save_config
            save_config(new_config)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})


@app.route('/api/network_info')
# Get current network information without full scan
def get_network_info():
    try:
        scanner = NetworkScanner(setup_logging(False))
        network_data = scanner.get_network_info()
        public_ips = scanner.extract_public_ips(network_data)

        return jsonify(
            {
                'total_connections': len(network_data),
                'public_ips_count': len(public_ips),
                'sample_connections': dict(list(network_data.items())[:5])  # First 5
            }
        )
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/api/test_api')
# Test AbuseIDDB API connection
def test_api():
    try:
        threat_intel = ThreatIntelligence(setup_logging(False), get_api_key())
        test_ip = "8.8.8.8"
        result = threat_intel._check_abuseipdb_sync(test_ip)

        if 'error' in result:
            return jsonify({'success': False, 'error': result['error']})
        else:
            return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Run web interface
def run_web_interface(host='127.0.0.1', port=5000, debug=False):
    print(f"🚀 Starting Network Threat Analyzer Web Interface...")
    print(f"📡 Access at: https://{host}:{port}")
    print(f"🛑 Press Ctrl+C to stop")
    app.run(host=host, port=port, debug=debug, threaded=True)

if __name__ == '__main__':
    run_web_interface()