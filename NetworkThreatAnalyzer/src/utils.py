"""
Utility functions for the Network Analyzer
"""
import sys
import json
import logging
from datetime import datetime


def setup_logging(verbose=False):
    """Setup Logging Configuration"""
    logger = logging.getLogger('NetworkThreatAnalyzer')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Create a console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(handler)

    return logger


def save_results(results, filename):
    """Saving threat analysis in JSON"""

    try:
        output = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_ips_checked': len(results),
                'malicious_ips': sum(1 for r in results.values() if r.get('is_malicious', False)),
                'high_threat_ips': sum(1 for r in results.values() if r.get('threat_level') == 'high')
            },
            'results': results
        }

        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)

        return True
    except Exception as e:
        logging.error(f"Failed to save results: {str(e)}")
        return False


def display_results(results):
    """Display results in a formated table"""
    print("\n" + "=" * 80)
    print("NETWORK THREAT ANALYSIS RESULTS")
    print("=" * 80)

    malicious_cnt = 0
    high_threat_cnt = 0

    for ip, result in results.items():
        if result.get('is_malicious', True):
            malicious_cnt += 1
            threat_level = result.get('threat_level', 'unknown')
            if threat_level == 'high':
                high_threat_cnt += 1

            print(f"\n MALICIOUS IP: {ip}")
            print(f"   Threat Level: {threat_level.upper()}")
            print(f"   Checks Performed: {', '.join(result.get('checks_performed', []))}")

            # AbuseIPDB and FireHOL results
            details = result.get('details', {})
            if 'abuseipdb' in details:
                abuse_data = details['abuseipdb']
                if 'abuseConfidenceScore' in abuse_data:
                    print(f" AbuseIPDB Score: {abuse_data['abuseConfidenceScore']}%")

            if 'firehol' in details and details['firehol'].get('listed', False):
                print(f" FireHOL Blocklist: {details['firehol'].get('blocklist', 'Unknown')}")

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY:")
    print(f"Total IPs Checked: {len(results)}")
    print(f"Malicious IPs Found: {malicious_cnt}")
    print(f"High Threat IPs: {high_threat_cnt}")
    print("=" * 80)

    if malicious_cnt == 0:
        print("\n No malicious IPs detected in current network connections.")
    else:
        print(f"\n Found {malicious_cnt} potentially malicious IP addresses!")
