"""
Utility functions for the Network Threat Analyzer
"""

import logging
import json
import sys
from datetime import datetime
from typing import Dict, Any

def setup_logging(verbose=False):
    """Setup logging configuration."""
    logger = logging.getLogger('NetworkThreatAnalyzer')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Clear any existing handlers
    logger.handlers.clear()

    # Create console handler
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
    """Save threat analysis results to JSON file."""
    try:
        output = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_ips_checked': len(results),
                'malicious_ips': sum(1 for r in results.values() if r.get('is_malicious', False)),
                'high_threat_ips': sum(1 for r in results.values() if r.get('threat_level') == 'high'),
                'medium_threat_ips': sum(1 for r in results.values() if r.get('threat_level') == 'medium')
            },
            'results': results
        }

        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)

        return True
    except Exception as e:
        print(f"❌ Failed to save results: {str(e)}")
        return False

def display_results(results):
    """Display results in a table."""
    print("\n" + "="*80)
    print("NETWORK THREAT ANALYSIS RESULTS")
    print("="*80)

    malicious_count = 0
    high_threat_count = 0
    medium_threat_count = 0

    for ip, result in results.items():
        if result.get('is_malicious', False):
            malicious_count += 1
            threat_level = result.get('threat_level', 'unknown')

            if threat_level == 'high':
                high_threat_count += 1
                emoji = '🔴'
            elif threat_level == 'medium':
                medium_threat_count += 1
                emoji = '🟡'
            else:
                emoji = '🟠'

            print(f"\n{emoji} MALICIOUS IP: {ip}")
            print(f"   Threat Level: {threat_level.upper()}")
            print(f"   Checks Performed: {', '.join(result.get('checks_performed', []))}")

            # Show key indicators
            details = result.get('details', {})
            if 'abuseipdb' in details:
                abuse_data = details['abuseipdb']
                if 'abuseConfidenceScore' in abuse_data:
                    print(f"   AbuseIPDB Score: {abuse_data['abuseConfidenceScore']}%")
                if abuse_data.get('totalReports', 0) > 0:
                    print(f"   Total Reports: {abuse_data['totalReports']}")
                if abuse_data.get('countryCode'):
                    print(f"   Country: {abuse_data['countryCode']}")
                if abuse_data.get('isp'):
                    print(f"   ISP: {abuse_data['isp']}")

            if 'firehol' in details and details['firehol'].get('listed', False):
                print(f"   FireHOL Blocklist: {details['firehol'].get('blocklist', 'Unknown')}")

    # Summary
    print("\n" + "="*80)
    print("SUMMARY:")
    print(f"Total IPs Checked: {len(results)}")
    print(f"Malicious IPs Found: {malicious_count}")
    print(f"High Threat IPs: {high_threat_count}")
    print(f"Medium Threat IPs: {medium_threat_count}")
    print("="*80)

    if malicious_count == 0:
        print("\nNo malicious IPs detected in current network connections.")
    else:
        print(f"\nFound {malicious_count} potentially malicious IP addresses!")

        # Show recommendations
        if high_threat_count > 0:
            print("\nRECOMMENDATIONS:")
            print("   - Investigate high threat IPs immediately")
            print("   - Consider blocking these IPs in your firewall")
            print("   - Check for any unauthorized network activity")