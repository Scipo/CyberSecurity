#!/usr/bin/env python3

"""
Network threat analyzer - Main function
"""

import argparse
import sys
import json
from datetime import datetime

from network_scanner import NetworkScanner
from threat_intel import ThreatIntelligence
from utils import setup_logging, save_results, display_results


def main():
    """ Main entry point """
    parser = argparse.ArgumentParser(description='Network Threat Analyzer')
    parser.add_argument('--output', '-o', default='threat_report.json',
                        help='Output file for results (default: threat_report.json)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--api-key', help='AbuseIPDB API key (or set ABUSEIPDB_API_KEY env var)')

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(args.verbose)

    try:
        logger.info("Starting Network Threat Analyzer")

        # Init components
        scanner = NetworkScanner(logger)
        threat_intel = ThreatIntelligence(logger, args.api_key)

        #  Network information gathering
        logger.info("Network information gathering")
        network_data = scanner.get_network_info()

        if not network_data:
            logger.error("No network data collected")
            return 1
        # Extract Public IPs
        public_ips = scanner.extract_public_ips(network_data)
        logger.info(f"Found {len(public_ips)} unique public IPs to analyze")

        if not public_ips:
            logger.warning("No public IPs found to analyze")
            return 0

        # Check IPs against threat intelligence
        logger.info("Checking IPs against threat intelligence feeds...")
        threat_results = threat_intel.check_ips(public_ips)

        # Display results
        display_results(threat_results)

        # Save results
        save_results(threat_results, args.output)
        logger.info(f"Results saved to {args.output}")

        # Summary
        malicious_count = sum(1 for result in threat_results.values() if result.get('is_malicious', False))
        logger.info(f"Analysis complete: {malicious_count} malicious IPs found out of {len(public_ips)} total")

        return 0
    except Exception as e:
        logger.error(f"Application error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
