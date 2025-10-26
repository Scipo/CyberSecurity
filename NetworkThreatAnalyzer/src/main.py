#!/usr/bin/env python3

"""
Network threat analyzer - Main function
"""

import argparse
import sys
import json
from datetime import datetime

from src.network_scanner import NetworkScanner
from src.threat_intel import ThreatIntelligence
from src.utils import setup_logging, save_results, display_results


def main():
    """ Main entry point """
    parser = argparse.ArgumentParser(description='Network Threat Analyzer')
    parser.add_argument('--output', '-o', default='threat_report.json', help='Output file for results (default: threat_report.json)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--api-key', help='AbuseIPDB API key (or set ABUSEIPDB_API_KEY env var)')

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(args.verbose)


