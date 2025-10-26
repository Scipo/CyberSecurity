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
    pass