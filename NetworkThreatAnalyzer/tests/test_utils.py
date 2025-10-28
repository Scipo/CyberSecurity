"""
Mock tests for Utility functions
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import tempfile
import os
import sys
from io import StringIO
from src.utils import setup_logging, save_results, display_results
import logging


class TestUtils(unittest.TestCase):

    def test_setup_logging_verbose(self):
        """Test logging setup with verbose mode."""
        logger = setup_logging(verbose=True)
        self.assertEqual(logger.level, logging.DEBUG)

    def test_setup_logging_normal(self):
        """Test logging setup with normal mode."""
        logger = setup_logging(verbose=False)
        self.assertEqual(logger.level, logging.INFO)

    def test_save_results_success(self):
        """Test successful saving of results to JSON file."""
        test_results = {
            '8.8.8.8': {
                'ip': '8.8.8.8',
                'is_malicious': True,
                'threat_level': 'high',
                'checks_performed': ['abuseipdb', 'firehol'],
                'details': {
                    'abuseipdb': {'abuseConfidenceScore': 95},
                    'firehol': {'listed': True}
                }
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name

        try:
            success = save_results(test_results, temp_file)
            self.assertTrue(success)

            # Verify file content
            with open(temp_file, 'r') as f:
                saved_data = json.load(f)

            self.assertIn('timestamp', saved_data)
            self.assertIn('summary', saved_data)
            self.assertIn('results', saved_data)
            self.assertEqual(saved_data['summary']['malicious_ips'], 1)
            self.assertEqual(saved_data['summary']['total_ips_checked'], 1)
            self.assertIn('8.8.8.8', saved_data['results'])

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_save_results_invalid_path(self):
        """Test saving results to invalid path."""
        test_results = {'8.8.8.8': {'ip': '8.8.8.8', 'is_malicious': False}}

        # Try to save to read-only location (should fail)
        success = save_results(test_results, '/root/invalid_path/test.json')
        self.assertFalse(success)

    def test_save_results_serialization_error(self):
        """Test handling of JSON serialization errors."""
        # Create an object that cannot be serialized to JSON
        test_results = {
            '8.8.8.8': {
                'ip': '8.8.8.8',
                'invalid_object': object()  # Not JSON serializable
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name

        try:
            success = save_results(test_results, temp_file)
            self.assertFalse(success)
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch('sys.stdout', new_callable=StringIO)
    def test_display_results_malicious_ips(self, mock_stdout):
        """Test display of results with malicious IPs."""
        test_results = {
            '8.8.8.8': {
                'ip': '8.8.8.8',
                'is_malicious': True,
                'threat_level': 'high',
                'checks_performed': ['abuseipdb', 'firehol'],
                'details': {
                    'abuseipdb': {'abuseConfidenceScore': 95, 'totalReports': 25},
                    'firehol': {'listed': True, 'blocklist': 'firehol_level1.netset'},
                }
            },
            '1.1.1.1': {
                'ip': '1.1.1.1',
                'is_malicious': False,
                'threat_level': 'low',
                'checks_performed': ['abuseipdb', 'firehol'],
                'details': {
                    'abuseipdb': {'abuseConfidenceScore': 0, 'totalReports': 0},
                    'firehol': {'listed': False},
                }
            }
        }

        display_results(test_results)
        output = mock_stdout.getvalue()

        # Verify malicious IP is displayed
        self.assertIn('MALICIOUS IP: 8.8.8.8', output)
        self.assertIn('Threat Level: HIGH', output)
        self.assertIn('AbuseIPDB Score: 95%', output)
        self.assertIn('FireHOL Blocklist: firehol_level1.netset', output)

        # Verify summary
        self.assertIn('Total IPs Checked: 2', output)
        self.assertIn('Malicious IPs Found: 1', output)
        self.assertIn('High Threat IPs: 1', output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_display_results_no_malicious(self, mock_stdout):
        """Test display of results with no malicious IPs."""
        test_results = {
            '1.1.1.1': {
                'ip': '1.1.1.1',
                'is_malicious': False,
                'threat_level': 'low',
                'checks_performed': ['abuseipdb', 'firehol'],
                'details': {}
            }
        }

        display_results(test_results)
        output = mock_stdout.getvalue()

        self.assertIn('No malicious IPs detected', output)
        self.assertIn('Total IPs Checked: 1', output)
        self.assertIn('Malicious IPs Found: 0', output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_display_results_empty(self, mock_stdout):
        """Test display of empty results."""
        display_results({})
        output = mock_stdout.getvalue()

        self.assertIn('Total IPs Checked: 0', output)
        self.assertIn('Malicious IPs Found: 0', output)
        self.assertIn('No malicious IPs detected', output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_display_results_medium_threat(self, mock_stdout):
        """Test display of results with medium threat level."""
        test_results = {
            '8.8.8.8': {
                'ip': '8.8.8.8',
                'is_malicious': True,
                'threat_level': 'medium',
                'checks_performed': ['abuseipdb'],
                'details': {
                    'abuseipdb': {'abuseConfidenceScore': 50}
                }
            }
        }

        display_results(test_results)
        output = mock_stdout.getvalue()

        self.assertIn('Threat Level: MEDIUM', output)
        self.assertIn('AbuseIPDB Score: 50%', output)


if __name__ == '__main__':
    unittest.main()