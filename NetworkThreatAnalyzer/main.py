"""
Network threat analyzer - Main function
"""

import argparse
import os
import sys
import json
from datetime import datetime
from traceback import print_tb

from src.network_scanner import NetworkScanner
from src.web.app import run_web_interface
from src.threat_intel import ThreatIntelligence
from src.utils import setup_logging, save_results, display_results
from src.config.settings import load_config, save_config, get_api_key
from src.reporting.generator1 import ReportGenerator, HAS_WEASYPRINT
from src.integrations.notifications import NotificationManager
from src.state.statemanager import state_manager


def display_menu():
    """Display the main menu options."""
    print("\n" + "=" * 50)
    print("    NETWORK THREAT ANALYZER")
    print("=" * 50)
    print("1. Scan Network & Check Threats")
    print("2. Configure AbuseIPDB API Key")
    print("3. View Current Configuration")
    print("4. Test API Connection")
    print("5. Web Interface")
    print("6. Generate Advanced Report")
    print("7. View Scan History")
    print("8. Exit")
    print("=" * 50)


def get_menu_choice():
    try:
        choice = input("\nEnter your choice (1-8): ").strip()
        return int(choice) if choice.isdigit() else None
    except (ValueError, EOFError):
        return None


def configure_api_key():
    print("\n--- Configure AbuseIPDB API Key ---")
    print("You can get a free API key from: https://www.abuseipdb.com/")
    print("Leave empty to use existing key or skip configuration.")

    api_key = input("Enter your AbuseIPDB API key: ").strip()

    if api_key:
        success = save_config({'ABUSEIPDB_API_KEY': api_key})
        if success:
            print("API key configured successfully!")
        else:
            print("Failed to save API key configuration.")
    elif not api_key and get_api_key():
        print("Using existing API key.")
    else:
        print("No API key configured. Some features will be limited.")
    input("\nPress Enter to continue...")


def view_configuration():
    config = load_config()
    print("\n--- Current Configuration ---")

    if config.get('ABUSEIPDB_API_KEY'):
        masked_key = config['ABUSEIPDB_API_KEY'][:8] + '***' + config['ABUSEIPDB_API_KEY'][-4]
        print(f"AbuseIPDB API Key: {masked_key}")
    else:
        print("AbuseIPDB API Key: Not configured")

    # Report settings
    report_formats = config.get('REPORT_FORMATS', ['json'])
    print(f"Report Formats: {', '.join(report_formats)}")
    print(f"Auto-generated Reports: {config.get('AUTO_GENERATE_REPORTS', True)}")

    # Notification settings
    print(f"Notifications Enabled: {config.get('ENABLE_NOTIFICATIONS', False)}")
    print(f"Config File: {os.path.join(os.path.expanduser('~'), '.NetworkThreatAnalyzer', 'config.json')}")

    input("\nPress Enter to continue...")


def test_api_connection():
    print("\n--- Testing API Connection ---")
    api_key = get_api_key()
    if not api_key:
        print("No API key configured. Please configure it first.")
        input("\nPress Enter to continue...")
        return
    threat_intel = ThreatIntelligence(setup_logging(False), api_key)
    test_ip = ["109.205.213.30", "34.92.247.119 ", "8.8.8.8", "128.14.236.128"]
    for ip in test_ip:
        print(f"Testing with IP: {ip}")
        try:
            result = threat_intel._check_abuseipdb_sync(ip)
            if 'error' in result:
                print(f"API Test Failed: {result['error']}")
            else:
                print("API Connection Successful!")
                print(f"Abuse Confidence Score: {result.get('abuseConfidenceScore', 0)}%")
                print(f"Total Reports: {result.get('totalReports', 0)}")
                print(f"ISP: {result.get('isp', 'Unknown')}")
                print(f"Country: {result.get('countryCode', 'Unknown')}")
        except Exception as e:
            print(f"API Test Failed: {str(e)}")
        print(8 * '*')


# def run_network_scan():
#     logger = setup_logging(False)
#
#     try:
#         api_key = get_api_key()
#         if not api_key:
#             print("\nWarning: No AbuseIPDB API key configured.")
#             print("Some threat intelligence features will be limited.")
#             print("You can configure it from the main menu (Option 2).")
#             proceed = input("Continue anyway? (y/N): ").strip().lower()
#             if proceed != 'y':
#                 return
#
#         # Init components
#         scanner = NetworkScanner(logger)
#         threat_intel = ThreatIntelligence(logger, api_key)
#
#         # Gather network information
#         print("\nGathering network connection information...")
#         network_data = scanner.get_network_info()
#
#         if not network_data:
#             print("No network data collected. Please check your network connections.")
#             return
#
#         # Extract unique public IPs
#         public_ips = scanner.extract_public_ips(network_data)
#         print(f"Found {len(public_ips)} unique public IPs to analyze")
#
#         print("Checking IPs against threat intelligence feeds...")
#         threat_results = threat_intel.check_ips(public_ips)
#
#         # Result Display
#         display_results(threat_results)
#
#         # save results
#         output_file = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
#         save_results(threat_results, output_file)
#         print(f"Results saved to: {output_file}")
#
#         # Summary
#         malicious_count = sum(1 for result in threat_results.values() if result.get('is_malicious', False))
#         print(f"\nAnalysis complete: {malicious_count} malicious IPs found out of {len(public_ips)} total")
#     except KeyboardInterrupt:
#         print("Scan interrupted by user.")
#     except Exception as e:
#         print(f"Application error: {str(e)}")
#     input("Press Enter to continue.....")


def run_network_scan():
    """Run the main network scanning and threat analysis with new features."""
    from src.config.settings import load_config, enable_rich_output, use_async_mode, should_use_cache
    from src.utils import setup_logging, save_results, display_rich_results, display_rich_network_info, \
        show_scan_progress
    from rich.console import Console

    config = load_config()
    logger = setup_logging(False)
    use_rich = enable_rich_output()
    try:
        RICH_AVAILABLE = True
    except ImportError:
        RICH_AVAILABLE = False
    console = Console() if RICH_AVAILABLE else None

    try:

        logger.info("Starting Network Threat Analyzer")

        # Load configuration
        api_key = get_api_key()
        if not api_key:
            if use_rich and console:
                console.print("\n [yellow]Warning: No AbuseIPDB API key configured.[/yellow]")
                console.print("Some threat intelligence features will be limited.")
                console.print("You can configure it from the main menu (Option 2).")
                proceed = input("Continue anyway? (y/N): ").strip().lower()
            else:
                print("\n Warning: No AbuseIPDB API key configured.")
                print("Some threat intelligence features will be limited.")
                print("You can configure it from the main menu (Option 2).")
                proceed = input("Continue anyway? (y/N): ").strip().lower()

            if proceed != 'y':
                return

        # Initialize components
        scanner = NetworkScanner(logger)
        threat_intel = ThreatIntelligence(logger, api_key, use_cache=should_use_cache())

        # Gather network information
        if use_rich and console:
            console.print("\n[cyan]Gathering network connection information...[/cyan]")
        else:
            print("\nGathering network connection information...")

        network_data = scanner.get_network_info()

        if not network_data:
            if use_rich and console:
                console.print(" [red]No network data collected. Please check your network connections.[/red]")
            else:
                print(" No network data collected. Please check your network connections.")
            return

        # Display network information
        if use_rich:
            display_rich_network_info(network_data)

        # Extract unique public IPs
        public_ips = scanner.extract_public_ips(network_data)

        if use_rich and console:
            console.print(f"[cyan]Found {len(public_ips)} unique public IPs to analyze[/cyan]")
        else:
            print(f"Found {len(public_ips)} unique public IPs to analyze")

        if not public_ips:
            if use_rich and console:
                console.print(
                    "[yellow]No public IPs found to analyze. Only private network connections detected.[/yellow]")
            else:
                print("No public IPs found to analyze. Only private network connections detected.")
            return

        # Check IPs against threat intelligence
        if use_rich and console:
            console.print("[cyan]Checking IPs against threat intelligence feeds...[/cyan]")

            # Show progress bar
            progress = show_scan_progress()
            with progress:
                task = progress.add_task("Checking IPs...", total=len(public_ips))
                threat_results = threat_intel.check_ips(public_ips)
                progress.update(task, completed=len(public_ips))
        else:
            print("Checking IPs against threat intelligence feeds...")
            threat_results = threat_intel.check_ips(public_ips)

        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_results = {
            'id': scan_id,
            'network_data': network_data,
            'threat_results': threat_results,
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_ips_scanned': len(public_ips),
                'public_ips_count': len(public_ips),
                'scanner_version': '1.0.0'
            }
        }
        state_manager.set_last_scan_result(scan_results)
        # Add to history
        history_entry = {
            'id': scan_id,
            'timestamp': scan_results['scan_metadata']['timestamp'],
            'total_ips': len(public_ips),
            'malicious_ips': sum(1 for r in threat_results.values() if r.get('is_malicious', False)),
            'high_threats': sum(1 for r in threat_results.values() if r.get('threat_level') == 'high')
        }
        state_manager.add_scan_results_to_history(history_entry)
        # Display results
        if use_rich:
            display_rich_results(threat_results)
        else:
            display_results(threat_results)

        # Save results
        output_file = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_results(threat_results, output_file)

        if use_rich and console:
            console.print(f"[green]Results saved to: {output_file}[/green]")
        else:
            print(f"Results saved to: {output_file}")

        # Auto-generate reports if enabled
        if config.get('AUTO_GENERATE_REPORTS', False):
            generate_reports_after_scan(scan_results)

        # Send notifications if enabled
        if config.get('ENABLE_NOTIFICATIONS', False):
            send_notifications_after_scan(scan_results)

        # Summary
        malicious_count = sum(1 for result in threat_results.values() if result.get('is_malicious', False))
        if use_rich and console:
            if malicious_count > 0:
                console.print(
                    f"\n[red]Analysis complete: {malicious_count} malicious IPs found out of {len(public_ips)} total[/red]")
            else:
                console.print(
                    f"\n[green]Analysis complete: {malicious_count} malicious IPs found out of {len(public_ips)} total[/green]")
        else:
            print(f"\nAnalysis complete: {malicious_count} malicious IPs found out of {len(public_ips)} total")

    except KeyboardInterrupt:
        if use_rich and console:
            console.print("\n\n[yellow]Scan interrupted by user.[/yellow]")
        else:
            print("\n\n Scan interrupted by user.")
    except Exception as e:
        if use_rich and console:
            console.print(f" [red]Application error: {str(e)}[/red]")
        else:
            print(f" Application error: {str(e)}")

    input("\nPress Enter to continue...")


# Automatically generate reports after scan
def generate_reports_after_scan(scan_results):
    print(f"DEBUG: scan_results type: {type(scan_results)}")
    print(f"DEBUG: scan_results keys: {list(scan_results.keys()) if isinstance(scan_results, dict) else 'Not a dict'}")
    config = load_config()
    report_formats = config.get('REPORT_FORMATS', ['json'])
    print(f"DEBUG: report_formats: {report_formats}, type: {type(report_formats)}")
    if not isinstance(report_formats, list):
        report_formats = ['json']
    report_formats = [fmt for fmt in report_formats if isinstance(fmt, str)]
    if not report_formats:
        print("No valid report formats specified in config")
        return []

    output_dir = config.get('REPORT_OUTPUT_DIR', 'reports')

    print(f"\nGenerating reports in formats: {', '.join(report_formats)}")
    generator = ReportGenerator(output_dir=output_dir)
    generated_reports = []

    try:
        for rep_f in report_formats:
            try:
                print(f"DEBUG: Processing format: {rep_f}")
                if rep_f == 'html':
                    report_path = generator.generate_html_repot(scan_results)
                    generated_reports.append(('HTML', report_path))
                elif rep_f == 'json':
                    report_path = generator.generate_json_report(scan_results)
                    generated_reports.append(('JSON', report_path))
                elif rep_f == 'csv':
                    report_path = generator.generate_csv_report(scan_results)
                    generated_reports.append(('CSV', report_path))
                elif rep_f == 'pdf' and HAS_WEASYPRINT:
                    report_path = generator.generate_pdf_report(scan_results)
                    generated_reports.append(('PDF', report_path))
            except Exception as e:
                print(f"Failed to generate {rep_f.upper()} report: {str(e)}")

            # Display reports
            if generated_reports:
                print("Generated Reports:")
                for rep_type, rep_path in generated_reports:
                    print(f"{rep_type} : {rep_path}")
            else:
                print("No reports were generated")
    except Exception as e:
        print(f"Report generation failed: {str(e)}")


# notifications after a scan if threats are found
def send_notifications_after_scan(scan_result):
    config = load_config()
    threat_results = scan_result.get('threat_results', {})
    malicious_count = sum(1 for r in threat_results.values() if r.get('is_malicious', False))

    # Only send notifications if threats are found and alerts are enabled
    if malicious_count > 0:
        alert_on_high = config.get('ALERT_ON_HIGH_THREAT', True)
        alert_on_medium = config.get('ALERT_ON_MEDIUM_THREAT', False)

        high_threats = sum(1 for r in threat_results.values()
                           if r.get('is_malicious') and r.get('threat_level') == 'high')
        medium_threats = sum(1 for r in threat_results.values()
                             if r.get('is_malicious') and r.get('threat_level') == 'medium')

        should_alert = (alert_on_high and high_threats > 0) or (alert_on_medium and medium_threats > 0)

        # if should_alert:
        #     print("Sending notifications...")
        #     notifier = NotificationManager()
        #     notifications_sent, errors = notifier.send_all_notifications(scan_results)
        #
        #     if notifications_sent:
        #         print(f"Notifications sent: {', '.join(notifications_sent)}")
        #     if errors:
        #         print(f"Notification errors: {', '.join(errors)}")


# Start web interface
def start_web_interface():
    from src.config.settings import get_setting
    host = get_setting('WEB_HOST', '127.0.0.1')
    port = get_setting('WEB_PORT', 5000)
    debug = get_setting('WEB_DEBUG', False)
    try:
        run_web_interface(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        print("Web interface stopped.")
    except Exception as e:
        print(f"Failed to start web interface: {str(e)}")


# Generate advanced report
def generate_advanced_report():
    print("Advanced report")
    print("=" * 40)
    # Get last scan results from state manager
    last_scan_results = state_manager.get_last_scan_result()

    if last_scan_results is None:
        print("No recent scan results found.")
        print("You need to run a scan first or load existing results.")
        choice = input("Run a new scan now? (Y/N): ").strip().lower()

        if choice == 'y':
            run_network_scan()
            # Get the update results after scan
            if last_scan_results is None:
                return
        else:
            # Option to load existing results from file
            load_existing_results()
            last_scan_results = state_manager.get_last_scan_result()
            if last_scan_results is None:
                return
    # Show scan Info
    scan_id = last_scan_results.get('id', 'unknown')
    scan_time = last_scan_results.get('scan_metadata', {}).get('timestamp', 'unknown')
    total_ips = len(last_scan_results.get('threat_results', {}))
    malicious_ips = sum(1 for r in last_scan_results.get('threat_results', {}).values() if r.get('is_malicious', False))

    print(f"Using scan from: {scan_time}")
    print(f"Scan contains: {total_ips} IPs, {malicious_ips} malicious")

    # Report format selection
    print("Available Report Formats:")
    print("1. HTML Report (Interactive)")
    print("2. JSON Report (Detailed)")
    print("3. CSV Report (Spreadsheet)")
    print("4. PDF Report (Professional)")
    print("5. All Formats")
    print("6. Custom Selection")

    try:
        choice = input("\nSelect report format (1-6): ").strip()
        format_choice = int(choice) if choice.isdigit() else 0
    except ValueError:
        format_choice = 0

    formats_to_generate = []

    if format_choice == 1:
        formats_to_generate = ['html']
    elif format_choice == 2:
        formats_to_generate = ['json']
    elif format_choice == 3:
        formats_to_generate = ['csv']
    elif format_choice == 4:
        formats_to_generate = ['pdf']
    elif format_choice == 5:
        formats_to_generate = ['html', 'json', 'csv', 'pdf']
    elif format_choice == 6:
        print("Enter formats separated by commas (html,json,csv,pdf,executive):")
        custom_formats = input("Formats: ").strip().lower().split(',')
        formats_to_generate = [f.strip() for f in custom_formats if f.strip()]
    else:
        print("Invalid selection. Using defaults formats (html, json). ")
        formats_to_generate = ['html', 'json']

    # Out_put directory
    output_dir = input("\nOutput directory (press Enter for 'reports'): ").strip()
    if not output_dir:
        output_dir = 'reports'

    print(f"Generating {len(formats_to_generate)} reports(s)...")
    generator = ReportGenerator(output_dir=output_dir)
    generated_reports = []

    for frm in formats_to_generate:
        try:
            if frm == 'html':
                report_path = generator.generate_html_repot(last_scan_results)
                generated_reports.append(('HTML', report_path))
                print(f"Generated HTML report: {report_path}")
            elif frm == 'json':
                report_path = generator.generate_json_report(last_scan_results)
                generated_reports.append(('JSON', report_path))
                print(f"Generated JSON report: {report_path}")
            elif frm == 'csv':
                report_path = generator.generate_csv_report(last_scan_results)
                generated_reports.append(('CSV', report_path))
                print(f"Generated CSV report: {report_path}")
            elif frm == 'pdf':
                try:
                    from weasyprint import HTML
                    report_path = generator.generate_pdf_report(last_scan_results)
                    generated_reports.append(('PDF', report_path))
                    print(f"Generated PDF report: {report_path}")
                except ImportError:
                    print("PDF generation requires WeasyPrint. Install with: pip install weasyprint")
            else:
                print(f"Unknown format: {format}")
        except Exception as e:
            print(f"Failed to generate {format} report: {str(e)}")

    if generated_reports:
        print(f"Successfully generated {len(generated_reports)} report(s):")
        for report_type, report_path in generated_reports:
            print(f" {report_type}:{report_path}")
        # Open html if generated
        html_reports = [path for tpe, path in generated_reports if tpe == 'HTML']
        if html_reports and input("Open HTML report in browser? (Y/n): ").strip().lower() == 'y':
            import webbrowser
            webbrowser.open(f'file://{os.path.abspath(html_reports[0])}')
        else:
            print("No reports were generated")

    input("\nPress Enter to continue...")


# View and manage scan history
def view_scan_history():
    history = state_manager.get_scan_history()

    print("Scan History")
    print("=" * 40)

    if not history:
        print("No scan history available")
        print("Run a scan to build history")
        print("Press Enter to continue...")
    # Display History
    print(f"Total scans in history: {len(history)}")
    print("Recent Scans: ")
    print("-" * 60)

    for i, scan in enumerate(reversed(history[-10:]), 1):
        scan_id = scan.get('id', 'unknown')
        timestamp = scan.get('timestamp', 'unknown')
        total_ips = scan.get('total_ips', 0)
        malicious_ips = scan.get('malicious_ips', 0)
        high_threats = scan.get('high_threats', 0)

        print(f"{i}. {timestamp}")
        print(f"   ID: {scan_id}")
        print(f"   IPs: {total_ips} | Malicious: {malicious_ips} | High Threats: {high_threats}")

        print()
    # Options
    print("Options: ")
    print("1. Load a specific scan for reporting")
    print("2. Clear history")
    print("3. Back to main menu")

    try:
        choice = input("\nSelect of Options (1-3): ").strip()
        options = int(choice) if choice.isdigit() else 0
    except ValueError:
        options = 0

    if options == 1:
        load_specific_scan()
    elif options == 2:
        clear_history_confirmation()
    elif options == 3:
        main_menu()


# Load specific scan from history
def load_specific_scan():
    history = state_manager.get_scan_history()
    if not history:
        print("No scan history available.")
        return

    print("\nEnter the scan ID to load (or press Enter to cancel):")
    scan_id = input("Scan ID: ").strip()

    if not scan_id:
        return

    # Find scan ID
    scan_data = state_manager.get_scan_by_id(scan_id)
    if scan_data:
        last_scan = state_manager.get_last_scan_result()
        if last_scan and last_scan.get('id') == scan_id:
            print(f"Scan {scan_id} is already the current scan.")
        else:
            print(f"Full results for scan {scan_id} are not available.")
            print("Only the most recent scan's full results are stored.")
            print("Please run a new scan to generate full results.")
    else:
        print(f"Scan {scan_id} not found in history.")

    input("\nPress Enter to continue...")


# Confirm and clear history
def clear_history_confirmation():
    print("Clear Scan History")
    print("This will remove all scan history entries.")
    print("This action cannot be undone!")
    confirm = input("Type 'DELETE' to confirm: ").strip()
    if confirm == 'DELETE':
        state_manager.clear_history()
        print("Scan history cleared.")
    else:
        print("Clear cancelled.")

    input("\nPress Enter to continue...")


# Loading existing results
def load_existing_results():
    print("Load Existing Scan Results")
    print("Enter the path to a previously saved JSON results file:")
    file_path = input("File path: ").strip()

    if not file_path:
        return
    try:
        with open(file_path, 'r') as f:
            file_content = json.load(f)
        # Create scan results structure
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S_loaded')
        scan_res = {
            'id': scan_id,
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'loaded_from': file_path,
                'scanner_version': '1.0.0'
            }
        }
        # Handle different file formats
        if 'threat_results' in file_content and 'network_data' in file_content:
            # Full scan results formats
            scan_res.update(file_content)
        elif 'threat_results' in file_content:
            # Results form main output
            scan_res['threat_results'] = file_content['threat_results']
            scan_res['network_data'] = file_content.get('network_data', {})
        else:
            # Basic format main output
            scan_res['threat_results'] = file_content
            scan_res['network_data'] = {}

        # Store results formats
        state_manager.set_last_scan_result(scan_res)

        # Add to history
        threat_results = scan_res.get('threat_results', {})
        history_entry = {
            'id': scan_id,
            'timestamp': scan_res['scan_metadata']['timestamp'],
            'total_ips': len(threat_results),
            'malicious_ips': sum(1 for r in threat_results.values() if r.get('is_malicious', False)),
            'high_threats': sum(1 for r in threat_results.values() if r.get('threat_level') == 'high'),
            'source': 'loaded'
        }

        state_manager.add_scan_results_to_history(history_entry)
        print(f"Successfully loaded results from: {file_path}")
        # show summary
        threat_results = scan_res.get('threat_results', {})
        malicious_count = sum(1 for r in threat_results.values() if r.get('is_malicious', False))

        print(f"Loaded data: {len(threat_results)} IPs, {malicious_count} malicious")
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except json.JSONDecodeError:
        print(f"Invalid JSON file: {file_path}")
    except Exception as e:
        print(f"Error loading file: {str(e)}")

    input("\nPress Enter to continue...")


def main_menu():
    while True:
        display_menu()
        choice = get_menu_choice()
        if choice == 1:
            run_network_scan()
        elif choice == 2:
            configure_api_key()
        elif choice == 3:
            view_configuration()
        elif choice == 4:
            test_api_connection()
        elif choice == 5:
            start_web_interface()
        elif choice == 6:
            generate_advanced_report()
        elif choice == 7:
            view_scan_history()
        elif choice == 8:
            print("Exit")
            break
        else:
            print("Invalid choice. Please enter a number between 1-5.")


def main():
    """ Main entry point """
    parser = argparse.ArgumentParser(description='Network Threat Analyzer')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--api-key', help='AbuseIPDB API key')
    parser.add_argument('--scan', '-s', action='store_true',
                        help='Run scan directly without menu')

    args = parser.parse_args()

    if args.scan:
        direct_run(args)
    else:
        main_menu()


def direct_run(args):
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
