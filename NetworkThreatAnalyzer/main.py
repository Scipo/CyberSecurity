"""
Network threat analyzer - Main function
"""

import argparse
import os
import sys
import json
from datetime import datetime

from src.network_scanner import NetworkScanner
from src.web.app import run_web_interface, scan_results
from src.threat_intel import ThreatIntelligence
from src.utils import setup_logging, save_results, display_results
from src.config.settings import load_config, save_config, get_api_key
from src.reporting.generator import ReportGenerator, HAS_WEASYPRINT
from src.integrations.notifications import NotificationManager


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
    print("7. Exit")
    print("=" * 50)


def get_menu_choice():
    try:
        choice = input("\nEnter your choice (1-7): ").strip()
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
    test_ip = ["109.205.213.30","34.92.247.119 ", "8.8.8.8", "128.14.236.128"]
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
         print(8*'*')


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
        if config.get('AUTO_GENERATE_REPORTS', True):
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
def generate_reports_after_scan(scan_repots):
    config = load_config()
    report_formats = config.get('REPORT_FORMATS', ['json'])
    output_dir = config.get('REPORT_OUTPUT_DIR', 'reports')

    print(f"\nGenerating reports in formats: {', '.join(report_formats)}")
    generator = ReportGenerator(output_dir=output_dir)
    generated_reports = []

    try:
        for rep_f in report_formats:
            try:
                if rep_f == 'html':
                    report_path = generator.generate_html_report(scan_results)
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

        if should_alert:
            print("Sending notifications...")
            notifier = NotificationManager()
            notifications_sent, errors = notifier.send_all_notifications(scan_results)

            if notifications_sent:
                print(f"Notifications sent: {', '.join(notifications_sent)}")
            if errors:
                print(f"Notification errors: {', '.join(errors)}")


# Start web interface
def start_web_interface():
    from src.config.settings import  get_setting
    host = get_setting('WEB_HOST', '127.0.0.1')
    port = get_setting('WEB_PORT', 5000)
    debug = get_setting('WEB_DEBUG', False)

    run_web_interface(host=host, port=port, debug=debug)

# Generate advanced report
def generate_advanced_report():

    print("\nAdvanced ReportingTO Here")
    print("This feature will be available after running a scan.")
    print("Run a scan first, then use the web interface for advanced reports.")
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
