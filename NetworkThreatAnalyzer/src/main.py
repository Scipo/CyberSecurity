"""
Network threat analyzer - Main function
"""

import argparse
import os
import sys
import json
from datetime import datetime

from network_scanner import NetworkScanner
from threat_intel import ThreatIntelligence
from utils import setup_logging, save_results, display_results
from config.settings import load_config, save_config, get_api_key


def display_menu():
    """Display the main menu options."""
    print("\n" + "=" * 50)
    print("    NETWORK THREAT ANALYZER")
    print("=" * 50)
    print("1. Scan Network & Check Threats")
    print("2. Configure AbuseIPDB API Key")
    print("3. View Current Configuration")
    print("4. Test API Connection")
    print("5. Exit")
    print("=" * 50)


def get_menu_choice():
    try:
        choice = input("\nEnter your choice (1-5): ").strip()
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
    from config.settings import load_config, enable_rich_output, use_async_mode, should_use_cache
    from utils import setup_logging, save_results, display_rich_results, display_rich_network_info, \
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
            print("\nExit!!!")
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
