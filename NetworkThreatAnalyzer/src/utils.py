"""
Utility functions for the Network Threat Analyzer
"""

import logging
import json
import sys
from datetime import datetime
import rich

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.text import Text
    from rich import box
    from rich.markdown import Markdown

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None


def setup_logging(verbose=False):
    """Setup logging configuration with Rich support."""
    logger = logging.getLogger('NetworkThreatAnalyzer')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Clear any existing handlers
    logger.handlers.clear()

    if RICH_AVAILABLE and verbose:
        from rich.logging import RichHandler
        handler = RichHandler(rich_tracebacks=True, markup=True)
        handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        logger.addHandler(handler)
    else:
        # Standard console handler
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
        # If the filename is not provided during the direct scan -s
        if filename is None:
            filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            print(f"Filename provided automatically, using: {filename}")
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


def display_rich_results(results):
    """Display results OK"""
    if not RICH_AVAILABLE:
        display_results(results)

    malicious_cnt = sum(1 for result in results.values() if result.get('is_malicious', False))
    high_threat_cnt = sum(1 for result in results.values() if result.get('threat_level') == 'high')
    medium_threat_cnt = sum(1 for result in results.values() if result.get('threat_level') == 'medium')

    # Summary Panel
    summary_table = Table(show_header=False, box=box.ROUNDED, style="blue")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Total IPs checks", str(len(results)))
    summary_table.add_row("Malicious IPs Found",
                          f"[red]{malicious_cnt}[/red]" if malicious_cnt > 0 else f"[green]{malicious_cnt}[/green]")
    summary_table.add_row("High Threat IPs",
                          f"[bold red]{high_threat_cnt}[/bold red]" if high_threat_cnt > 0 else f"[green]{high_threat_cnt}[/green]")
    summary_table.add_row("Medium Threat IPs",
                          f"[yellow]{medium_threat_cnt}[/yellow]" if medium_threat_cnt > 0 else f"[green]{medium_threat_cnt}[/green]")

    console.print()
    console.print(Panel(summary_table, title="Scan Summary", title_align="left", style="blue"))

    # Malicious IPs Table
    if malicious_cnt > 0:
        malicious_table = Table(title="Malicious IPs Detected", box=box.ROUNDED, style="red")

        malicious_table.add_column("IP Address", style="bold red")
        malicious_table.add_column("Threat Level", style="white")
        malicious_table.add_column("Abuse Score", style="yellow")
        malicious_table.add_column("Reports", style="cyan")
        malicious_table.add_column("ISP", style="green")
        malicious_table.add_column("Blocklists", style="magenta")

        for ip, result in results.items():
            if result.get('is_malicious', False):
                details = result.get('details', {})
                abuse_data = details.get('abuseipdb', {})
                firehol_data = details.get('firehol', {})

                threat_level = result.get('threat_level', 'unknown')
                threat_style = "bold red" if threat_level == 'high' else "yellow"

                abuse_score = abuse_data.get('abuseConfidenceScore', 0)
                total_reports = abuse_data.get('totalReports', 0)
                isp = abuse_data.get('isp', 'Unknown')[:20] + "..." if abuse_data.get('isp') and len(
                    abuse_data.get('isp', '')) > 20 else abuse_data.get('isp', 'Unknown')

                blocklists = "FireHOL" if firehol_data.get('listed') else "None"

                malicious_table.add_row(
                    ip,
                    f"[{threat_style}]{threat_level.upper()}[/{threat_style}]",
                    f"{abuse_score}%" if abuse_score > 0 else "N/A",
                    str(total_reports) if total_reports > 0 else "0",
                    isp,
                    blocklists
                )

        console.print()
        console.print(malicious_table)

    # Clean Ips table (if any)
    clean_ips = [ip for ip, result in results.items() if not result.get('is_malicious', False)]
    if clean_ips:
        clean_table = Table(title="Clean IPs", box=box.ROUNDED, style="green")
        clean_table.add_column("IP Address", style="green")
        clean_table.add_column("ISP", style="white")
        clean_table.add_column("Country", style="cyan")

        for ip in clean_ips[:10]:  # Show first 10 clean IPs
            result = results[ip]
            details = result.get('details', {})
            abuse_data = details.get('abuseipdb', {})

            isp = abuse_data.get('isp', 'Unknown')[:25] + "..." if abuse_data.get('isp') and len(
                abuse_data.get('isp', '')) > 25 else abuse_data.get('isp', 'Unknown')
            country = abuse_data.get('countryCode', 'Unknown')

            clean_table.add_row(ip, isp, country)

        if len(clean_ips) > 10:
            clean_table.add_row(f"... and {len(clean_ips) - 10} more", "", "")

        console.print()
        console.print(clean_table)

    # Recommendations
    if malicious_cnt > 0:
        console.print()
        if high_threat_cnt > 0:
            console.print(Panel(
                "[bold red]IMMEDIATE ACTION RECOMMENDED[/bold red]\n"
                "• Block high threat IPs in your firewall\n"
                "• Investigate network traffic from these IPs\n"
                "• Check for compromised systems\n"
                "• Review security logs for suspicious activity",
                title="Security Recommendations",
                style="red"
            ))
        else:
            console.print(Panel(
                "[bold yellow]SECURITY REVIEW RECOMMENDED[/bold yellow]\n"
                "• Monitor network traffic from these IPs\n"
                "• Consider adding to watchlist\n"
                "• Review security policies",
                title="Security Recommendations",
                style="yellow"
            ))
    else:
        console.print()
        console.print(Panel(
            "[bold green]No immediate threats detected[/bold green]\n"
            " - Continue regular security monitoring\n"
            " - Keep threat intelligence feeds updated",
            title="Security Status",
            style="green"
        ))


def show_scan_progress():
    if not RICH_AVAILABLE:
        return None
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        transient=True,
    )
    return progress


# Display network info using Rich
def display_rich_network_info(network_data):
    if not RICH_AVAILABLE or not network_data:
        return

    table = Table(title="Network Connections", box=box.ROUNDED)
    table.add_column("Remote IP", style="cyan")
    table.add_column("Protocol", style="green")
    table.add_column("Local Address", style="white")
    table.add_column("State", style="yellow")
    table.add_column("Source", style="magenta")

    for ip, connection in list(network_data.items())[:15]:
        for con in connection[:2]:
            row_data = [
                ip,
                con.get('protocol', 'unknown'),
                con.get('local_address', 'unknown'),
                con.get('state', 'unknown'),
                con.get('source', 'unknown')
            ]
            # Convert every value to string
            row_data = [str(item) if item is not None else 'unknown' for item in row_data]
            table.add_row(*row_data)
    console.print()
    console.print(table)

    if len(network_data) > 15:
        console.print(f"... and {len(network_data) - 15} more connections")


def display_results(results):
    """Display results in a table."""
    print("\n" + "=" * 80)
    print("NETWORK THREAT ANALYSIS RESULTS")
    print("=" * 80)

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
    print("\n" + "=" * 80)
    print("SUMMARY:")
    print(f"Total IPs Checked: {len(results)}")
    print(f"Malicious IPs Found: {malicious_count}")
    print(f"High Threat IPs: {high_threat_count}")
    print(f"Medium Threat IPs: {medium_threat_count}")
    print("=" * 80)

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
